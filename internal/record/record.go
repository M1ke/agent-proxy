// Package record writes the session transcript: one JSON object per line, plus
// a live one-line-per-request summary on the console.
package record

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const FileName = "session.jsonl"

// Entry types.
const (
	TypeSessionStart = "session_start"
	TypeRequest      = "request"
	TypeNote         = "note"
	TypeWebsocket    = "websocket"
	TypeSessionEnd   = "session_end"
)

// Body kinds.
const (
	BodyJSON      = "json"
	BodyForm      = "form"
	BodyMultipart = "multipart"
	BodyText      = "text"
	BodyHTML      = "html"
	BodyBinary    = "binary"
)

type Body struct {
	Kind      string `json:"kind"`
	Data      any    `json:"data,omitempty"`
	Text      string `json:"text,omitempty"`
	Title     string `json:"title,omitempty"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Entry is every record shape in one struct; `type` discriminates and
// omitempty keeps each line to only the fields that apply.
type Entry struct {
	Type     string `json:"type"`
	Seq      int    `json:"seq"`
	T        string `json:"t"`
	OffsetMS int64  `json:"offset_ms"`
	GapMS    int64  `json:"gap_ms,omitempty"`

	// session_start
	Version   string `json:"version,omitempty"`
	Listen    string `json:"listen,omitempty"`
	Filtering string `json:"filtering,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`

	// note
	Text string `json:"text,omitempty"`

	// request / websocket
	DurationMS  int64          `json:"duration_ms,omitempty"`
	Method      string         `json:"method,omitempty"`
	URL         string         `json:"url,omitempty"`
	Host        string         `json:"host,omitempty"`
	Path        string         `json:"path,omitempty"`
	Query       map[string]any `json:"query,omitempty"`
	ReqHeaders  map[string]any `json:"req_headers,omitempty"`
	ReqBody     *Body          `json:"req_body,omitempty"`
	Status      int            `json:"status,omitempty"`
	RespHeaders map[string]any `json:"resp_headers,omitempty"`
	RespBody    *Body          `json:"resp_body,omitempty"`
	Error       string         `json:"error,omitempty"`
	Redacted    []string       `json:"redacted,omitempty"`

	// session_end
	Recorded  int            `json:"recorded,omitempty"`
	Dropped   map[string]int `json:"dropped,omitempty"`
	DurationS float64        `json:"duration_s,omitempty"`
}

type Recorder struct {
	dir   string
	start time.Time
	quiet bool
	out   io.Writer

	mu         sync.Mutex
	f          *os.File
	seq        int
	lastOffset int64
	recorded   int
	dropped    map[string]int
	closed     bool
}

func New(dir string, quiet bool) (*Recorder, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, FileName), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	return &Recorder{
		dir:     dir,
		start:   time.Now(),
		quiet:   quiet,
		out:     os.Stdout,
		f:       f,
		dropped: map[string]int{},
	}, nil
}

func (r *Recorder) Dir() string  { return r.dir }
func (r *Recorder) Path() string { return filepath.Join(r.dir, FileName) }

// Write stamps an entry with sequence and timing, persists it and echoes a
// summary line. Timing is recorded three ways because replay needs all three:
// wall clock, position in the session, and the gap since the last record.
func (r *Recorder) Write(e *Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	now := time.Now()
	offset := now.Sub(r.start).Milliseconds()
	r.seq++
	e.Seq = r.seq
	e.T = now.UTC().Format("2006-01-02T15:04:05.000Z")
	e.OffsetMS = offset
	if r.seq > 1 {
		e.GapMS = offset - r.lastOffset
	}
	r.lastOffset = offset
	if e.Type == TypeRequest {
		r.recorded++
	}
	r.emit(e)
	r.console(e)
}

// Drop counts an exchange the filter discarded, so the session end can report
// what was left out rather than silently losing it.
func (r *Recorder) Drop(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropped[reason]++
}

func (r *Recorder) Note(text string) {
	r.Write(&Entry{Type: TypeNote, Text: text})
}

func (r *Recorder) Counts() (recorded int, dropped map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int, len(r.dropped))
	for k, v := range r.dropped {
		out[k] = v
	}
	return r.recorded, out
}

func (r *Recorder) Close() error {
	recorded, dropped := r.Counts()
	r.Write(&Entry{
		Type:      TypeSessionEnd,
		Recorded:  recorded,
		Dropped:   dropped,
		DurationS: time.Since(r.start).Round(time.Millisecond).Seconds(),
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if !r.quiet {
		fmt.Fprintf(r.out, "\nRecorded %d exchanges in %s\n", recorded, time.Since(r.start).Round(time.Second))
		if len(dropped) > 0 {
			fmt.Fprintf(r.out, "Filtered out: %s\n", formatCounts(dropped))
		}
		fmt.Fprintf(r.out, "Transcript: %s\n", filepath.Join(r.dir, FileName))
	}
	return r.f.Close()
}

func (r *Recorder) emit(e *Entry) {
	line, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent-proxy: encoding entry: %v\n", err)
		return
	}
	// Written and synced per line so the file is readable while recording.
	if _, err := r.f.Write(append(line, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "agent-proxy: writing entry: %v\n", err)
	}
}

func (r *Recorder) console(e *Entry) {
	if r.quiet {
		return
	}
	stamp := fmt.Sprintf("[+%6.1fs]", float64(e.OffsetMS)/1000)
	switch e.Type {
	case TypeRequest:
		status := fmt.Sprintf("%d", e.Status)
		if e.Error != "" {
			status = "ERR"
		}
		marks := ""
		if len(e.Redacted) > 0 {
			marks = fmt.Sprintf(" [%d redacted]", len(e.Redacted))
		}
		fmt.Fprintf(r.out, "%s %-6s %s%s -> %s (%dms)%s\n",
			stamp, e.Method, e.Host, e.Path, status, e.DurationMS, marks)
	case TypeNote:
		fmt.Fprintf(r.out, "%s NOTE   %s\n", stamp, e.Text)
	case TypeWebsocket:
		fmt.Fprintf(r.out, "%s WS     %s%s (not recorded)\n", stamp, e.Host, e.Path)
	}
}

func formatCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}
