// Package control serves the in-browser annotation UI. Keeping notes in the
// browser means the user can mark up the flow without leaving the window they
// are working in.
package control

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/m1ke/agent-proxy/internal/record"
)

type Handler struct {
	rec    *record.Recorder
	host   string
	caPath string
	stop   func()
}

func New(rec *record.Recorder, host, caPath string, stop func()) *Handler {
	return &Handler{rec: rec, host: host, caPath: caPath, stop: stop}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		h.page(w, "")
	case r.URL.Path == "/note" && r.Method == http.MethodPost:
		r.ParseForm()
		h.note(w, r.FormValue("text"))
	case r.URL.Path == "/ca.crt":
		h.serveCA(w)
	case r.URL.Path == "/status":
		h.status(w)
	case r.URL.Path == "/stop":
		h.shutdown(w)
	case r.Method == http.MethodGet && len(r.URL.Path) > 1:
		// Anything else is shorthand: http://proxy.note/clicked%20submit
		text, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			text = strings.TrimPrefix(r.URL.Path, "/")
		}
		h.note(w, strings.ReplaceAll(text, "+", " "))
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) note(w http.ResponseWriter, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		h.page(w, "")
		return
	}
	h.rec.Note(text)
	h.page(w, text)
}

func (h *Handler) status(w http.ResponseWriter) {
	recorded, dropped := h.rec.Counts()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"recorded":   recorded,
		"dropped":    dropped,
		"transcript": h.rec.Path(),
	})
}

func (h *Handler) serveCA(w http.ResponseWriter) {
	data, err := os.ReadFile(h.caPath)
	if err != nil {
		http.Error(w, "cannot read CA: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="agent-proxy-ca.crt"`)
	w.Write(data)
}

func (h *Handler) shutdown(w http.ResponseWriter) {
	recorded, _ := h.rec.Counts()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, shell, "Recording stopped", fmt.Sprintf(
		`<p class="ok">Recording stopped after %d exchanges.</p><p class="path">%s</p>`,
		recorded, html.EscapeString(h.rec.Path())))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go h.stop()
}

func (h *Handler) page(w http.ResponseWriter, saved string) {
	recorded, _ := h.rec.Counts()
	var body strings.Builder
	if saved != "" {
		fmt.Fprintf(&body, `<p class="ok">Noted: %s</p>`, html.EscapeString(saved))
	}
	fmt.Fprintf(&body, `
<form method="post" action="http://%s/note">
  <input name="text" placeholder="what did you just do?" autofocus autocomplete="off">
  <button type="submit">Add note</button>
</form>
<p class="meta">%d exchanges recorded &middot; <a href="http://%s/stop">stop recording</a> &middot; <a href="http://%s/ca.crt">CA certificate</a></p>
<p class="meta">Shorthand: visit <code>http://%s/signed%%20in</code> to drop a note without this page.</p>`,
		h.host, recorded, h.host, h.host, h.host)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, shell, "agent-proxy", body.String())
}

const shell = `<!doctype html><meta charset="utf-8"><title>%s</title>
<style>
 :root { color-scheme: light dark; }
 body { font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; max-width: 34rem; margin: 4rem auto; padding: 0 1.5rem; }
 h1 { font-size: 1.1rem; letter-spacing: .02em; text-transform: uppercase; opacity: .6; margin: 0 0 1.5rem; }
 input { width: 100%%; padding: .6rem .7rem; font: inherit; border: 1px solid; border-radius: 6px; background: transparent; color: inherit; }
 button { margin-top: .6rem; padding: .5rem 1rem; font: inherit; border-radius: 6px; cursor: pointer; }
 .ok { padding: .6rem .8rem; border-left: 3px solid currentColor; opacity: .85; }
 .meta { font-size: .85rem; opacity: .6; }
 .path { font-family: ui-monospace, monospace; font-size: .85rem; opacity: .6; word-break: break-all; }
 code { font-family: ui-monospace, monospace; }
</style>
<h1>agent-proxy</h1>
%s
`
