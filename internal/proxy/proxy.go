// Package proxy is the recording HTTP/HTTPS proxy itself.
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/m1ke/agent-proxy/internal/ca"
	"github.com/m1ke/agent-proxy/internal/filter"
	"github.com/m1ke/agent-proxy/internal/record"
	"github.com/m1ke/agent-proxy/internal/redact"
)

type Options struct {
	CA       *ca.CA
	Filter   *filter.Filter
	Redactor *redact.Redactor
	Recorder *record.Recorder
	// Control handles the in-browser annotation UI; requests to ControlHost
	// and direct (non-proxied) requests to the listener are routed to it.
	Control     http.Handler
	ControlHost string
	// Transport overrides the outbound transport; tests use it to trust a
	// throwaway origin certificate.
	Transport *http.Transport
}

type Proxy struct {
	Options
	transport *http.Transport
}

func New(o Options) *Proxy {
	if o.Transport != nil {
		return &Proxy{Options: o, transport: o.Transport}
	}
	return &Proxy{
		Options: o,
		transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// A proxied request carries an absolute URI; anything else is the browser
	// talking to the listener directly, which means the control UI.
	if r.URL.Scheme == "" || p.isControlHost(r.Host) {
		p.Control.ServeHTTP(w, r)
		return
	}
	p.forward(w, r, "http", r.Host)
}

func (p *Proxy) isControlHost(host string) bool {
	h := host
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.EqualFold(h, p.ControlHost)
}

// hop-by-hop headers must not be forwarded (RFC 7230 6.1).
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, name := range h.Values("Connection") {
		for _, token := range strings.Split(name, ",") {
			if t := strings.TrimSpace(token); t != "" {
				h.Del(t)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, scheme, host string) {
	if isUpgrade(r) {
		p.tunnelUpgrade(w, r, scheme, host)
		return
	}

	start := time.Now()
	hostname := stripPort(host)
	reqReason := p.Filter.CheckRequest(r, hostname)
	capture := reqReason == ""

	var reqBody []byte
	var reqTruncated bool
	bodyReader := io.Reader(r.Body)
	if capture && r.Body != nil {
		reqBody, reqTruncated, bodyReader = readCapped(r.Body, maxBody)
	}

	target := *r.URL
	target.Scheme = scheme
	if target.Host == "" {
		target.Host = host
	}

	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bodyReader)
	if err != nil {
		p.fail(w, r, scheme, host, start, err)
		return
	}
	out.Header = r.Header.Clone()
	stripHopByHop(out.Header)
	// Let the transport negotiate compression so it transparently gunzips for
	// us; forwarding the browser's brotli offer would leave us holding bytes
	// we cannot read.
	out.Header.Del("Accept-Encoding")
	out.Host = r.Host
	if !reqTruncated && reqBody != nil {
		out.ContentLength = int64(len(reqBody))
	} else if r.ContentLength > 0 {
		out.ContentLength = r.ContentLength
	}

	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		p.fail(w, r, scheme, host, start, err)
		return
	}
	defer resp.Body.Close()

	dropReason := reqReason
	if capture {
		if reason := p.Filter.CheckResponse(resp.Header.Get("Content-Type")); reason != "" {
			capture = false
			dropReason = reason
		}
	}
	if dropReason != "" {
		p.Recorder.Drop(dropReason)
	}

	if !capture {
		streamResponse(w, resp)
		return
	}

	respBody, respTruncated, _ := readCapped(resp.Body, maxBody)
	duration := time.Since(start)

	writeBuffered(w, resp, respBody, respTruncated)
	p.record(r, resp, host, scheme, reqBody, reqTruncated, respBody, respTruncated, duration)
}

func (p *Proxy) record(r *http.Request, resp *http.Response, host, scheme string,
	reqBody []byte, reqTruncated bool, respBody []byte, respTruncated bool, duration time.Duration) {

	var found []string
	red := p.Redactor

	displayed := displayHost(scheme, host)
	full := *r.URL
	full.Scheme = scheme
	full.Host = displayed
	query := full.Query()
	full.RawQuery = ""

	e := &record.Entry{
		Type:        record.TypeRequest,
		DurationMS:  duration.Milliseconds(),
		Method:      r.Method,
		URL:         full.String(),
		Host:        displayed,
		Path:        r.URL.Path,
		ReqHeaders:  captureHeaders(r.Header, reqHeaderKeep, red, "req.header", &found),
		ReqBody:     captureBody(reqBody, r.Header.Get("Content-Type"), reqTruncated, red, "req.body", &found),
		Status:      resp.StatusCode,
		RespHeaders: captureHeaders(resp.Header, respHeaderKeep, red, "resp.header", &found),
		RespBody:    captureBody(respBody, resp.Header.Get("Content-Type"), respTruncated, red, "resp.body", &found),
	}
	if len(query) > 0 {
		e.Query = red.Values(query, "req.query", &found)
	}
	e.Redacted = redact.Dedupe(found)
	p.Recorder.Write(e)
}

func (p *Proxy) fail(w http.ResponseWriter, r *http.Request, scheme, host string, start time.Time, err error) {
	p.Recorder.Write(&record.Entry{
		Type:       record.TypeRequest,
		Method:     r.Method,
		URL:        r.URL.String(),
		Host:       displayHost(scheme, host),
		Path:       r.URL.Path,
		DurationMS: time.Since(start).Milliseconds(),
		Error:      err.Error(),
	})
	http.Error(w, "agent-proxy: "+err.Error(), http.StatusBadGateway)
}

func streamResponse(w http.ResponseWriter, resp *http.Response) {
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func writeBuffered(w http.ResponseWriter, resp *http.Response, body []byte, truncated bool) {
	copyHeaders(w.Header(), resp.Header)
	if truncated {
		// The capture stopped short but the client still needs everything.
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		io.Copy(w, resp.Body)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func copyHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, v := range values {
			dst.Add(name, v)
		}
	}
	stripHopByHop(dst)
	dst.Del("Content-Length")
}

// readCapped buffers up to limit bytes for the transcript while returning a
// reader that still yields the complete stream.
func readCapped(rc io.Reader, limit int) (captured []byte, truncated bool, full io.Reader) {
	if rc == nil {
		return nil, false, bytes.NewReader(nil)
	}
	buf, err := io.ReadAll(io.LimitReader(rc, int64(limit)+1))
	if err != nil {
		return buf, false, bytes.NewReader(buf)
	}
	if len(buf) > limit {
		return buf[:limit], true, io.MultiReader(bytes.NewReader(buf), rc)
	}
	return buf, false, bytes.NewReader(buf)
}

func isUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != ""
}

// tunnelUpgrade hands WebSocket (and other upgrades) straight through. The
// framed protocol that follows is out of scope for v1, so the session only
// notes that a socket was opened.
func (p *Proxy) tunnelUpgrade(w http.ResponseWriter, r *http.Request, scheme, host string) {
	p.Recorder.Write(&record.Entry{
		Type:   record.TypeWebsocket,
		Method: r.Method,
		Host:   host,
		Path:   r.URL.Path,
		URL:    (&url.URL{Scheme: scheme, Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}).String(),
	})

	client, _, err := hijack(w)
	if err != nil {
		http.Error(w, "agent-proxy: cannot hijack for upgrade", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	upstream, err := dial(scheme, host)
	if err != nil {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	if err := r.Write(upstream); err != nil {
		return
	}
	pipe(client, upstream)
}

// displayHost drops the implicit port so recorded URLs read the way a user
// would type them.
func displayHost(scheme, host string) string {
	if scheme == "https" && strings.HasSuffix(host, ":443") {
		return strings.TrimSuffix(host, ":443")
	}
	if scheme == "http" && strings.HasSuffix(host, ":80") {
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
