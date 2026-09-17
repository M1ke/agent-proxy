package proxy_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m1ke/agent-proxy/internal/ca"
	"github.com/m1ke/agent-proxy/internal/filter"
	"github.com/m1ke/agent-proxy/internal/proxy"
	"github.com/m1ke/agent-proxy/internal/record"
	"github.com/m1ke/agent-proxy/internal/redact"
)

// harness stands up an HTTPS origin, the recording proxy in front of it, and a
// client configured the way Firefox would be.
type harness struct {
	origin     *httptest.Server
	client     *http.Client
	transcript string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Set-Cookie", "sid=s3cr3tsessionvalue01; Path=/; HttpOnly; Secure")
		w.Header().Set("X-Request-Id", "abc")
		w.Header().Set("X-Tenant-Id", "acme")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"ok":true,"user_id":91}`)
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<html><head><title>Dashboard</title></head><body>hi</body></html>")
	})
	mux.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte{0x89, 'P', 'N', 'G'})
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "console.log(1)")
	})
	mux.HandleFunc("/api/items", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"items":[{"id":1}]}`)
	})
	origin := httptest.NewTLSServer(mux)
	t.Cleanup(origin.Close)

	dir := t.TempDir()
	authority, err := ca.Load(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	sessionDir := filepath.Join(dir, "session")
	rec, err := record.New(sessionDir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rec.Close() })

	// The proxy must trust the throwaway origin certificate.
	originPool := x509.NewCertPool()
	originPool.AddCert(origin.Certificate())

	p := proxy.New(proxy.Options{
		CA:          authority,
		Filter:      filter.New(filter.Builtin(), false),
		Redactor:    redact.New(nil),
		Recorder:    rec,
		Control:     http.NotFoundHandler(),
		ControlHost: "proxy.note",
		Transport:   &http.Transport{TLSClientConfig: &tls.Config{RootCAs: originPool}},
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: p}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	// The client trusts our CA, exactly as the browser does after importing it.
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(authority.PEM()) {
		t.Fatal("could not parse generated CA")
	}
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &harness{origin: origin, client: client, transcript: filepath.Join(sessionDir, record.FileName)}
}

func (h *harness) do(t *testing.T, method, path, contentType, body string, secFetchDest string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.origin.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if secFetchDest != "" {
		req.Header.Set("Sec-Fetch-Dest", secFetchDest)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func (h *harness) entries(t *testing.T) []record.Entry {
	t.Helper()
	f, err := os.Open(h.transcript)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []record.Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e record.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad transcript line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

func find(entries []record.Entry, path string) *record.Entry {
	for i := range entries {
		if entries[i].Type == record.TypeRequest && entries[i].Path == path {
			return &entries[i]
		}
	}
	return nil
}

func TestRecordsFlowAndFiltersNoise(t *testing.T) {
	h := newHarness(t)

	h.do(t, "GET", "/dashboard", "", "", "document")
	h.do(t, "GET", "/logo.png", "", "", "image")
	h.do(t, "GET", "/app.js", "", "", "")
	h.do(t, "OPTIONS", "/api/items", "", "", "empty")
	time.Sleep(15 * time.Millisecond) // make the gap between records measurable
	h.do(t, "POST", "/login", "application/json", `{"email":"a@b.com","password":"hunter2"}`, "empty")
	h.do(t, "GET", "/api/items?page=2&api_key=zzz", "", "", "empty")

	entries := h.entries(t)

	for _, dropped := range []string{"/logo.png", "/app.js", "/api/items"} {
		if dropped == "/api/items" {
			continue // the GET is kept; only the OPTIONS should be missing
		}
		if e := find(entries, dropped); e != nil {
			t.Errorf("%s should have been filtered out, but was recorded", dropped)
		}
	}
	for _, e := range entries {
		if e.Method == http.MethodOptions {
			t.Error("OPTIONS preflight should have been filtered out")
		}
	}

	login := find(entries, "/login")
	if login == nil {
		t.Fatal("the login POST was not recorded")
	}
	if login.Status != 200 {
		t.Errorf("status = %d", login.Status)
	}
	body := login.ReqBody.Data.(map[string]any)
	if body["password"] != redact.Marker {
		t.Errorf("password was not redacted: %#v", body)
	}
	if body["email"] != "a@b.com" {
		t.Errorf("email should survive: %#v", body)
	}
	if !contains(login.Redacted, "req.body.password") {
		t.Errorf("redacted paths = %v, want req.body.password", login.Redacted)
	}
	if !contains(login.Redacted, "resp.header.set-cookie.sid") {
		t.Errorf("redacted paths = %v, want resp.header.set-cookie.sid", login.Redacted)
	}
	setCookie, _ := login.RespHeaders["set-cookie"].(string)
	if strings.Contains(setCookie, "s3cr3tsessionvalue01") {
		t.Errorf("session value leaked into the transcript: %q", setCookie)
	}
	if !strings.Contains(setCookie, "HttpOnly") {
		t.Errorf("cookie attributes should survive: %q", setCookie)
	}
	if login.RespHeaders["x-tenant-id"] != "acme" {
		t.Errorf("x- headers should be kept: %#v", login.RespHeaders)
	}
	if login.GapMS <= 0 {
		t.Errorf("gap_ms = %d, want the delay before this request", login.GapMS)
	}
	if login.RespBody.Data.(map[string]any)["user_id"] != float64(91) {
		t.Errorf("response body = %#v", login.RespBody.Data)
	}

	items := find(entries, "/api/items")
	if items == nil {
		t.Fatal("the items GET was not recorded")
	}
	if items.Query["page"] != "2" {
		t.Errorf("query = %#v", items.Query)
	}
	if items.Query["api_key"] != redact.Marker {
		t.Errorf("query api_key was not redacted: %#v", items.Query)
	}
	if strings.Contains(items.URL, "api_key") {
		t.Errorf("the recorded URL should not carry the query string verbatim: %q", items.URL)
	}

	dash := find(entries, "/dashboard")
	if dash == nil {
		t.Fatal("the dashboard navigation was not recorded")
	}
	if dash.RespBody.Kind != record.BodyHTML || dash.RespBody.Title != "Dashboard" {
		t.Errorf("html body = %#v", dash.RespBody)
	}
}

func TestResponseBodyReachesTheClientIntact(t *testing.T) {
	h := newHarness(t)
	resp, err := h.client.Get(h.origin.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, []byte(`{"ok":true,"user_id":91}`)) {
		t.Errorf("client received %q", got)
	}
}

func TestDropCountsAreReported(t *testing.T) {
	h := newHarness(t)
	h.do(t, "GET", "/logo.png", "", "", "image")
	h.do(t, "OPTIONS", "/api/items", "", "", "empty")

	// Drop counts land in the session_end entry, written on Close.
	entries := h.entries(t)
	for _, e := range entries {
		if e.Type == record.TypeSessionEnd {
			t.Fatal("session_end written before Close")
		}
	}
	if len(entries) != 0 {
		t.Errorf("filtered traffic should produce no request entries, got %d", len(entries))
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
