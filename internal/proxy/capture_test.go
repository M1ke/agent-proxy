package proxy

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/m1ke/agent-proxy/internal/record"
	"github.com/m1ke/agent-proxy/internal/redact"
)

func TestKeepHeader(t *testing.T) {
	keep := []string{"Cookie", "Authorization", "Content-Type", "X-Api-Key", "X-Tenant-Id", "X-CSRF-Token"}
	drop := []string{"User-Agent", "Accept-Encoding", "Sec-Fetch-Dest", "Sec-Ch-Ua", "Connection", "X-Powered-By", "X-Cache", "Server", "Date"}
	for _, h := range keep {
		if !keepHeader(h, reqHeaderKeep) {
			t.Errorf("%s should be kept", h)
		}
	}
	for _, h := range drop {
		if keepHeader(h, reqHeaderKeep) {
			t.Errorf("%s should be dropped", h)
		}
	}
}

func TestCaptureHeadersRedacts(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "sid=0123456789abcdef0123; theme=dark")
	h.Set("Authorization", "Bearer abcdefghij")
	h.Set("X-Api-Key", "topsecretvalue")
	h.Set("X-Tenant-Id", "acme")
	h.Set("User-Agent", "Firefox")

	var found []string
	out := captureHeaders(h, reqHeaderKeep, redact.New(nil, nil), "req.header", &found)

	if _, ok := out["user-agent"]; ok {
		t.Error("user-agent should not be recorded per-request")
	}
	if out["x-tenant-id"] != "acme" {
		t.Errorf("non-secret x- header should survive, got %v", out["x-tenant-id"])
	}
	if out["x-api-key"] != "topsecretvalue" {
		t.Errorf("an app-level API key is required to replay the flow and should be kept, got %v", out["x-api-key"])
	}
	if out["authorization"] != "Bearer <REDACTED:10>" {
		t.Errorf("authorization = %v", out["authorization"])
	}
	if !strings.Contains(out["cookie"].(string), "theme=dark") {
		t.Errorf("cookie names and harmless values should survive, got %v", out["cookie"])
	}
}

func TestCaptureHeadersMultipleSetCookie(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "sid=0123456789abcdef; HttpOnly")
	h.Add("Set-Cookie", "csrf=0123456789abcdef; Secure")

	var found []string
	out := captureHeaders(h, respHeaderKeep, redact.New(nil, nil), "resp.header", &found)

	values, ok := out["set-cookie"].([]string)
	if !ok || len(values) != 2 {
		t.Fatalf("multiple Set-Cookie headers should become a list, got %#v", out["set-cookie"])
	}
	if len(found) != 2 {
		t.Errorf("both cookies should be reported as redacted, got %v", found)
	}
}

func TestCaptureBodyJSON(t *testing.T) {
	var found []string
	b := captureBody([]byte(`{"email":"a@b.com","password":"x"}`), "application/json", false, redact.New(nil, nil), "req.body", &found)
	if b.Kind != record.BodyJSON {
		t.Fatalf("kind = %s", b.Kind)
	}
	if b.Data.(map[string]any)["password"] != redact.Marker {
		t.Errorf("password not redacted: %#v", b.Data)
	}
	if b.Bytes != 34 {
		t.Errorf("bytes = %d", b.Bytes)
	}
}

func TestCaptureBodyInvalidJSONFallsBackToText(t *testing.T) {
	var found []string
	b := captureBody([]byte(`not json at all`), "application/json", false, redact.New(nil, nil), "req.body", &found)
	if b.Kind != record.BodyText || b.Text != "not json at all" {
		t.Errorf("got %#v", b)
	}
}

func TestCaptureBodyForm(t *testing.T) {
	var found []string
	b := captureBody([]byte("user=bob&password=hunter2"), "application/x-www-form-urlencoded", false, redact.New(nil, nil), "req.body", &found)
	if b.Kind != record.BodyForm {
		t.Fatalf("kind = %s", b.Kind)
	}
	data := b.Data.(map[string]any)
	if data["user"] != "bob" || data["password"] != redact.Marker {
		t.Errorf("got %#v", data)
	}
}

func TestCaptureBodyMultipartElidesFileContents(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("title", "my doc")
	mw.WriteField("secret_token", "abc123")
	fw, _ := mw.CreateFormFile("upload", "report.pdf")
	fw.Write(bytes.Repeat([]byte("x"), 2048))
	mw.Close()

	var found []string
	b := captureBody(buf.Bytes(), mw.FormDataContentType(), false, redact.New(nil, nil), "req.body", &found)
	if b.Kind != record.BodyMultipart {
		t.Fatalf("kind = %s", b.Kind)
	}
	data := b.Data.(map[string]any)
	if data["title"] != "my doc" {
		t.Errorf("title = %v", data["title"])
	}
	if data["secret_token"] != redact.Marker {
		t.Errorf("secret_token = %v", data["secret_token"])
	}
	file := data["upload"].(map[string]any)
	if file["filename"] != "report.pdf" || file["bytes"] != 2048 {
		t.Errorf("file metadata = %#v", file)
	}
	if strings.Contains(string(mustJSON(t, data)), strings.Repeat("x", 100)) {
		t.Error("file contents should not be recorded")
	}
}

func TestCaptureBodyHTMLKeepsOnlyTitle(t *testing.T) {
	html := []byte("<html><head><title>  Your &amp; My Dashboard </title></head><body>" + strings.Repeat("filler ", 500) + "</body></html>")
	var found []string
	b := captureBody(html, "text/html; charset=utf-8", false, redact.New(nil, nil), "resp.body", &found)
	if b.Kind != record.BodyHTML {
		t.Fatalf("kind = %s", b.Kind)
	}
	if b.Title != "Your & My Dashboard" {
		t.Errorf("title = %q", b.Title)
	}
	if b.Text != "" || b.Data != nil {
		t.Error("HTML body content should not be recorded")
	}
	if b.Bytes != len(html) {
		t.Errorf("bytes = %d, want %d", b.Bytes, len(html))
	}
}

func TestCaptureBodyBinary(t *testing.T) {
	var found []string
	b := captureBody([]byte{0x89, 0x50, 0x4e, 0x47}, "image/png", false, redact.New(nil, nil), "resp.body", &found)
	if b.Kind != record.BodyBinary || b.Bytes != 4 {
		t.Errorf("got %#v", b)
	}
}

func TestCaptureBodyEmpty(t *testing.T) {
	var found []string
	if b := captureBody(nil, "application/json", false, redact.New(nil, nil), "req.body", &found); b != nil {
		t.Errorf("empty body should record nothing, got %#v", b)
	}
}

func TestReadCappedTruncates(t *testing.T) {
	data := bytes.Repeat([]byte("a"), 100)
	captured, truncated, full := readCapped(bytes.NewReader(data), 10)
	if len(captured) != 10 || !truncated {
		t.Fatalf("captured=%d truncated=%v", len(captured), truncated)
	}
	rest, _ := readAll(full)
	if len(rest) != 100 {
		t.Errorf("the client must still receive the whole body, got %d bytes", len(rest))
	}
}

func TestClipMarksTruncation(t *testing.T) {
	var found []string
	long := strings.Repeat("y", maxText+50)
	b := captureBody([]byte(long), "text/plain", false, redact.New(nil, nil), "resp.body", &found)
	if !strings.HasSuffix(b.Text, "...") || len(b.Text) != maxText+3 {
		t.Errorf("text body should be clipped, got %d chars", len(b.Text))
	}
}
