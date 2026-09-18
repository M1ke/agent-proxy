package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/m1ke/agent-proxy/internal/record"
	"github.com/m1ke/agent-proxy/internal/redact"
)

// maxBody is how much of a body is captured for the transcript. Anything
// beyond it is streamed to the client but recorded only as a size.
const maxBody = 64 << 10

// maxText is the cap on free-text bodies, which are rarely worth more.
const maxText = 8 << 10

// Headers worth keeping because they affect auth, routing or content
// negotiation. Everything else is browser bookkeeping.
var reqHeaderKeep = map[string]bool{
	"cookie": true, "authorization": true, "proxy-authorization": true,
	"content-type": true, "accept": true, "referer": true, "origin": true,
	// Auth headers that are neither Authorization nor x-prefixed. Their
	// values get redacted, but an automation still has to know they exist.
	"apikey": true, "api-key": true, "auth-token": true, "token": true,
}

var respHeaderKeep = map[string]bool{
	"set-cookie": true, "location": true, "content-type": true,
	"www-authenticate": true, "retry-after": true,
}

// x-* headers are kept by default since they carry API keys, tenant ids and
// CSRF tokens -- except these, which are boilerplate.
var xHeaderNoise = map[string]bool{
	"x-powered-by": true, "x-frame-options": true, "x-content-type-options": true,
	"x-xss-protection": true, "x-cache": true, "x-cache-hits": true,
	"x-served-by": true, "x-timer": true, "x-runtime": true,
	"x-download-options": true, "x-permitted-cross-domain-policies": true,
	"x-ua-compatible": true, "x-dns-prefetch-control": true,
	"x-amz-cf-id": true, "x-amz-cf-pop": true, "x-amz-request-id": true,
	"x-envoy-upstream-service-time": true, "x-fb-debug": true,
}

func keepHeader(name string, allow map[string]bool) bool {
	n := strings.ToLower(name)
	if allow[n] {
		return true
	}
	return strings.HasPrefix(n, "x-") && !xHeaderNoise[n]
}

// captureHeaders filters and redacts one direction's headers. prefix is the
// path stem used when noting redactions, e.g. "req.header".
func captureHeaders(h http.Header, allow map[string]bool, r *redact.Redactor, prefix string, found *[]string) map[string]any {
	out := map[string]any{}
	for name, values := range h {
		if !keepHeader(name, allow) {
			continue
		}
		key := strings.ToLower(name)
		path := prefix + "." + key
		switch key {
		case "cookie":
			out[key] = r.Cookie(strings.Join(values, "; "), path, found)
		case "set-cookie":
			redacted := make([]string, len(values))
			for i, v := range values {
				redacted[i] = r.SetCookie(v, path, found)
			}
			out[key] = collapse(redacted)
		case "authorization", "proxy-authorization":
			out[key] = r.Authorization(strings.Join(values, " "), path, found)
		default:
			if r.IsSecretName(key) {
				out[key] = r.Header(strings.Join(values, ", "), path, found)
				continue
			}
			// Referer and Location routinely carry tokens in their query.
			scrubbed := make([]string, len(values))
			for i, v := range values {
				scrubbed[i] = r.Text(v, path, found)
			}
			out[key] = collapse(scrubbed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func collapse(values []string) any {
	if len(values) == 1 {
		return values[0]
	}
	return values
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// captureBody turns raw bytes into a recordable body, parsing structured
// formats so redaction can walk them. HTML is deliberately not captured --
// it is large and low-value -- but its <title> is kept as a page landmark.
func captureBody(data []byte, contentType string, truncated bool, r *redact.Redactor, prefix string, found *[]string) *record.Body {
	if len(data) == 0 {
		return nil
	}
	body := &record.Body{Bytes: len(data), Truncated: truncated}
	base, params := parseMediaType(contentType)

	switch {
	case base == "application/json" || strings.HasSuffix(base, "+json"):
		var v any
		if err := json.Unmarshal(data, &v); err == nil {
			body.Kind = record.BodyJSON
			body.Data = r.JSON(v, prefix, found)
			return body
		}
		body.Kind = record.BodyText
		body.Text = clip(string(data), maxText)
		return body

	case base == "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(data))
		if err == nil {
			body.Kind = record.BodyForm
			body.Data = r.Values(values, prefix, found)
			return body
		}
		body.Kind = record.BodyText
		body.Text = clip(string(data), maxText)
		return body

	case base == "multipart/form-data":
		if fields, err := captureMultipart(data, params["boundary"], r, prefix, found); err == nil {
			body.Kind = record.BodyMultipart
			body.Data = fields
			return body
		}
		body.Kind = record.BodyBinary
		return body

	case base == "text/html" || base == "application/xhtml+xml":
		body.Kind = record.BodyHTML
		if m := titleRe.FindSubmatch(data); m != nil {
			body.Title = strings.TrimSpace(html(string(m[1])))
		}
		return body

	case strings.HasPrefix(base, "text/") || base == "application/xml" || base == "application/graphql":
		body.Kind = record.BodyText
		body.Text = clip(string(data), maxText)
		return body

	default:
		body.Kind = record.BodyBinary
		return body
	}
}

// captureMultipart records field names and values, but for file parts only the
// metadata -- uploaded file contents are never useful to an agent reading a flow.
func captureMultipart(data []byte, boundary string, r *redact.Redactor, prefix string, found *[]string) (map[string]any, error) {
	if boundary == "" {
		return nil, errNoBoundary
	}
	mr := multipart.NewReader(bytes.NewReader(data), boundary)
	out := map[string]any{}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		name := part.FormName()
		path := prefix + "." + name
		if fn := part.FileName(); fn != "" {
			content, _ := io.ReadAll(io.LimitReader(part, maxBody))
			out[name] = map[string]any{
				"filename":     fn,
				"content_type": part.Header.Get("Content-Type"),
				"bytes":        len(content),
			}
			part.Close()
			continue
		}
		value, _ := io.ReadAll(io.LimitReader(part, maxText))
		if r.IsSecretName(name) {
			*found = append(*found, path)
			out[name] = redact.Marker
		} else {
			out[name] = string(value)
		}
		part.Close()
	}
}

var errNoBoundary = errorString("multipart body without boundary")

type errorString string

func (e errorString) Error() string { return string(e) }

func parseMediaType(ct string) (string, map[string]string) {
	base, params, err := mime.ParseMediaType(ct)
	if err != nil {
		base, _, _ = strings.Cut(ct, ";")
		return strings.ToLower(strings.TrimSpace(base)), map[string]string{}
	}
	return strings.ToLower(base), params
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// html unescapes the handful of entities that show up in <title>.
func html(s string) string {
	return strings.NewReplacer(
		"&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'", "&nbsp;", " ",
	).Replace(s)
}
