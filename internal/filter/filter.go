package filter

import (
	"net/http"
	"path"
	"strings"
)

// Drop reasons, used both to short-circuit recording and to report at the end
// of a session what was discarded.
const (
	ReasonOptions     = "options-preflight"
	ReasonSubresource = "subresource"
	ReasonExtension   = "static-extension"
	ReasonContentType = "static-content-type"
	ReasonHost        = "noise-host"
	ReasonPath        = "noise-path"
)

type Filter struct {
	dropHosts []string
	keepHosts []string
	dropPaths []string
	dropExts  map[string]bool
	disabled  bool
}

func New(r Rules, disabled bool) *Filter {
	f := &Filter{disabled: disabled, dropExts: map[string]bool{}}
	for _, h := range r.DropHosts {
		f.dropHosts = append(f.dropHosts, strings.ToLower(h))
	}
	for _, h := range r.KeepHosts {
		f.keepHosts = append(f.keepHosts, strings.ToLower(h))
	}
	for _, p := range r.DropPaths {
		p = strings.ToLower(strings.TrimRight(p, "/"))
		if p != "" {
			f.dropPaths = append(f.dropPaths, p)
		}
	}
	for _, e := range r.DropExtensions {
		e = strings.ToLower(e)
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		f.dropExts[e] = true
	}
	return f
}

// Sec-Fetch-Dest values that mean "the browser fetched this to render a page",
// not "the user did something". Firefox sets this on every request.
var subresourceDests = map[string]bool{
	"image": true, "font": true, "style": true, "script": true,
	"audio": true, "video": true, "track": true, "manifest": true,
	"worker": true, "sharedworker": true, "serviceworker": true,
	"paintworklet": true, "audioworklet": true,
}

// CheckRequest decides from the request alone. An empty reason means keep.
func (f *Filter) CheckRequest(r *http.Request, host string) string {
	if f.disabled {
		return ""
	}
	host = strings.ToLower(stripPort(host))
	if matchHost(host, f.keepHosts) {
		return ""
	}
	if r.Method == http.MethodOptions {
		return ReasonOptions
	}
	if matchHost(host, f.dropHosts) {
		return ReasonHost
	}
	if matchPath(r.URL.Path, f.dropPaths) {
		return ReasonPath
	}
	if subresourceDests[strings.ToLower(r.Header.Get("Sec-Fetch-Dest"))] {
		return ReasonSubresource
	}
	if ext := strings.ToLower(path.Ext(r.URL.Path)); ext != "" && f.dropExts[ext] {
		return ReasonExtension
	}
	return ""
}

var staticTypePrefixes = []string{"image/", "font/", "video/", "audio/"}

var staticTypes = map[string]bool{
	"text/css":                 true,
	"application/javascript":   true,
	"text/javascript":          true,
	"application/x-javascript": true,
	"application/wasm":         true,
	"application/font-woff":    true,
	"application/octet-stream": true,
}

// CheckResponse applies the rules that need the response's content type.
func (f *Filter) CheckResponse(contentType string) string {
	if f.disabled {
		return ""
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		return ""
	}
	for _, p := range staticTypePrefixes {
		if strings.HasPrefix(ct, p) {
			return ReasonContentType
		}
	}
	if staticTypes[ct] {
		return ReasonContentType
	}
	return ""
}

// matchHost matches a host exactly or as a subdomain. Patterns containing a
// slash are treated as host+path prefixes (e.g. "facebook.com/tr").
func matchHost(host string, patterns []string) bool {
	for _, p := range patterns {
		if i := strings.IndexByte(p, '/'); i >= 0 {
			p = p[:i]
		}
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

// matchPath matches a path exactly or as a parent segment, so
// "/cdn-cgi/rum" covers "/cdn-cgi/rum/v1" but not "/cdn-cgi/rumour". A
// trailing "*" opts into raw prefix matching instead.
func matchPath(path string, patterns []string) bool {
	path = strings.ToLower(strings.TrimRight(path, "/"))
	if path == "" {
		return false
	}
	for _, p := range patterns {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(path, strings.TrimSuffix(p, "*")) {
				return true
			}
			continue
		}
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func stripPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {
		return host[:i]
	}
	return host
}
