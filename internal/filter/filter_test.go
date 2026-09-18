package filter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func req(t *testing.T, method, url, secFetchDest string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, url, nil)
	if secFetchDest != "" {
		r.Header.Set("Sec-Fetch-Dest", secFetchDest)
	}
	return r
}

func TestCheckRequest(t *testing.T) {
	f := New(Builtin(), false)
	cases := []struct {
		name, method, url, dest, host, want string
	}{
		{"api post kept", "POST", "https://app.example.com/api/login", "empty", "app.example.com", ""},
		{"document kept", "GET", "https://app.example.com/dashboard", "document", "app.example.com", ""},
		{"preflight dropped", "OPTIONS", "https://app.example.com/api/items", "empty", "app.example.com", ReasonOptions},
		{"image dest dropped", "GET", "https://app.example.com/avatar", "image", "app.example.com", ReasonSubresource},
		{"script ext dropped", "GET", "https://app.example.com/bundle.js", "", "app.example.com", ReasonExtension},
		{"analytics dropped", "POST", "https://www.google-analytics.com/collect", "empty", "www.google-analytics.com", ReasonHost},
		{"subdomain of noise dropped", "GET", "https://o123.ingest.sentry.io/api/1/store", "empty", "o123.ingest.sentry.io", ReasonHost},
		{"port ignored", "GET", "http://localhost:3000/api/me", "empty", "localhost:3000", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := f.CheckRequest(req(t, c.method, c.url, c.dest), c.host); got != c.want {
				t.Errorf("CheckRequest = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCheckRequestKeepHostWins(t *testing.T) {
	rules := Builtin()
	rules.KeepHosts = []string{"google-analytics.com"}
	f := New(rules, false)
	if got := f.CheckRequest(req(t, "OPTIONS", "https://www.google-analytics.com/collect", "image"), "www.google-analytics.com"); got != "" {
		t.Errorf("keep_hosts should override every drop rule, got %q", got)
	}
}

func TestDisabledKeepsEverything(t *testing.T) {
	f := New(Builtin(), true)
	if got := f.CheckRequest(req(t, "OPTIONS", "https://doubleclick.net/x.png", "image"), "doubleclick.net"); got != "" {
		t.Errorf("--no-filter should keep everything, got %q", got)
	}
	if got := f.CheckResponse("image/png"); got != "" {
		t.Errorf("--no-filter should keep every content type, got %q", got)
	}
}

func TestCheckResponse(t *testing.T) {
	f := New(Builtin(), false)
	cases := map[string]string{
		"application/json":                    "",
		"application/json; charset=utf-8":     "",
		"text/html; charset=utf-8":            "",
		"":                                    "",
		"image/png":                           ReasonContentType,
		"text/css":                            ReasonContentType,
		"Application/JavaScript; charset=u-8": ReasonContentType,
		"font/woff2":                          ReasonContentType,
	}
	for ct, want := range cases {
		if got := f.CheckResponse(ct); got != want {
			t.Errorf("CheckResponse(%q) = %q, want %q", ct, got, want)
		}
	}
}

func TestExtensionOverrideNormalisesDot(t *testing.T) {
	rules := Builtin()
	rules.DropExtensions = []string{"xyz"}
	f := New(rules, false)
	if got := f.CheckRequest(req(t, "GET", "https://example.com/a.xyz", ""), "example.com"); got != ReasonExtension {
		t.Errorf("override extension without a dot should still match, got %q", got)
	}
}

func TestCheckRequestDropPaths(t *testing.T) {
	f := New(Builtin(), false)
	cases := []struct{ url, want string }{
		// First-party telemetry, indistinguishable from a real API call by host.
		{"https://app.example.com/_vercel/insights/event", ReasonPath},
		{"https://app.example.com/cdn-cgi/rum", ReasonPath},
		{"https://app.example.com/cdn-cgi/challenge-platform/h/b/scripts/x", ReasonPath},
		{"https://app.example.com/matomo.php", ReasonPath},
		{"http://localhost:3000/_next/webpack-hmr", ReasonPath},
		// Must not eat real endpoints that merely share a stem.
		{"https://app.example.com/ingest/events-page", ""},
		{"https://app.example.com/api/insights", ""},
		{"https://app.example.com/", ""},
	}
	for _, c := range cases {
		if got := f.CheckRequest(req(t, "POST", c.url, "empty"), "app.example.com"); got != c.want {
			t.Errorf("CheckRequest(%s) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestDropPathsOverrideAndWildcard(t *testing.T) {
	rules := Builtin()
	rules.DropPaths = []string{"/api/metrics", "/internal/telemetry*"}
	f := New(rules, false)
	for _, path := range []string{"/api/metrics", "/api/metrics/batch", "/internal/telemetry-v2"} {
		if got := f.CheckRequest(req(t, "POST", "https://app.example.com"+path, "empty"), "app.example.com"); got != ReasonPath {
			t.Errorf("%s should be dropped, got %q", path, got)
		}
	}
	if got := f.CheckRequest(req(t, "POST", "https://app.example.com/api/metrics-report", "empty"), "app.example.com"); got != "" {
		t.Errorf("a non-wildcard rule should not match a sibling path, got %q", got)
	}
}

func TestKeepHostBeatsDropPath(t *testing.T) {
	rules := Builtin()
	rules.KeepHosts = []string{"app.example.com"}
	f := New(rules, false)
	if got := f.CheckRequest(req(t, "POST", "https://app.example.com/cdn-cgi/rum", "empty"), "app.example.com"); got != "" {
		t.Errorf("keep_hosts should override drop_paths, got %q", got)
	}
}

// Regression: a real Firefox session put ~13% junk in a transcript because the
// blocklist had mozilla.com and mozilla.net but not mozilla.org.
func TestBrowserServiceNoiseFromRealSession(t *testing.T) {
	f := New(Builtin(), false)
	noise := []struct{ host, path string }{
		{"incoming.telemetry.mozilla.org", "/submit/firefox-desktop/messaging-system/1/abc"},
		{"ads.mozilla.org", "/"},
		{"archive.mozilla.org", "/"},
		{"mozilla-ohttp.fastly-edge.com", "/"},
		{"prod-games-particle.merino.prod.webservices.mozgcp.net", "/generated/daily-puzzle.v1.json"},
		{"www.google.com", "/complete/search"},
	}
	for _, c := range noise {
		got := f.CheckRequest(req(t, "POST", "https://"+c.host+c.path, "empty"), c.host)
		if got == "" {
			t.Errorf("%s%s should be filtered out", c.host, c.path)
		}
	}
	// Google itself must stay recordable; only the autocomplete path goes.
	for _, c := range []struct{ host, path string }{
		{"www.google.com", "/search"},
		{"mail.google.com", "/mail/u/0"},
		{"accounts.google.com", "/signin"},
	} {
		if got := f.CheckRequest(req(t, "GET", "https://"+c.host+c.path, "document"), c.host); got != "" {
			t.Errorf("%s%s should be kept, got %q", c.host, c.path, got)
		}
	}
}
