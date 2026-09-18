// Package filter decides which proxied exchanges are worth recording.
package filter

import (
	"encoding/json"
	"os"
)

// Rules are the tunable parts of the filter. An override file is merged over
// the built-ins rather than replacing them.
type Rules struct {
	DropHosts      []string `json:"drop_hosts"`
	KeepHosts      []string `json:"keep_hosts"`
	DropPaths      []string `json:"drop_paths"`
	DropExtensions []string `json:"drop_extensions"`
	RedactKeys     []string `json:"redact_keys"`
}

// Builtin covers the traffic that is almost never part of a task flow:
// bundles and media, analytics, error reporting, ads and support widgets.
func Builtin() Rules {
	return Rules{
		DropHosts: []string{
			// analytics / product telemetry
			"google-analytics.com", "analytics.google.com", "googletagmanager.com",
			"segment.io", "segment.com", "mixpanel.com", "amplitude.com",
			"hotjar.com", "hotjar.io", "clarity.ms", "matomo.cloud",
			"plausible.io", "posthog.com", "heap.io", "fullstory.com",
			"statcounter.com", "quantserve.com", "scorecardresearch.com",
			// error reporting / APM / tracing
			"sentry.io", "ingest.sentry.io", "bugsnag.com", "datadoghq.com",
			"datadoghq.eu", "newrelic.com", "nr-data.net", "rollbar.com",
			"logrocket.com", "logrocket.io", "raygun.io", "trackjs.com",
			// ads
			"doubleclick.net", "googlesyndication.com", "googleadservices.com",
			"adservice.google.com", "adnxs.com", "criteo.com", "taboola.com",
			"outbrain.com", "pubmatic.com", "rubiconproject.com",
			// social pixels
			"connect.facebook.net", "facebook.com/tr", "analytics.tiktok.com",
			"ads-twitter.com", "snap.licdn.com", "bat.bing.com",
			// support / chat widgets
			"intercom.io", "intercomcdn.com", "widget.intercom.io",
			"zdassets.com", "zopim.com", "crisp.chat", "drift.com",
			"livechatinc.com", "tawk.to", "usersnap.com",
			// static CDNs
			"fonts.googleapis.com", "fonts.gstatic.com", "cdnjs.cloudflare.com",
			"unpkg.com", "cdn.jsdelivr.net", "ajax.googleapis.com",
			"stackpath.bootstrapcdn.com", "use.fontawesome.com",
			// browser services -- Firefox is the documented browser for this
			// tool, and it chatters at Mozilla constantly throughout a session
			"mozilla.com", "mozilla.net", "mozilla.org", "firefox.com",
			"detectportal.firefox.com", "mozgcp.net",
			"mozilla-ohttp.fastly-edge.com",
			"gvt1.com", "gvt2.com", "safebrowsing.googleapis.com",
		},
		// First-party telemetry cannot be caught by host, because it is served
		// from the same domain as the traffic being recorded. Only paths
		// specific enough to be unambiguous belong here -- anything generic
		// (/api/track, /collect) would eventually eat a real endpoint.
		DropPaths: []string{
			// hosting-platform analytics mounted into the app
			"/_vercel/insights", "/_vercel/speed-insights",
			"/cdn-cgi/rum", "/cdn-cgi/beacon", "/cdn-cgi/zaraz",
			"/cdn-cgi/challenge-platform",
			// self-hosted analytics with conventional mount points
			"/matomo.php", "/piwik.php", "/g/collect", "/j/collect",
			"/ingest/e", "/ingest/decide", "/ingest/s",
			// URL-bar autocomplete; google.com as a whole cannot be dropped
			// because real apps are recorded there
			"/complete/search",
			// dev-server tooling, noisy when recording against a local app
			"/_next/webpack-hmr", "/__nextjs_original-stack-frame",
			"/__nextjs_launch-editor", "/@vite", "/@react-refresh",
			"/sockjs-node", "/browser-sync", "/__webpack_hmr",
		},
		DropExtensions: []string{
			".js", ".mjs", ".cjs", ".css", ".map",
			".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp", ".avif", ".apng",
			".woff", ".woff2", ".ttf", ".otf", ".eot",
			".mp4", ".webm", ".ogv", ".mov", ".mp3", ".ogg", ".wav", ".m4a", ".m3u8", ".ts",
			".wasm", ".pdf", ".zip", ".gz", ".br",
		},
	}
}

// Load merges an override file over the built-in rules. A missing path at the
// default location is not an error.
func Load(path string, optional bool) (Rules, error) {
	base := Builtin()
	data, err := os.ReadFile(path)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return base, nil
		}
		return base, err
	}
	var over Rules
	if err := json.Unmarshal(data, &over); err != nil {
		return base, err
	}
	base.DropHosts = append(base.DropHosts, over.DropHosts...)
	base.DropPaths = append(base.DropPaths, over.DropPaths...)
	base.DropExtensions = append(base.DropExtensions, over.DropExtensions...)
	base.KeepHosts = append(base.KeepHosts, over.KeepHosts...)
	base.RedactKeys = append(base.RedactKeys, over.RedactKeys...)
	return base, nil
}
