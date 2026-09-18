// Package redact removes credential-shaped values from recorded traffic while
// preserving where they were. The recorded paths are the handoff to the agent:
// each one is a value a generated automation must take from the environment
// rather than hardcode.
package redact

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const Marker = "<REDACTED>"

// Sized marks a header value, where the length is a useful hint (a 200-char
// bearer token reads differently from a 6-char one) and the value is not.
func Sized(n int) string { return fmt.Sprintf("<REDACTED:%d>", n) }

// Per-user credentials. App-level identifiers -- publishable/anon API keys,
// client ids -- are deliberately absent: they are static, shipped to every
// browser, and an automation cannot replay the flow without them. Anything
// that identifies a *session* or a *person* stays on the list.
var builtinKeys = []string{
	"password", "passwd", "pwd", "passphrase",
	"secret", "token",
	"auth", "authorization", "credential", "credentials", "bearer",
	"private_key", "privatekey", "client_secret",
	"otp", "mfa", "totp", "2fa", "verification_code",
	"signature", "_csrf", "csrf", "xsrf",
	"cvv", "cvc", "card_number", "cardnumber", "pan", "iban", "sort_code",
	"ssn", "national_insurance",
	// Bodies that echo the request back (debug endpoints, API playgrounds)
	// otherwise reintroduce the very headers we strip elsewhere.
	"cookie",
}

// Cookie names that are credentials regardless of what they are called
// elsewhere. Combined with the length heuristic this catches session cookies
// without stripping harmless preferences like `theme=dark`.
var sessionCookieNames = []string{
	"sid", "sess", "session", "sessid", "sessionid", "phpsessid",
	"jsessionid", "asp.net_sessionid", "connect.sid", "_session",
	"remember", "login", "identity", "user",
}

// Cookie values at least this long are assumed to be opaque credentials.
const opaqueCookieLen = 16

type Redactor struct {
	keys  []string
	allow map[string]bool
}

// New builds a redactor from the built-in terms plus any extra ones. Names in
// allow are never redacted, which is how a site whose field happens to be
// called "secret_menu" stays readable.
func New(extra, allow []string) *Redactor {
	keys := make([]string, 0, len(builtinKeys)+len(extra))
	keys = append(keys, builtinKeys...)
	for _, k := range extra {
		keys = append(keys, strings.ToLower(strings.TrimSpace(k)))
	}
	allowed := make(map[string]bool, len(allow))
	for _, a := range allow {
		allowed[strings.ToLower(strings.TrimSpace(a))] = true
	}
	return &Redactor{keys: keys, allow: allowed}
}

// Short terms are matched against whole name segments rather than as
// substrings. "pan" inside "company" and "auth" inside "author" are the kind
// of false positive that silently destroys a transcript's usefulness.
const substringMinLen = 5

// IsSecretName matches loosely on purpose: `user_password_confirm` and
// `X-Api-Key` should both hit.
func (r *Redactor) IsSecretName(name string) bool {
	n := strings.ToLower(name)
	if r.allow[n] {
		return false
	}
	var segs []string
	for _, k := range r.keys {
		if k == "" {
			continue
		}
		if len(k) >= substringMinLen {
			if strings.Contains(n, k) {
				return true
			}
			continue
		}
		if segs == nil {
			// Segment the original so camelCase humps survive.
			segs = segments(name)
		}
		for _, s := range segs {
			if s == k {
				return true
			}
		}
	}
	return false
}

// segments splits a field name on punctuation and camelCase humps, so
// `p_company_id`, `apiKey` and `X-Auth-Token` all break into their parts.
func segments(name string) []string {
	var out []string
	var cur strings.Builder
	var prevLower bool
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			cur.WriteRune(r)
			prevLower = true
		case r >= '0' && r <= '9':
			cur.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			if prevLower {
				flush()
			}
			cur.WriteRune(r - 'A' + 'a')
			prevLower = false
		default:
			flush()
			prevLower = false
		}
	}
	flush()
	return out
}

// JSON walks a decoded JSON value, replacing secret-named leaves and appending
// the dotted path of each replacement to found.
func (r *Redactor) JSON(v any, path string, found *[]string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			child := join(path, k)
			if r.IsSecretName(k) && isScalar(val) {
				out[k] = Marker
				*found = append(*found, child)
				continue
			}
			if s, ok := val.(string); ok {
				out[k] = r.Text(s, child, found)
				continue
			}
			out[k] = r.JSON(val, child, found)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = r.JSON(val, join(path, strconv.Itoa(i)), found)
		}
		return out
	default:
		return v
	}
}

// Values redacts url.Values, used for both query strings and form bodies.
func (r *Redactor) Values(v url.Values, path string, found *[]string) map[string]any {
	out := make(map[string]any, len(v))
	for k, vals := range v {
		child := join(path, k)
		if r.IsSecretName(k) {
			*found = append(*found, child)
			out[k] = Marker
			continue
		}
		// A non-secret param can still carry one, e.g. ?next=/x?token=y.
		scrubbed := make([]string, len(vals))
		for i, v := range vals {
			scrubbed[i] = r.Text(v, child, found)
		}
		if len(scrubbed) == 1 {
			out[k] = scrubbed[0]
		} else {
			out[k] = scrubbed
		}
	}
	return out
}

// queryPair matches a `?key=value` or `&key=value` run inside free text.
var queryPair = regexp.MustCompile(`([?&])([A-Za-z0-9_.\-\[\]%]+)=([^&\s"'<>#]*)`)

// Text redacts credentials embedded in a string value -- a callback URL in a
// JSON field, a Location header, a Referer. These carry real tokens and are
// easy to miss because the enclosing key is innocuous.
func (r *Redactor) Text(s, path string, found *[]string) string {
	if !strings.ContainsAny(s, "?&") {
		return s
	}
	hit := false
	out := queryPair.ReplaceAllStringFunc(s, func(m string) string {
		parts := queryPair.FindStringSubmatch(m)
		if parts[3] == "" || !r.IsSecretName(parts[2]) {
			return m
		}
		hit = true
		return parts[1] + parts[2] + "=" + Marker
	})
	if hit {
		*found = append(*found, path)
	}
	return out
}

// Cookie redacts the values of a request Cookie header, keeping every name so
// the agent can see which credentials a step depends on.
func (r *Redactor) Cookie(header, path string, found *[]string) string {
	parts := strings.Split(header, ";")
	for i, p := range parts {
		lead := ""
		if trimmed := strings.TrimLeft(p, " "); trimmed != p {
			lead = p[:len(p)-len(trimmed)]
			p = trimmed
		}
		name, value, ok := strings.Cut(p, "=")
		if !ok || value == "" {
			parts[i] = lead + p
			continue
		}
		if r.secretCookie(name, value) {
			*found = append(*found, join(path, name))
			parts[i] = lead + name + "=" + Sized(len(value))
			continue
		}
		parts[i] = lead + p
	}
	return strings.Join(parts, ";")
}

// SetCookie redacts the value of a Set-Cookie header, keeping its attributes
// (HttpOnly, Secure, Max-Age) because they describe how the session behaves.
func (r *Redactor) SetCookie(header, path string, found *[]string) string {
	first, rest, hasRest := strings.Cut(header, ";")
	name, value, ok := strings.Cut(first, "=")
	if !ok || value == "" {
		return header
	}
	if r.secretCookie(name, value) {
		*found = append(*found, join(path, strings.TrimSpace(name)))
		first = name + "=" + Sized(len(value))
	}
	if hasRest {
		return first + ";" + rest
	}
	return first
}

func (r *Redactor) secretCookie(name, value string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if r.IsSecretName(n) {
		return true
	}
	for _, s := range sessionCookieNames {
		if strings.Contains(n, s) {
			return true
		}
	}
	return len(value) >= opaqueCookieLen
}

// Authorization keeps the scheme, which tells the agent what kind of
// credential the endpoint wants.
func (r *Redactor) Authorization(value, path string, found *[]string) string {
	*found = append(*found, path)
	scheme, rest, ok := strings.Cut(value, " ")
	if !ok {
		return Sized(len(value))
	}
	return scheme + " " + Sized(len(rest))
}

// Header redacts an arbitrary header value whose name looked secret.
func (r *Redactor) Header(value, path string, found *[]string) string {
	*found = append(*found, path)
	return Sized(len(value))
}

// Dedupe sorts and de-duplicates a path list for stable output.
func Dedupe(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	sort.Strings(paths)
	out := paths[:1]
	for _, p := range paths[1:] {
		if p != out[len(out)-1] {
			out = append(out, p)
		}
	}
	return out
}

func isScalar(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return false
	}
	return true
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
