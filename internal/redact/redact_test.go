package redact

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestJSONNested(t *testing.T) {
	var v any
	json.Unmarshal([]byte(`{
      "user": {"email": "a@b.com", "password": "hunter2"},
      "items": [{"api_key": "abc"}, {"qty": 2}],
      "keep": "visible"
    }`), &v)

	var found []string
	out := New(nil).JSON(v, "req.body", &found).(map[string]any)

	if got := out["user"].(map[string]any)["password"]; got != Marker {
		t.Errorf("password = %v, want %s", got, Marker)
	}
	if got := out["user"].(map[string]any)["email"]; got != "a@b.com" {
		t.Errorf("email should survive, got %v", got)
	}
	if got := out["keep"]; got != "visible" {
		t.Errorf("non-secret key should survive, got %v", got)
	}
	want := []string{"req.body.items.0.api_key", "req.body.user.password"}
	if got := Dedupe(found); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}
}

func TestJSONDoesNotFlattenSecretNamedObjects(t *testing.T) {
	var v any
	json.Unmarshal([]byte(`{"auth": {"scheme": "basic", "token": "xyz"}}`), &v)
	var found []string
	out := New(nil).JSON(v, "req.body", &found).(map[string]any)

	inner, ok := out["auth"].(map[string]any)
	if !ok {
		t.Fatalf("a secret-named object should be walked, not replaced: %#v", out["auth"])
	}
	if inner["scheme"] != "basic" {
		t.Errorf("scheme should survive, got %v", inner["scheme"])
	}
	if inner["token"] != Marker {
		t.Errorf("nested token should be redacted, got %v", inner["token"])
	}
}

func TestValues(t *testing.T) {
	v := url.Values{"q": {"widgets"}, "api_key": {"secret"}, "tag": {"a", "b"}}
	var found []string
	out := New(nil).Values(v, "req.query", &found)

	if out["q"] != "widgets" {
		t.Errorf("q = %v", out["q"])
	}
	if out["api_key"] != Marker {
		t.Errorf("api_key = %v", out["api_key"])
	}
	if !reflect.DeepEqual(out["tag"], []string{"a", "b"}) {
		t.Errorf("repeated param should stay a list, got %#v", out["tag"])
	}
	if len(found) != 1 || found[0] != "req.query.api_key" {
		t.Errorf("paths = %v", found)
	}
}

func TestValuesHonoursExtraKeys(t *testing.T) {
	var found []string
	out := New([]string{"customer_ref"}).Values(url.Values{"customer_ref": {"X1"}}, "req.query", &found)
	if out["customer_ref"] != Marker {
		t.Errorf("configured key should be redacted, got %v", out["customer_ref"])
	}
}

func TestCookie(t *testing.T) {
	var found []string
	got := New(nil).Cookie("theme=dark; sid=0123456789abcdef0123; lang=en", "req.header.cookie", &found)

	if !strings.Contains(got, "theme=dark") || !strings.Contains(got, "lang=en") {
		t.Errorf("short non-secret cookies should survive: %q", got)
	}
	if !strings.Contains(got, "sid=<REDACTED:20>") {
		t.Errorf("session cookie should be redacted with its length: %q", got)
	}
	if len(found) != 1 || found[0] != "req.header.cookie.sid" {
		t.Errorf("paths = %v", found)
	}
}

func TestCookieOpaqueValueWithInnocentName(t *testing.T) {
	var found []string
	got := New(nil).Cookie("ph_xyz=0123456789abcdefghij", "req.header.cookie", &found)
	if !strings.Contains(got, "<REDACTED:20>") {
		t.Errorf("long opaque value should be redacted regardless of name: %q", got)
	}
}

func TestSetCookieKeepsAttributes(t *testing.T) {
	var found []string
	got := New(nil).SetCookie("sid=0123456789abcdef; Path=/; HttpOnly; Secure", "resp.header.set-cookie", &found)
	if !strings.HasPrefix(got, "sid=<REDACTED:16>;") {
		t.Errorf("value should be redacted: %q", got)
	}
	if !strings.Contains(got, "HttpOnly") || !strings.Contains(got, "Secure") {
		t.Errorf("attributes describe session behaviour and should survive: %q", got)
	}
}

func TestAuthorizationKeepsScheme(t *testing.T) {
	var found []string
	got := New(nil).Authorization("Bearer abcdefghij", "req.header.authorization", &found)
	if got != "Bearer <REDACTED:10>" {
		t.Errorf("got %q", got)
	}
	if len(found) != 1 {
		t.Errorf("paths = %v", found)
	}
}

func TestIsSecretNameIsLoose(t *testing.T) {
	r := New(nil)
	for _, name := range []string{"Password", "user_password_confirm", "X-Api-Key", "csrf_token"} {
		if !r.IsSecretName(name) {
			t.Errorf("%q should be treated as secret", name)
		}
	}
	for _, name := range []string{"email", "username", "quantity", "theme"} {
		if r.IsSecretName(name) {
			t.Errorf("%q should not be treated as secret", name)
		}
	}
}

func TestTextRedactsEmbeddedQueryTokens(t *testing.T) {
	var found []string
	got := New(nil).Text("https://app.example.com/cb?state=abc&access_token=zzz&next=/home", "resp.body.url", &found)
	if !strings.Contains(got, "state=abc") || !strings.Contains(got, "next=/home") {
		t.Errorf("harmless params should survive: %q", got)
	}
	if strings.Contains(got, "zzz") {
		t.Errorf("embedded token leaked: %q", got)
	}
	if len(found) != 1 || found[0] != "resp.body.url" {
		t.Errorf("paths = %v", found)
	}
}

func TestTextLeavesPlainStringsAlone(t *testing.T) {
	var found []string
	for _, s := range []string{"hello world", "https://example.com/path", ""} {
		if got := New(nil).Text(s, "p", &found); got != s {
			t.Errorf("Text(%q) = %q", s, got)
		}
	}
	if len(found) != 0 {
		t.Errorf("nothing should have been reported, got %v", found)
	}
}

func TestEchoedCookieHeaderInBodyIsRedacted(t *testing.T) {
	var v any
	json.Unmarshal([]byte(`{"headers":{"cookie":"sid=abcdef0123456789xy; theme=dark"}}`), &v)
	var found []string
	out := New(nil).JSON(v, "resp.body", &found).(map[string]any)
	if got := out["headers"].(map[string]any)["cookie"]; got != Marker {
		t.Errorf("an echoed cookie header should not survive in a body, got %v", got)
	}
}
