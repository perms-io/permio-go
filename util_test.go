package permio

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestValidateAPIKey(t *testing.T) {
	if k, err := ValidateAPIKey(testKey); err != nil || k != APIKeyOpaque {
		t.Fatalf("valid key: %v, %v", k, err)
	}
	if k, err := ValidateAPIKey("aaa.bbb.ccc"); err != nil || k != APIKeyJWT {
		t.Fatalf("jwt: %v, %v", k, err)
	}
	// Last checksum character changed.
	last := "a"
	if testKey[len(testKey)-1] == 'a' {
		last = "b"
	}
	bad := testKey[:len(testKey)-1] + last
	for name, key := range map[string]string{
		"empty":    "",
		"checksum": bad,
		"length":   testKey[:20],
		"alphabet": testKey[:10] + "!" + testKey[11:],
		"garbage":  "not-a-key",
	} {
		if _, err := ValidateAPIKey(key); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The same check runs in New, before any network use.
	if _, err := New(Options{APIKey: bad}); !errors.Is(err, ErrConfig) {
		t.Fatalf("New: %v", err)
	}
	t.Setenv(EnvAPIKey, testKey)
	c, err := New(Options{})
	if err != nil {
		t.Fatalf("env key: %v", err)
	}
	_ = c.Close()
}

func TestParseEndpoint(t *testing.T) {
	for in, want := range map[string]struct {
		target string
		tls    bool
	}{
		"":                         {DefaultEndpoint, true},
		"api.example.com:443":      {"api.example.com:443", true},
		"https://api.example.com":  {"api.example.com:443", true},
		"https://api.example.com/": {"api.example.com:443", true},
		"http://localhost:8080":    {"localhost:8080", false},
		"localhost":                {"localhost:443", true},
	} {
		target, tls, err := parseEndpoint(in)
		if err != nil || target != want.target || tls != want.tls {
			t.Errorf("%q: %q %v %v", in, target, tls, err)
		}
	}
	for _, bad := range []string{"ftp://x", "https://x/path", "https://"} {
		if _, _, err := parseEndpoint(bad); !errors.Is(err, ErrConfig) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestPlaintextOnlyToLocalHosts(t *testing.T) {
	for _, ep := range []string{"http://localhost:8080", "http://127.0.0.1:9000", "http://[::1]:9000", "http://api.localhost", "http://app.localhost.:80"} {
		c, err := New(Options{APIKey: testKey, Endpoint: ep})
		if err != nil {
			t.Errorf("%s: %v", ep, err)
			continue
		}
		_ = c.Close()
	}
	for _, opts := range []Options{
		{Endpoint: "http://api.example.com"},
		{Endpoint: "http://10.0.0.5:8080"},
		{Endpoint: "http://localhost.example.com"},
		{Endpoint: "api.example.com:443", Insecure: true},
		{Insecure: true}, // the default (production) endpoint
	} {
		opts.APIKey = testKey
		if _, err := New(opts); !errors.Is(err, ErrConfig) {
			t.Errorf("%+v: %v, want a config error", opts, err)
		}
	}
	c, err := New(Options{APIKey: testKey, Endpoint: "localhost:50051", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestResource(t *testing.T) {
	if got, err := Resource("projects", "p1", "docs", "a/b c"); err != nil || got != "/projects/p1/docs/a%2Fb%20c" {
		t.Fatal(got, err)
	}
	for name, segs := range map[string][]string{"none": nil, "empty segment": {"docs", ""}, "too long": {strings.Repeat("x", MaxResourceURILength)}} {
		if got, err := Resource(segs...); !errors.Is(err, ErrValidation) || got != "" {
			t.Errorf("%s: Resource = %q, %v; want a validation error", name, got, err)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("MustResource() did not panic")
			}
		}()
		MustResource()
	}()
	if got := EncodeSegment("x(1)*!'~._-é"); got != "x%281%29%2A%21%27~._-%C3%A9" {
		t.Fatal(got)
	}
	if err := ValidateResourceURI("/docs/"); err == nil {
		t.Fatal("empty segment accepted")
	}
	for _, ok := range []string{"/a", "/a/b/c", "/tenants/_/docs", "/a%2Fb"} {
		if err := ValidateResourceURI(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a", "/a/", "//a", "/a b", "/a(1)", "/a*"} {
		if err := ValidateResourceURI(bad); !errors.Is(err, ErrValidation) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if GroupPrincipal("eds") != "group:eds" {
		t.Fatal("GroupPrincipal")
	}
}

func TestAccessScopes(t *testing.T) {
	a := &AccessScopes{Under: "/docs", Scopes: []AccessScope{
		{URI: "/docs/1", Kind: ScopeSubtree},
		{URI: "/docs/1/sub", Kind: ScopeSubtree},
		{URI: "/docs/_/public", Kind: ScopePattern},
		{URI: "/docs/x", Kind: ScopeUnknown},
	}}
	re := a.Regexp()
	cases := map[string]bool{
		"/docs/1":          true,
		"/docs/1/a/b":      true,
		"/docs/12":         false, // segment-wise, not string prefix
		"/docs/7/public":   true,
		"/docs/7/public/x": true,
		"/docs/7":          false,
		"/docs/x":          false, // unknown kinds never match
		"docs/1":           false,
	}
	for uri, want := range cases {
		if got := a.Allows(uri); got != want {
			t.Errorf("Allows(%q) = %v, want %v", uri, got, want)
		}
		if got := re.MatchString(uri); got != want {
			t.Errorf("Regexp(%q) = %v, want %v", uri, got, want)
		}
	}
	if got := a.Prefixes(); !reflect.DeepEqual(got, []string{"/docs/1"}) {
		t.Errorf("Prefixes = %v", got)
	}
	if got := a.Patterns(); !reflect.DeepEqual(got, []string{"/docs/_/public"}) {
		t.Errorf("Patterns = %v", got)
	}
	empty := &AccessScopes{Under: "/docs"}
	if !empty.IsEmpty() || empty.Regexp().MatchString("/docs") || empty.Regexp().MatchString("") {
		t.Error("empty scopes")
	}
}
