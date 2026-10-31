package permio_test

// Integration test against a real deployment. Skipped unless PERMIO_API_KEY is
// set. PERMIO_BASE_URL defaults to the development API (permio.DevEndpoint).
// Because the test writes, it only runs against an allowlist of hosts (see
// allowedLiveHost): the dev API and local servers, never production. The key
// needs full access to its project (PERMIO_PROJECT, default: the key's project
// from WhoAmI):
//
//	PERMIO_API_KEY=perms_... go test -run TestLive -v .
//
// Everything it creates uses fixed IDs prefixed "sdk-it-go" and is removed
// before and after the run, so an interrupted run is cleaned up by the next
// one. Runs sharing a project must not overlap (CI serialises them).

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	permio "github.com/perms-io/permio-go"
)

const (
	alice   = "sdk-it-go-alice"
	bob     = "sdk-it-go-bob"
	editors = "sdk-it-go-editors"
	read    = "sdk-it-go.read"
	write   = "sdk-it-go.write"
	root    = "/sdk-it-go"
	docs    = root + "/docs"
	doc1    = docs + "/1"
	other   = root + "/other"
)

// allowedLiveHost reports whether endpoint ("host:port", "host" or a URL) is
// one the integration test may write to: the dev API, a loopback address,
// localhost, or a name under .localhost or .test. Anything else, production
// included, is refused.
func allowedLiveHost(endpoint string) (string, bool) {
	raw := endpoint
	if !strings.Contains(raw, "://") {
		raw = "//" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return endpoint, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	switch {
	case host == "dev-api.perms.io", host == "localhost", host == "127.0.0.1", host == "::1",
		strings.HasSuffix(host, ".localhost"), strings.HasSuffix(host, ".test"):
		return host, true
	}
	return host, false
}

func TestLive(t *testing.T) {
	key := os.Getenv("PERMIO_API_KEY")
	if key == "" {
		t.Skip("PERMIO_API_KEY is not set")
	}
	endpoint := os.Getenv("PERMIO_BASE_URL")
	if endpoint == "" {
		endpoint = permio.DevEndpoint
	}
	if host, ok := allowedLiveHost(endpoint); !ok {
		t.Fatalf("refusing to run the integration test against %q: only dev-api.perms.io, localhost, loopback addresses, *.localhost and *.test are allowed", host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	c, err := permio.New(permio.Options{APIKey: key, Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	project := os.Getenv("PERMIO_PROJECT")
	if project == "" {
		me, err := c.WhoAmI(ctx)
		if err != nil {
			t.Fatalf("WhoAmI: %v", err)
		}
		project = me.Project
	}
	if project == "" {
		project = "default"
	}
	c = c.WithProject(project)

	// Deleting the permissions also removes every grant that uses them.
	cleanUp := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.Groups().Delete(ctx, editors); err != nil {
			t.Errorf("cleanup: delete group: %v", err)
		}
		for _, p := range []string{read, write} {
			if err := c.DeletePermission(ctx, p); err != nil {
				t.Errorf("cleanup: delete %s: %v", p, err)
			}
		}
	}
	cleanUp()
	t.Cleanup(cleanUp)
	for _, p := range []string{read, write} {
		if _, err := c.CreatePermission(ctx, p, "permio-go integration test"); err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
	}

	check := func(t *testing.T, principal, permission, resource string, want bool) {
		t.Helper()
		got, err := c.Check(ctx, principal, permission, resource)
		if err != nil {
			t.Fatalf("Check(%s, %s, %s): %v", principal, permission, resource, err)
		}
		if got != want {
			t.Fatalf("Check(%s, %s, %s) = %v, want %v", principal, permission, resource, got, want)
		}
	}

	t.Run("WhoAmI describes the API key", func(t *testing.T) {
		me, err := c.WhoAmI(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if me.Kind != permio.PrincipalAPIKey || me.Project != project || me.PrincipalID == "" || me.OrganisationID == "" || me.APIKeyAccess != permio.APIKeyAccessFull {
			t.Fatalf("WhoAmI = %+v", me)
		}
	})

	t.Run("CreatePermission is idempotent", func(t *testing.T) {
		p, err := c.CreatePermission(ctx, read, "permio-go integration test")
		if err != nil || p.Name != read {
			t.Fatalf("CreatePermission again = %+v, %v", p, err)
		}
		// A different description updates the existing permission.
		p, err = c.CreatePermission(ctx, read, "permio-go integration test (updated)")
		if err != nil || p.Description != "permio-go integration test (updated)" {
			t.Fatalf("CreatePermission with a new description = %+v, %v", p, err)
		}
	})

	t.Run("grant, then check is allowed below the granted URI", func(t *testing.T) {
		check(t, alice, read, doc1, false)
		if err := c.Grant(ctx, permio.GrantRequest{Principal: alice, Resource: docs, Permissions: []string{read}}); err != nil {
			t.Fatal(err)
		}
		check(t, alice, read, doc1, true)
		check(t, alice, write, doc1, false)
	})

	t.Run("BatchCheck answers each resource", func(t *testing.T) {
		got, err := c.BatchCheckDetailed(ctx, alice, []string{read}, []string{doc1, other, docs})
		if err != nil {
			t.Fatal(err)
		}
		want := []bool{true, false, true}
		for i, r := range got {
			if r.Allowed != want[i] {
				t.Fatalf("BatchCheck = %+v", got)
			}
		}
	})

	t.Run("ListAccess returns the granted subtree", func(t *testing.T) {
		a, err := c.ListAccess(ctx, alice, read, root)
		if err != nil {
			t.Fatal(err)
		}
		if a.CoversAll || len(a.Prefixes()) != 1 || a.Prefixes()[0] != docs || !a.Allows(doc1) || a.Allows(other) {
			t.Fatalf("ListAccess = %+v", a)
		}
	})

	t.Run("WhoHasAccess lists the grantee", func(t *testing.T) {
		entries, err := c.WhoHasAccess(ctx, doc1, &permio.WhoHasAccessOptions{Permission: read})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range entries {
			found = found || e.Principal == alice
		}
		if !found {
			t.Fatalf("WhoHasAccess = %+v", entries)
		}
	})

	t.Run("revoke, then check is denied", func(t *testing.T) {
		req := permio.GrantRequest{Principal: alice, Resource: docs, Permissions: []string{read}}
		if err := c.Revoke(ctx, req); err != nil {
			t.Fatal(err)
		}
		check(t, alice, read, doc1, false)
		// Revoking what is no longer held is harmless.
		if err := c.Revoke(ctx, req); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a group grant applies to its members until the group is deleted", func(t *testing.T) {
		g := c.Groups()
		if _, err := g.Create(ctx, editors, "permio-go integration test"); err != nil {
			t.Fatal(err)
		}
		res, err := g.AddMembers(ctx, editors, []string{bob})
		if err != nil || len(res.Changed) != 1 || res.Changed[0] != bob || len(res.Unchanged) != 0 {
			t.Fatalf("AddMembers = %+v, %v", res, err)
		}
		members, err := permio.Collect(g.ListMembers(ctx, editors, nil))
		if err != nil || len(members) != 1 || members[0].PrincipalID != bob {
			t.Fatalf("ListMembers = %+v, %v", members, err)
		}
		if err := c.Grant(ctx, permio.GrantRequest{Principal: permio.GroupPrincipal(editors), Resource: docs, Permissions: []string{write}}); err != nil {
			t.Fatal(err)
		}
		check(t, bob, write, doc1, true)
		check(t, alice, write, doc1, false)

		if err := g.Delete(ctx, editors); err != nil {
			t.Fatal(err)
		}
		check(t, bob, write, doc1, false)
	})

	t.Run("an unknown key is rejected with an auth error", func(t *testing.T) {
		bad, err := permio.New(permio.Options{APIKey: "perms_0123456789ABCDEFGHIJKLMNOPQRSTUV1ggZdL", Endpoint: endpoint, Project: project})
		if err != nil {
			t.Fatal(err)
		}
		defer bad.Close()
		if _, err := bad.Check(ctx, alice, read, doc1); !errors.Is(err, permio.ErrAuth) {
			t.Fatalf("Check with a bad key: %v", err)
		}
		if _, err := bad.WhoAmI(ctx); !errors.Is(err, permio.ErrAuth) {
			t.Fatalf("WhoAmI with a bad key: %v", err)
		}
	})
}

func TestLiveHostAllowlist(t *testing.T) {
	for _, ok := range []string{permio.DevEndpoint, "https://dev-api.perms.io", "localhost:8080", "http://127.0.0.1:9000",
		"http://[::1]:9000", "http://api.localhost", "permio.test:443", "https://Dev-API.perms.io."} {
		if _, allowed := allowedLiveHost(ok); !allowed {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{permio.DefaultEndpoint, "https://api.perms.io", "temp-api.perms.io:443", "https://dev-api.perms.io.evil.com",
		"evil.com/dev-api.perms.io", "https://user@example.com", "localhost.example.com", "test", "", "://"} {
		if _, allowed := allowedLiveHost(bad); allowed {
			t.Errorf("%q allowed", bad)
		}
	}
}
