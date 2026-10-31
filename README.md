# permio-go

[![Go Reference](https://pkg.go.dev/badge/github.com/perms-io/permio-go.svg)](https://pkg.go.dev/github.com/perms-io/permio-go)
[![Version](https://img.shields.io/github/v/tag/perms-io/permio-go?sort=semver&label=version)](https://github.com/perms-io/permio-go/tags)
[![License](https://img.shields.io/github/license/perms-io/permio-go)](LICENSE)

The official Go SDK for [perms.io](https://perms.io), a hosted authorization
service for RBAC and fine-grained, resource-level permissions in multi-tenant
apps. Use it to check whether a user may perform an action on a resource,
grant and revoke roles and permissions, manage groups, and filter lists down
to what a user can access, from any Go service.

Package `permio` wraps the generated gRPC clients with API key auth,
per-attempt timeouts, retries for idempotent reads, typed errors and helpers
for checks, grants, groups and paginated listings. The generated clients ship
in the same module and stay reachable as an escape hatch.

## Install

```bash
go get github.com/perms-io/permio-go@latest
```

Requires Go 1.24 or later.

## Quick start

```go
client, err := permio.New(permio.Options{APIKey: os.Getenv("PERMIO_API_KEY"), Project: "my-app"})
if err != nil { log.Fatal(err) }
defer client.Close()

resource, err := permio.Resource("docs", docID) // "/docs/<encoded docID>"
if err != nil { log.Fatal(err) }
ok, err := client.Check(ctx, userID, "docs.read", resource)
```

A denial is `false` with a nil error. An error means the check could not be
answered (bad key, network, ...); treat it as "not allowed".

## Configuration

```go
client, err := permio.New(permio.Options{
	APIKey:   "perms_...",           // default: $PERMIO_API_KEY
	Project:  "my-app",              // default project_name
	Timeout:  5 * time.Second,       // per attempt; default 10s, negative disables
	ListTimeout: 30 * time.Second,   // per attempt for each list page; default: Timeout
	Retry:    permio.RetryOptions{MaxRetries: 3}, // default 2, negative disables
})
```

- The API key is checked locally (format and checksum) before any request, so
  a mistyped key fails in `New` with a config error. Only the API can tell
  whether a key exists: use `client.WhoAmI(ctx)` to verify it at startup and to
  learn its project and access level (`check` or `full`).
- `Endpoint` takes `host:port` or a URL (`https://api.perms.io`); the default is
  `permio.DefaultEndpoint` (`api.perms.io:443`).
  Plaintext (`Insecure: true` or an `http://` URL) is only allowed to
  `localhost`, `*.localhost` and loopback addresses, since the API key would
  otherwise cross the network in clear; anything else fails in `New`.
- `client.WithProject("other")` returns a client for another project that
  shares the connection.
- Set an overall deadline (across retries) with the context.
- `Options.Conn` takes any `grpc.ClientConnInterface` instead of dialling, e.g.
  a bufconn connection in tests; auth, timeouts, retries and errors still apply.

## Checks

```go
client.Check(ctx, principal, "docs.read", resource)                     // one permission
client.CheckAll(ctx, principal, []string{"docs.read", "docs.write"}, r) // every permission
client.CheckAny(ctx, principal, []string{"docs.read", "docs.admin"}, r) // at least one
client.CheckDetailed(ctx, permio.CheckRequest{...})                     // several resources, with what is missing
client.Assert(ctx, principal, "docs.read", resource)                    // error of kind KindDenied when not allowed

allowed, err := client.BatchCheck(ctx, principal, []string{"docs.read"}, uris) // map[uri]bool, one call per 100
```

`BatchCheck` sends its resources in requests of 100, at most 4 at a time, and
returns results in request order; the first failing request stops the rest and
its error is returned. It takes at most 10,000 resources per call (counted
before duplicates are removed); more is a `KindValidation` error. Raise the cap
with `permio.BatchCheckOptions{MaxResources: n}` as a last argument, or split
the list.

Build resource URIs with `permio.Resource("projects", id, "docs", docID)`,
which percent-encodes each segment so IDs containing `/` stay one segment. Use
the same helper when granting and when checking. It returns an error of kind
`KindValidation` for no segments (never `"/"`, which would cover everything)
or an empty segment; `permio.MustResource` panics instead, for literals.

### Filtering lists

```go
access, err := client.ListAccess(ctx, userID, "docs.read", "/docs")
// access.CoversAll       -> no filter needed
// access.Prefixes()      -> path prefixes (match p or p + "/...")
// access.RegexpSource()  -> one anchored regex for SQL "~" / MongoDB $regex
// access.Allows(uri)     -> test a single URI

who, err := client.WhoHasAccess(ctx, "/docs/42", &permio.WhoHasAccessOptions{Permission: "docs.read"})
```

### Large answers: caps and streaming

A resource can have millions of principals with access, so `WhoHasAccess` and
`ListAccess` collect at most 10,000 results (`permio.DefaultMaxResults`). If
there are more, they stop fetching (at most 10,001 items are requested) and
fail with `KindTooManyResults` / `ErrTooManyResults`; `Error.MaxResults` is the
cap. Raise it per call, or stream with the `Seq` forms, which fetch one page at
a time as the loop asks for more and hold nothing else in memory:

```go
who, err := client.WhoHasAccess(ctx, r, &permio.WhoHasAccessOptions{MaxResults: 50_000})
access, err := client.ListAccess(ctx, userID, "docs.read", "/docs", permio.ListAccessOptions{MaxResults: 50_000})

for entry, err := range client.WhoHasAccessSeq(ctx, r, &permio.WhoHasAccessOptions{Permission: "docs.read"}) {
	if err != nil { return err }
	// ...
}
for scope, err := range client.ListAccessSeq(ctx, userID, "docs.read", "/docs") {
	if err != nil { return err }
	// scope.URI == "/docs" && scope.Kind == permio.ScopeSubtree means it covers everything
}
```

`WhoHasAccessSeq` yields entries in the API's order (by principal ID). When the
principal holds the permission on `under` itself, `ListAccessSeq` yields exactly
one `ScopeSubtree` scope whose URI is `under`.

## Granting and revoking

```go
err := client.Grant(ctx, permio.GrantRequest{
	Principal:   "user-123",
	Resource:    "/docs",               // also covers everything below it
	Permissions: []string{"docs.read"},
	Roles:       []string{roleID},      // role IDs, see ListRoles
})
err = client.Revoke(ctx, permio.GrantRequest{...}) // exactly that URI; revoking twice is harmless
```

Grants and revokes need a full-access API key. They are sent once and never
retried automatically (see Retries).

Permission and role CRUD: `CreatePermission`, `GetPermission`,
`UpdatePermission`, `DeletePermission`, `CreateRole`, `GetRole`, `UpdateRole`,
`DeleteRole`, `GetGrant`.

## Groups

```go
g := client.Groups()
g.Create(ctx, "editors", "Document editors")
g.AddMembers(ctx, "editors", []string{"user-1", "user-2"}) // at most 100 per call
client.Grant(ctx, permio.GrantRequest{Principal: permio.GroupPrincipal("editors"), Resource: "/docs", Permissions: []string{"docs.write"}})
g.ListMembers(ctx, "editors", nil)
g.ListForPrincipal(ctx, "user-1", nil)
g.RemoveMembers(ctx, "editors", []string{"user-2"})
g.Delete(ctx, "editors") // also removes its memberships and grants
```

Group methods take a slug (`editors`) or a principal ID (`group:editors`).
Groups cannot contain groups.

## Listing

List methods return `iter.Seq2[T, error]` iterators that follow pagination
lazily; breaking out of the loop stops fetching.

```go
for role, err := range client.ListRoles(ctx, nil) {
	if err != nil { return err }
	fmt.Println(role.ID, role.Name)
}
perms, err := permio.Collect(client.ListPermissions(ctx, &permio.ListOptions{Search: "docs."}))
```

Available: `ListPermissions`, `ListRoles`, `ListPrincipals`,
`ListAssignments(principal)` (grants), `Groups().List`, `Groups().ListMembers`,
`Groups().ListForPrincipal`.

## Errors

Every failure is a `*permio.Error` with a `Kind`, the gRPC `Code` and the
message. Match kinds with `errors.Is`, read details with `errors.As`:

```go
var perr *permio.Error
switch {
case errors.Is(err, permio.ErrAuth):        // key unknown or revoked
case errors.As(err, &perr) && perr.Kind == permio.KindRateLimited:
	time.Sleep(perr.RetryAfter)
}
```

| Kind / sentinel | When |
| --- | --- |
| `KindConfig` / `ErrConfig` | Malformed API key, bad endpoint, no project |
| `KindAuth` / `ErrAuth` | `Unauthenticated`: key missing, unknown or revoked |
| `KindPermission` / `ErrPermission` | `PermissionDenied`: the key may not make this call (`Missing` lists what it lacks) |
| `KindValidation` / `ErrValidation` | `InvalidArgument`, or the SDK's own input checks |
| `KindNotFound` / `ErrNotFound` | `NotFound` |
| `KindAlreadyExists` / `ErrAlreadyExists` | `AlreadyExists` |
| `KindUnavailable` / `ErrUnavailable` | `Unavailable`: the API could not be reached |
| `KindTimeout` / `ErrTimeout` | `DeadlineExceeded`, per attempt or the context's |
| `KindRateLimited` / `ErrRateLimited` | `ResourceExhausted`: the organisation's rate limit is used up; `RetryAfter` is the server's delay |
| `KindDenied` / `ErrDenied` | Returned by `Assert`/`AssertAll` when the principal lacks the permissions |
| `KindTooManyResults` / `ErrTooManyResults` | `WhoHasAccess` / `ListAccess` found more than `MaxResults` results; use the `Seq` form or raise the cap |
| `KindOther` | Anything else, including cancellation |

`status.Code(err)` also works on these errors.

## Retries

Idempotent reads (Check, BatchCheck, WhoAmI, Get\*, List\*) are retried up to
2 times on `Unavailable` and `DeadlineExceeded`, with jittered exponential
backoff (100ms doubling, capped at 2s). A rate-limited read
(`ResourceExhausted`) is retried after the server's requested delay
(`google.rpc.RetryInfo`, else a `retry-after` header) when that delay is within
`RetryOptions.MaxDelay`; otherwise it fails with `KindRateLimited` and
`RetryAfter` set. `ResourceExhausted` without a delay is not retried. A
`retry-after` on `Unavailable` is used as the minimum backoff.

Each page of a listing (the `List*` iterators, the `Seq` forms, `WhoHasAccess`,
`ListAccess`) is one read under this policy, with `Options.ListTimeout` as its
per-attempt timeout. A page that times out is retried after the backoff, never
immediately.

Writes (Create, Update, Delete, Grant, Revoke, group membership) are never
retried. Grant and revoke converge on the server, so they are safe to repeat by
hand when you know nobody else is changing that grant. `permio.IsIdempotent`
reports whether a method is retried.

## Raw clients

```go
client.Permissions()   // permissionsv1.PermissionsServiceClient
client.Organisations() // organisationv1.OrganisationServiceClient
client.Conn()          // grpc.ClientConnInterface, for other generated clients
```

These carry the same auth, timeouts, retries and typed errors. Set
`ProjectName` on requests yourself. Generated packages:

| Import path | Contents |
| --- | --- |
| `github.com/perms-io/permio-go/proto/permissions/v1` | `PermissionsService` client, permission/role/check/group messages |
| `github.com/perms-io/permio-go/proto/organisation/v1` | `OrganisationService` client, organisation/project/API key messages |
| `github.com/perms-io/permio-go/proto/pagination/v1` | Pagination request/response messages |

## Development

```bash
go vet ./...
go test -race ./...
```

Unit tests run against an in-process gRPC server (bufconn). The integration
test `TestLive` runs only when `PERMIO_API_KEY` is set:

```bash
PERMIO_API_KEY=perms_... go test -count=1 -run TestLive -v .
```

It talks to the dev API by default (`PERMIO_BASE_URL` overrides it) and
refuses production, because it writes. The key needs full access to its
project (`PERMIO_PROJECT`, default: the key's own project). It uses fixed
`sdk-it-go-*` IDs and removes them before and after the run. In CI the
`integration` job runs it when the `PERMIO_DEV_API_KEY` secret exists.

The `proto/` directory is generated from
[perms-io/proto](https://github.com/perms-io/proto) by its release
workflow, which opens a `regen/<tag>` pull request here that replaces only
`proto/`. Do not edit it by hand.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
