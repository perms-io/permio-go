# Changelog

## Unreleased (v0.4.0)

### Removed

- **Breaking:** the `DevEndpoint` constant is gone. Code that used it must set
  `Options.Endpoint` explicitly. `DefaultEndpoint` (production) is unchanged.

## Unreleased (v0.3.0)

### Changed

- **Breaking:** the module path is now `github.com/perms-io/permio-go`, after
  the GitHub organisation was renamed. Update imports:

  ```sh
  go get github.com/perms-io/permio-go@v0.3.0
  find . -name '*.go' -exec sed -i 's#github.com/PrivateJAR/permio-go#github.com/perms-io/permio-go#g' {} +
  go mod tidy
  ```

  Nothing else changed: the API and the generated stubs are the same as
  v0.2.0 apart from their import path. Don't link v0.2.0 and v0.3.0 into the
  same binary; both register the same proto files.

## Unreleased (v0.2.0)

### Changed

- **Behaviour change:** `WhoHasAccess` and `ListAccess` collect at most 10,000
  results by default. With more, they stop fetching (at most cap + 1 items are
  requested) and fail with the new `KindTooManyResults` / `ErrTooManyResults`
  (`Error.MaxResults` is the cap). Raise it with `MaxResults`, or use the new
  streaming forms.
- **Behaviour change:** `BatchCheck` / `BatchCheckDetailed` accept at most
  10,000 resources per call (counted before de-duplication); more is a
  `KindValidation` error.
- `BatchCheck` sends its 100-resource requests 4 at a time instead of one after
  another, building each request only when it is sent. Results keep request
  order; the first failing request cancels the others and its error is
  returned.

### Added

- `Client.WhoHasAccessSeq` and `Client.ListAccessSeq`: `iter.Seq2` streams that
  fetch pages on demand, for answers of any size. A covers-all `ListAccessSeq`
  yields one `ScopeSubtree` scope for `under`.
- `WhoHasAccessOptions.MaxResults`; `ListAccessOptions{MaxResults}` as an
  optional last argument of `ListAccess`; `DefaultMaxResults`.
- `BatchCheckOptions{MaxResources}` as an optional last argument of
  `BatchCheck` / `BatchCheckDetailed`; `DefaultMaxBatchResources`,
  `BatchCheckConcurrency`.
- `Options.ListTimeout`: per-attempt timeout for each list page (default: the
  `Timeout`).

## v0.1.0

First release with the hand-written SDK package.

### Added

- Package `permio` at the module root: the hand-written SDK beside the
  generated stubs.
  - `New(Options)` with local API key validation, `PERMIO_API_KEY` fallback,
    `DefaultEndpoint` and an endpoint constant for the development API,
    default project and `WithProject`,
    per-attempt timeout (default 10s), retry options and an injectable
    `grpc.ClientConnInterface`.
  - Checks: `Check`, `CheckAll`, `CheckAny`, `CheckDetailed`, `Assert`,
    `AssertAll`, `BatchCheck`, `BatchCheckDetailed`.
  - `ListAccess` (with `Allows`, `Prefixes`, `Patterns`, `RegexpSource`) and
    `WhoHasAccess`.
  - `Grant`, `Revoke`, `GetGrant`, `WhoAmI`, permission and role CRUD.
  - Groups via `Client.Groups()`; `GroupPrincipal`, `Resource` /
    `MustResource`, `EncodeSegment`, `ValidateResourceURI`.
  - `Resource()` with no segments (or an empty segment) is a validation error,
    never `"/"`.
  - `Groups.AddMembers` / `RemoveMembers` take at most 100 principals and send
    them in one write; more is a validation error rather than several writes
    that could partly fail.
  - `CreatePermission` and `CreateRole` are idempotent (the API upserts);
    `AlreadyExists` from the API (e.g. a rename onto a used name) maps to
    `KindAlreadyExists` with no extra calls.
  - `iter.Seq2` iterators over every paginated listing, and `Collect`.
  - Typed errors: `*Error` with `Kind` (`errors.Is` with `ErrAuth`,
    `ErrPermission`, `ErrValidation`, `ErrNotFound`, `ErrUnavailable`,
    `ErrTimeout`, `ErrRateLimited`, `ErrDenied`, `ErrConfig`, ...).
    `GRPCStatus()` never reports `OK`: denied errors carry `PermissionDenied`
    and config errors `FailedPrecondition`.
  - Plaintext (`Insecure` or an `http://` endpoint) is only allowed to
    localhost, `*.localhost` and loopback addresses, so the API key is never
    sent in clear over the network.
  - Listings fail with an error if the API repeats a pagination cursor,
    instead of ending quietly with a partial result.
  - Retries of idempotent reads on Unavailable / DeadlineExceeded, and of
    rate-limited reads after the server's RetryInfo / retry-after delay.
    Writes are never retried.
  - Raw clients: `Permissions()`, `Organisations()`, `Conn()`.
- Apache-2.0 LICENSE, CI and release workflows on Blacksmith runners.

### Retracted

- v0.0.1 to v0.0.18 are retracted in `go.mod`: they contained only the
  generated stubs, not the SDK package.

## v0.0.18 and earlier

Generated stubs only, published by PrivateJAR/proto's release workflow.
