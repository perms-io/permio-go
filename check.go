package permio

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"

	pb "github.com/perms-io/permio-go/proto/permissions/v1"
)

// CheckRequest is a check of several permissions on several resources.
type CheckRequest struct {
	// Principal is the principal (user, service, "group:<slug>"...) whose
	// permissions are checked.
	Principal string
	// Resources are resource URIs; every one is checked. At most 100.
	Resources []string
	// Permissions are permission names. At most 100.
	Permissions []string
}

func checkInputs(principal string, resources, permissions []string, maxResources int) ([]string, []string, error) {
	if principal == "" {
		return nil, nil, invalid("principal is required")
	}
	resources, permissions = uniq(resources), uniq(permissions)
	if len(resources) == 0 {
		return nil, nil, invalid("at least one resource is required")
	}
	if len(permissions) == 0 {
		return nil, nil, invalid("at least one permission is required")
	}
	if maxResources > 0 && len(resources) > maxResources {
		return nil, nil, invalid("at most %d resources per check", maxResources)
	}
	if len(permissions) > MaxBatch {
		return nil, nil, invalid("at most %d permissions per check", MaxBatch)
	}
	for _, p := range permissions {
		if p == "" {
			return nil, nil, invalid("permission names must not be empty")
		}
	}
	for _, r := range resources {
		if err := ValidateResourceURI(r); err != nil {
			return nil, nil, err
		}
	}
	return resources, permissions, nil
}

// CheckDetailed checks whether the principal holds every permission on every
// resource and returns what is missing. A denial is a normal result, not an
// error.
//
// It fails with [KindPermission] if the API key lacks permission.check, and
// [KindValidation] for malformed URIs or empty inputs.
func (c *Client) CheckDetailed(ctx context.Context, req CheckRequest) (*CheckResult, error) {
	resources, permissions, err := checkInputs(req.Principal, req.Resources, req.Permissions, MaxBatch)
	if err != nil {
		return nil, err
	}
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	res, err := c.permissions.Check(ctx, &pb.CheckPermissionRequest{
		ProjectName: project, PrincipalId: req.Principal, ResourceUris: resources, Permissions: permissions,
	})
	if err != nil {
		return nil, err
	}
	out := &CheckResult{Allowed: res.GetPassed(), Missing: []MissingPermission{}}
	for _, m := range res.GetMissingPermissions() {
		if len(m.GetMissingPermissions()) == 0 {
			continue
		}
		out.Missing = append(out.Missing, MissingPermission{Resource: m.GetResourceUri(), Permissions: m.GetMissingPermissions()})
	}
	return out, nil
}

// Check reports whether principal holds permission on resource. A denial is
// false with a nil error.
func (c *Client) Check(ctx context.Context, principal, permission, resource string) (bool, error) {
	return c.CheckAll(ctx, principal, []string{permission}, resource)
}

// CheckAll reports whether principal holds every one of permissions on resource.
func (c *Client) CheckAll(ctx context.Context, principal string, permissions []string, resource string) (bool, error) {
	res, err := c.CheckDetailed(ctx, CheckRequest{Principal: principal, Resources: []string{resource}, Permissions: permissions})
	if err != nil {
		return false, err
	}
	return res.Allowed, nil
}

// CheckAny reports whether principal holds at least one of permissions on
// resource. It makes a single Check call.
func (c *Client) CheckAny(ctx context.Context, principal string, permissions []string, resource string) (bool, error) {
	res, err := c.CheckDetailed(ctx, CheckRequest{Principal: principal, Resources: []string{resource}, Permissions: permissions})
	if err != nil {
		return false, err
	}
	if res.Allowed {
		return true, nil
	}
	if len(res.Missing) == 0 {
		// Denied without saying what is missing: fail closed.
		return false, nil
	}
	wanted := uniq(permissions)
	for _, m := range res.Missing {
		if !slices.ContainsFunc(wanted, func(p string) bool { return !slices.Contains(m.Permissions, p) }) {
			return false, nil
		}
	}
	return true, nil
}

// Assert returns nil when principal holds permission on resource, and an
// [Error] of kind [KindDenied] (with Missing filled in) when it does not.
func (c *Client) Assert(ctx context.Context, principal, permission, resource string) error {
	return c.AssertAll(ctx, CheckRequest{Principal: principal, Resources: []string{resource}, Permissions: []string{permission}})
}

// AssertAll returns nil when the principal holds every permission on every
// resource, and an [Error] of kind [KindDenied] when it does not.
func (c *Client) AssertAll(ctx context.Context, req CheckRequest) error {
	res, err := c.CheckDetailed(ctx, req)
	if err != nil {
		return err
	}
	if !res.Allowed {
		return deniedError(req.Principal, res.Missing)
	}
	return nil
}

// DefaultMaxBatchResources is the default cap on resources per
// [Client.BatchCheck] call.
const DefaultMaxBatchResources = 10_000

// BatchCheckConcurrency is how many BatchCheck requests (of up to 100
// resources each) one [Client.BatchCheck] call keeps in flight.
const BatchCheckConcurrency = 4

// BatchCheckOptions refines [Client.BatchCheck] and [Client.BatchCheckDetailed].
type BatchCheckOptions struct {
	// MaxResources caps the resources one call accepts, counted as given
	// (before duplicates are removed). Zero means [DefaultMaxBatchResources]
	// (10,000); more fail with [KindValidation].
	MaxResources int
}

// BatchCheck checks each resource separately and returns, per resource URI,
// whether principal holds every one of permissions on it. Use it to filter a
// list you already have in memory. Resources are sent in requests of 100, at
// most [BatchCheckConcurrency] at a time; the first failing request stops the
// rest and its error is returned. At most MaxResources resources (default
// 10,000) per call. Pass at most one opts.
func (c *Client) BatchCheck(ctx context.Context, principal string, permissions []string, resources []string, opts ...BatchCheckOptions) (map[string]bool, error) {
	entries, err := c.BatchCheckDetailed(ctx, principal, permissions, resources, opts...)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(entries))
	for _, e := range entries {
		out[e.Resource] = e.Allowed
	}
	return out, nil
}

// BatchCheckDetailed is BatchCheck returning one entry per distinct resource,
// in request order, with the missing permissions.
func (c *Client) BatchCheckDetailed(ctx context.Context, principal string, permissions []string, resources []string, opts ...BatchCheckOptions) ([]BatchResult, error) {
	var o BatchCheckOptions
	if len(opts) > 1 {
		return nil, invalid("pass at most one BatchCheckOptions")
	} else if len(opts) == 1 {
		o = opts[0]
	}
	maxResources := o.MaxResources
	switch {
	case maxResources == 0:
		maxResources = DefaultMaxBatchResources
	case maxResources < 0:
		return nil, invalid("MaxResources must not be negative")
	}
	if len(resources) > maxResources {
		return nil, invalid("at most %d resources per BatchCheck call (got %d); split the list or raise MaxResources", maxResources, len(resources))
	}
	resources, permissions, err := checkInputs(principal, resources, permissions, 0)
	if err != nil {
		return nil, err
	}
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	responses, err := mapChunks(ctx, len(resources), MaxBatch, BatchCheckConcurrency, func(ctx context.Context, lo, hi int) (*pb.BatchCheckResponse, error) {
		return c.permissions.BatchCheck(ctx, &pb.BatchCheckRequest{
			ProjectName: project, PrincipalId: principal, ResourceUris: resources[lo:hi], Permissions: permissions,
		})
	})
	if err != nil {
		return nil, err
	}
	byURI := make(map[string]BatchResult, len(resources))
	for _, res := range responses {
		for _, r := range res.GetResults() {
			missing := r.GetMissingPermissions()
			if missing == nil {
				missing = []string{}
			}
			byURI[r.GetResourceUri()] = BatchResult{Resource: r.GetResourceUri(), Allowed: r.GetAllowed() && len(missing) == 0, Missing: missing}
		}
	}
	out := make([]BatchResult, 0, len(resources))
	for _, r := range resources {
		e, ok := byURI[r]
		if !ok {
			// Fail closed: every requested resource must have its own answer.
			return nil, inconsistent("no BatchCheck result for %q", r)
		}
		out = append(out, e)
	}
	return out, nil
}

// mapChunks calls fn for each [lo, hi) chunk of n items, size at a time, with
// at most workers calls in flight, and returns the results in chunk order.
// Requests are built as workers pick chunks up, not up front. The first error
// cancels the calls still running, stops new ones, and is returned.
func mapChunks[R any](ctx context.Context, n, size, workers int, fn func(ctx context.Context, lo, hi int) (R, error)) ([]R, error) {
	chunks := (n + size - 1) / size
	results := make([]R, chunks)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		next     atomic.Int64
		once     sync.Once
		firstErr error
		wg       sync.WaitGroup
	)
	for range min(workers, chunks) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= chunks || ctx.Err() != nil {
					return
				}
				r, err := fn(ctx, i*size, min(n, (i+1)*size))
				if err != nil {
					once.Do(func() {
						firstErr = err
						cancel()
					})
					return
				}
				results[i] = r
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, toError(err, nil)
	}
	return results, nil
}
