package permio

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	paginationv1 "github.com/perms-io/permio-go/proto/pagination/v1"
	pb "github.com/perms-io/permio-go/proto/permissions/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

var ctx = context.Background()

func allowAll(_ context.Context, _ *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
	return &pb.CheckPermissionResponse{Passed: true}, nil
}

func TestCheckSendsAuthAndProject(t *testing.T) {
	var got *pb.CheckPermissionRequest
	s := &fakeServer{check: func(_ context.Context, r *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
		got = r
		return &pb.CheckPermissionResponse{Passed: true}, nil
	}}
	c := start(t, s, Options{})
	ok, err := c.Check(ctx, "alice", "docs.read", "/docs/1")
	if err != nil || !ok {
		t.Fatalf("Check = %v, %v", ok, err)
	}
	if got.GetProjectName() != "proj" || got.GetPrincipalId() != "alice" ||
		!reflect.DeepEqual(got.GetResourceUris(), []string{"/docs/1"}) || !reflect.DeepEqual(got.GetPermissions(), []string{"docs.read"}) {
		t.Fatalf("request = %v", got)
	}
	if !reflect.DeepEqual(s.auth, []string{"Bearer " + testKey}) {
		t.Fatalf("authorization = %v", s.auth)
	}

	// WithProject overrides the project and shares the connection.
	if _, err := c.WithProject("other").Check(ctx, "alice", "docs.read", "/docs/1"); err != nil {
		t.Fatal(err)
	}
	if got.GetProjectName() != "other" {
		t.Fatalf("project = %q", got.GetProjectName())
	}
}

func TestCheckDenialIsNotAnError(t *testing.T) {
	s := &fakeServer{check: func(_ context.Context, r *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
		// alice holds docs.read only.
		var missing []string
		for _, p := range r.GetPermissions() {
			if p != "docs.read" {
				missing = append(missing, p)
			}
		}
		if len(missing) == 0 {
			return &pb.CheckPermissionResponse{Passed: true}, nil
		}
		return &pb.CheckPermissionResponse{MissingPermissions: []*pb.MissingPermissions{{ResourceUri: r.GetResourceUris()[0], MissingPermissions: missing}}}, nil
	}}
	c := start(t, s, Options{})

	if ok, err := c.Check(ctx, "alice", "docs.write", "/docs/1"); ok || err != nil {
		t.Fatalf("Check = %v, %v", ok, err)
	}
	if ok, err := c.CheckAll(ctx, "alice", []string{"docs.read", "docs.write"}, "/docs/1"); ok || err != nil {
		t.Fatalf("CheckAll = %v, %v", ok, err)
	}
	if ok, err := c.CheckAny(ctx, "alice", []string{"docs.read", "docs.write"}, "/docs/1"); !ok || err != nil {
		t.Fatalf("CheckAny = %v, %v", ok, err)
	}
	if ok, err := c.CheckAny(ctx, "alice", []string{"docs.write", "docs.delete"}, "/docs/1"); ok || err != nil {
		t.Fatalf("CheckAny(none held) = %v, %v", ok, err)
	}

	err := c.Assert(ctx, "alice", "docs.write", "/docs/1")
	var pe *Error
	if !errors.Is(err, ErrDenied) || !errors.As(err, &pe) {
		t.Fatalf("Assert = %v", err)
	}
	want := []MissingPermission{{Resource: "/docs/1", Permissions: []string{"docs.write"}}}
	if pe.Principal != "alice" || !reflect.DeepEqual(pe.Missing, want) {
		t.Fatalf("denied error = %+v", pe)
	}
	if err := c.Assert(ctx, "alice", "docs.read", "/docs/1"); err != nil {
		t.Fatalf("Assert(held) = %v", err)
	}
}

func TestInputValidation(t *testing.T) {
	s := &fakeServer{check: allowAll}
	c := start(t, s, Options{})
	for name, err := range map[string]error{
		"no principal": func() error { _, err := c.Check(ctx, "", "p", "/a"); return err }(),
		"bad uri":      func() error { _, err := c.Check(ctx, "u", "p", "a"); return err }(),
		"empty perm":   func() error { _, err := c.Check(ctx, "u", "", "/a"); return err }(),
		"no perms":     func() error { _, err := c.CheckAll(ctx, "u", nil, "/a"); return err }(),
		"grant none":   c.Grant(ctx, GrantRequest{Principal: "u", Resource: "/a"}),
		"bad group":    func() error { _, err := c.Groups().Create(ctx, "Bad Name", ""); return err }(),
		"nested group": func() error { _, err := c.Groups().AddMembers(ctx, "eds", []string{"group:x"}); return err }(),
	} {
		if !errors.Is(err, ErrValidation) {
			t.Errorf("%s: %v, want a validation error", name, err)
		}
	}
	if n := s.count(mCheck); n != 0 {
		t.Fatalf("invalid input reached the server %d times", n)
	}

	_, err := c.WithProject("").Check(ctx, "u", "p", "/a")
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("no project: %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := map[codes.Code]Kind{
		codes.Unauthenticated:   KindAuth,
		codes.PermissionDenied:  KindPermission,
		codes.InvalidArgument:   KindValidation,
		codes.NotFound:          KindNotFound,
		codes.AlreadyExists:     KindAlreadyExists,
		codes.Unavailable:       KindUnavailable,
		codes.DeadlineExceeded:  KindTimeout,
		codes.ResourceExhausted: KindRateLimited,
		codes.Internal:          KindOther,
	}
	for code, kind := range cases {
		t.Run(code.String(), func(t *testing.T) {
			s := &fakeServer{check: func(context.Context, *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
				return nil, status.Error(code, "boom")
			}}
			c := start(t, s, Options{Retry: RetryOptions{MaxRetries: -1}})
			_, err := c.Check(ctx, "u", "p", "/a")
			var pe *Error
			if !errors.As(err, &pe) || pe.Kind != kind || pe.Code != code || !errors.Is(err, kind) {
				t.Fatalf("got %#v, want kind %s", err, kind)
			}
			if status.Code(err) != code {
				t.Fatalf("status.Code = %v", status.Code(err))
			}
		})
	}

	msg := "missing permissions: [{ResourceURI:/organisation/o/project/p/doc MissingPermissions:[permission.check role.get]}]"
	err := toError(status.Error(codes.PermissionDenied, msg), nil)
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatal(err)
	}
	want := []MissingPermission{{Resource: "/organisation/o/project/p/doc", Permissions: []string{"permission.check", "role.get"}}}
	if !reflect.DeepEqual(pe.Missing, want) {
		t.Fatalf("missing = %+v", pe.Missing)
	}
}

func TestRetriesIdempotentReadsOnly(t *testing.T) {
	failures := 2
	s := &fakeServer{
		check: func(context.Context, *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
			if failures > 0 {
				failures--
				return nil, status.Error(codes.Unavailable, "down")
			}
			return &pb.CheckPermissionResponse{Passed: true}, nil
		},
		grant: func(context.Context, *pb.GrantUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error) {
			return nil, status.Error(codes.Unavailable, "down")
		},
	}
	c := start(t, s, Options{})
	if ok, err := c.Check(ctx, "u", "p", "/a"); !ok || err != nil {
		t.Fatalf("Check = %v, %v", ok, err)
	}
	if n := s.count(mCheck); n != 3 {
		t.Fatalf("Check attempts = %d, want 3", n)
	}

	err := c.Grant(ctx, GrantRequest{Principal: "u", Resource: "/a", Permissions: []string{"p"}})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Grant = %v", err)
	}
	if n := s.count(mGrant); n != 1 {
		t.Fatalf("Grant attempts = %d, want 1 (writes are never retried)", n)
	}

	// Retries give up after MaxRetries.
	failures = 10
	if _, err := c.Check(ctx, "u", "p", "/a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Check = %v", err)
	}
	if n := s.count(mCheck); n != 3+3 {
		t.Fatalf("Check attempts = %d, want 6", n)
	}

	// Non-retryable codes are not retried.
	s.check = func(context.Context, *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
		return nil, status.Error(codes.InvalidArgument, "bad")
	}
	_, _ = c.Check(ctx, "u", "p", "/a")
	if n := s.count(mCheck); n != 7 {
		t.Fatalf("Check attempts = %d, want 7", n)
	}

	if !IsIdempotent(mWhoAmI) || !IsIdempotent(mBatch) || IsIdempotent(mGrant) || IsIdempotent(mRevoke) {
		t.Fatal("allowlist")
	}
}

func TestRetriesDisabled(t *testing.T) {
	s := &fakeServer{check: func(context.Context, *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
		return nil, status.Error(codes.Unavailable, "down")
	}}
	c := start(t, s, Options{Retry: RetryOptions{MaxRetries: -1}})
	_, _ = c.Check(ctx, "u", "p", "/a")
	if n := s.count(mCheck); n != 1 {
		t.Fatalf("attempts = %d", n)
	}
}

func TestPerAttemptTimeout(t *testing.T) {
	s := &fakeServer{check: func(ctx context.Context, _ *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			// The propagated deadline can fire here before the client's own
			// timer; answering success would race the client-side timeout.
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		return &pb.CheckPermissionResponse{Passed: true}, nil
	}}
	c := start(t, s, Options{Timeout: 30 * time.Millisecond, Retry: RetryOptions{MaxRetries: 1}})
	began := time.Now()
	_, err := c.Check(ctx, "u", "p", "/a")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	if n := s.count(mCheck); n != 2 {
		t.Fatalf("attempts = %d, want 2 (timeouts are retried for reads)", n)
	}
	if time.Since(began) > time.Second {
		t.Fatal("timeout not applied")
	}

	// The caller's own deadline ends the call without further retries.
	c = start(t, s, Options{Timeout: -1})
	dctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, err := c.Check(dctx, "u", "p", "/a"); !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if n := s.count(mCheck); n != 1 {
		t.Fatalf("attempts = %d, want 1", n)
	}
}

func rateLimited(delay time.Duration) error {
	st := status.New(codes.ResourceExhausted, "check rate limit of 25 per second exceeded")
	if delay > 0 {
		st, _ = st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(delay)})
	}
	return st.Err()
}

func TestRateLimit(t *testing.T) {
	var at []time.Time
	s := &fakeServer{check: func(context.Context, *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
		at = append(at, time.Now())
		if len(at) == 1 {
			return nil, rateLimited(60 * time.Millisecond)
		}
		return &pb.CheckPermissionResponse{Passed: true}, nil
	}}
	c := start(t, s, Options{Retry: RetryOptions{MaxDelay: time.Second}})
	if ok, err := c.Check(ctx, "u", "p", "/a"); !ok || err != nil {
		t.Fatalf("Check = %v, %v", ok, err)
	}
	if len(at) != 2 || at[1].Sub(at[0]) < 55*time.Millisecond {
		t.Fatalf("retry did not wait for RetryInfo: %v", at)
	}

	t.Run("retry-after header", func(t *testing.T) {
		var at []time.Time
		s := &fakeServer{check: func(ctx context.Context, _ *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
			at = append(at, time.Now())
			if len(at) == 1 {
				_ = grpc.SetHeader(ctx, metadata.Pairs("retry-after", "1"))
				return nil, rateLimited(0)
			}
			return &pb.CheckPermissionResponse{Passed: true}, nil
		}}
		c := start(t, s, Options{Retry: RetryOptions{MaxDelay: 2 * time.Second}})
		if ok, err := c.Check(ctx, "u", "p", "/a"); !ok || err != nil {
			t.Fatalf("Check = %v, %v", ok, err)
		}
		if len(at) != 2 || at[1].Sub(at[0]) < 950*time.Millisecond {
			t.Fatalf("retry did not wait for retry-after: %v", at)
		}
	})

	t.Run("delay above MaxDelay fails fast", func(t *testing.T) {
		s := &fakeServer{check: func(context.Context, *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
			return nil, rateLimited(900 * time.Millisecond)
		}}
		c := start(t, s, Options{Retry: RetryOptions{MaxDelay: 100 * time.Millisecond}})
		_, err := c.Check(ctx, "u", "p", "/a")
		var pe *Error
		if !errors.As(err, &pe) || pe.Kind != KindRateLimited || pe.RetryAfter != 900*time.Millisecond {
			t.Fatalf("err = %#v", err)
		}
		if n := s.count(mCheck); n != 1 {
			t.Fatalf("attempts = %d", n)
		}
	})

	t.Run("no server delay: not retried", func(t *testing.T) {
		s := &fakeServer{check: func(context.Context, *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
			return nil, rateLimited(0)
		}}
		c := start(t, s, Options{})
		_, err := c.Check(ctx, "u", "p", "/a")
		var pe *Error
		if !errors.As(err, &pe) || pe.Kind != KindRateLimited || pe.RetryAfter != 0 {
			t.Fatalf("err = %#v", err)
		}
		if n := s.count(mCheck); n != 1 {
			t.Fatalf("attempts = %d", n)
		}
	})
}

func TestBatchCheck(t *testing.T) {
	var mu sync.Mutex
	var calls [][]string
	s := &fakeServer{batchCheck: func(_ context.Context, r *pb.BatchCheckRequest) (*pb.BatchCheckResponse, error) {
		mu.Lock()
		calls = append(calls, r.GetResourceUris())
		mu.Unlock()
		res := &pb.BatchCheckResponse{}
		// Answer in reverse order: the SDK must return request order.
		for i := len(r.GetResourceUris()) - 1; i >= 0; i-- {
			uri := r.GetResourceUris()[i]
			n, _ := strconv.Atoi(uri[len("/docs/"):])
			if n%2 == 0 {
				res.Results = append(res.Results, &pb.BatchCheckResult{ResourceUri: uri, Allowed: true})
			} else {
				res.Results = append(res.Results, &pb.BatchCheckResult{ResourceUri: uri, MissingPermissions: []string{"docs.read"}})
			}
		}
		return res, nil
	}}
	c := start(t, s, Options{})
	var resources []string
	for i := range 150 {
		resources = append(resources, fmt.Sprintf("/docs/%d", i))
	}
	resources = append(resources, "/docs/0") // duplicates are dropped
	got, err := c.BatchCheckDetailed(ctx, "u", []string{"docs.read"}, resources)
	if err != nil {
		t.Fatal(err)
	}
	// The two chunks run concurrently, so they may arrive in either order.
	if len(calls) != 2 || len(calls[0])+len(calls[1]) != 150 || max(len(calls[0]), len(calls[1])) != 100 {
		t.Fatalf("chunks = %d", len(calls))
	}
	if len(got) != 150 || got[0].Resource != "/docs/0" || !got[0].Allowed || got[1].Allowed || !reflect.DeepEqual(got[1].Missing, []string{"docs.read"}) {
		t.Fatalf("results = %+v", got[:2])
	}
	m, err := c.BatchCheck(ctx, "u", []string{"docs.read"}, []string{"/docs/2", "/docs/3"})
	if err != nil || !m["/docs/2"] || m["/docs/3"] {
		t.Fatalf("BatchCheck = %v, %v", m, err)
	}

	// A response missing a requested resource fails closed.
	s.batchCheck = func(context.Context, *pb.BatchCheckRequest) (*pb.BatchCheckResponse, error) {
		return &pb.BatchCheckResponse{Results: []*pb.BatchCheckResult{{ResourceUri: "/other", Allowed: true}}}, nil
	}
	if _, err := c.BatchCheck(ctx, "u", []string{"docs.read"}, []string{"/docs/1"}); err == nil {
		t.Fatal("expected an inconsistent-response error")
	}
}

func TestPagination(t *testing.T) {
	var limits []int32
	s := &fakeServer{listPermissions: func(_ context.Context, r *pb.ListPermissionsRequest) (*pb.ListPermissionsResponse, error) {
		limits = append(limits, r.GetPagination().GetLimit())
		page := 0
		if r.GetPagination().Cursor != nil {
			page, _ = strconv.Atoi(r.GetPagination().GetCursor())
		}
		res := &pb.ListPermissionsResponse{Pagination: &paginationv1.PaginationResponse{}}
		for i := range 2 {
			res.Permissions = append(res.Permissions, &pb.Permission{Name: fmt.Sprintf("p%d.%d", page, i)})
		}
		if page < 2 {
			res.Pagination.NextCursor = strconv.Itoa(page + 1)
		}
		return res, nil
	}}
	c := start(t, s, Options{})
	all, err := Collect(c.ListPermissions(ctx, &ListOptions{PageSize: 2}))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 6 || all[5].Name != "p2.1" || !reflect.DeepEqual(limits, []int32{2, 2, 2}) {
		t.Fatalf("got %v, limits %v", all, limits)
	}

	// Breaking early stops fetching.
	limits = nil
	for p, err := range c.ListPermissions(ctx, nil) {
		if err != nil || p.Name != "p0.0" {
			t.Fatal(p, err)
		}
		break
	}
	if !reflect.DeepEqual(limits, []int32{100}) {
		t.Fatalf("pages fetched: %v", limits)
	}

	// A repeated cursor is an error, not a quiet end of a partial listing (and
	// does not loop).
	s.listPermissions = func(context.Context, *pb.ListPermissionsRequest) (*pb.ListPermissionsResponse, error) {
		return &pb.ListPermissionsResponse{Permissions: []*pb.Permission{{Name: "x"}}, Pagination: &paginationv1.PaginationResponse{NextCursor: "same"}}, nil
	}
	if all, err := Collect(c.ListPermissions(ctx, nil)); err == nil || KindOf(err) != KindOther || len(all) != 2 {
		t.Fatalf("repeated cursor: %d items, %v; want an error after 2 items", len(all), err)
	}

	// An error is yielded once and ends the iteration.
	s.listPermissions = func(context.Context, *pb.ListPermissionsRequest) (*pb.ListPermissionsResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "no")
	}
	n := 0
	for _, err := range c.ListPermissions(ctx, nil) {
		n++
		if !errors.Is(err, ErrPermission) {
			t.Fatalf("err = %v", err)
		}
	}
	if n != 1 {
		t.Fatalf("yields = %d", n)
	}
}

func TestGrantRevoke(t *testing.T) {
	var grants []*pb.GrantUserPermissionsAndRolesOnResourceRequest
	var revokes []*pb.RevokeUserPermissionsAndRolesOnResourceRequest
	s := &fakeServer{
		grant: func(_ context.Context, r *pb.GrantUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error) {
			grants = append(grants, r)
			return &emptypb.Empty{}, nil
		},
		revoke: func(_ context.Context, r *pb.RevokeUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error) {
			revokes = append(revokes, r)
			return &emptypb.Empty{}, nil
		},
	}
	c := start(t, s, Options{})
	req := GrantRequest{Principal: GroupPrincipal("eds"), Resource: MustResource("docs", "42"), Permissions: []string{"a", "b", "a"}, Roles: []string{"r1"}}
	if err := c.Grant(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(ctx, req); err != nil {
		t.Fatal(err)
	}
	g := grants[0]
	if g.GetProjectName() != "proj" || g.GetUserId() != "group:eds" || g.GetResourceUri() != "/docs/42" ||
		!reflect.DeepEqual(g.GetPermissions(), []string{"a", "b"}) || !reflect.DeepEqual(g.GetRoles(), []string{"r1"}) {
		t.Fatalf("grant = %v", g)
	}
	if len(revokes) != 1 || revokes[0].GetUserId() != "group:eds" {
		t.Fatalf("revokes = %v", revokes)
	}
}

func TestWhoAmI(t *testing.T) {
	s := &fakeServer{whoAmI: func(context.Context, *pb.WhoAmIRequest) (*pb.WhoAmIResponse, error) {
		return &pb.WhoAmIResponse{PrincipalId: "key1", OrganisationId: "org", PrincipalType: pb.PrincipalType_PRINCIPAL_TYPE_API_KEY,
			ProjectName: "default", ApiKeyAccess: pb.APIKeyAccess_API_KEY_ACCESS_FULL}, nil
	}}
	c := start(t, s, Options{})
	me, err := c.WithProject("").WhoAmI(ctx) // needs no project
	if err != nil {
		t.Fatal(err)
	}
	want := &Identity{PrincipalID: "key1", OrganisationID: "org", Kind: PrincipalAPIKey, Project: "default", APIKeyAccess: APIKeyAccessFull}
	if !reflect.DeepEqual(me, want) {
		t.Fatalf("got %+v", me)
	}
}

func TestGroups(t *testing.T) {
	var added [][]string
	s := &fakeServer{
		createGroup: func(_ context.Context, r *pb.CreateGroupRequest) (*pb.Group, error) {
			return &pb.Group{Name: r.GetName(), Description: r.GetDescription()}, nil
		},
		addGroupMembers: func(_ context.Context, r *pb.AddGroupMembersRequest) (*pb.AddGroupMembersResponse, error) {
			added = append(added, r.GetPrincipalIds())
			return &pb.AddGroupMembersResponse{AddedPrincipalIds: r.GetPrincipalIds()}, nil
		},
		listGroupMembers: func(_ context.Context, r *pb.ListGroupMembersRequest) (*pb.ListGroupMembersResponse, error) {
			return &pb.ListGroupMembersResponse{Members: []*pb.GroupMember{{PrincipalId: "bob"}}}, nil
		},
	}
	c := start(t, s, Options{})
	g, err := c.Groups().Create(ctx, "group:editors", "Editors")
	if err != nil || g.Name != "editors" || g.PrincipalID != "group:editors" {
		t.Fatalf("Create = %+v, %v", g, err)
	}
	var many []string
	for i := range 120 {
		many = append(many, fmt.Sprintf("u%d", i))
	}
	// More than 100 principals is rejected before any write, so a failure
	// cannot leave the group half changed.
	if _, err := c.Groups().AddMembers(ctx, "editors", many); !errors.Is(err, ErrValidation) {
		t.Fatalf("AddMembers(120) = %v, want a validation error", err)
	}
	if _, err := c.Groups().RemoveMembers(ctx, "editors", many); !errors.Is(err, ErrValidation) {
		t.Fatalf("RemoveMembers(120) = %v, want a validation error", err)
	}
	if len(added) != 0 {
		t.Fatalf("%d writes reached the server", len(added))
	}
	// Duplicates are dropped before counting.
	res, err := c.Groups().AddMembers(ctx, "editors", append(many[:100:100], many[:20]...))
	if err != nil || len(res.Changed) != 100 || len(added) != 1 {
		t.Fatalf("AddMembers = %v, %v (%d calls)", res, err, len(added))
	}
	members, err := Collect(c.Groups().ListMembers(ctx, "editors", nil))
	if err != nil || len(members) != 1 || members[0].PrincipalID != "bob" {
		t.Fatalf("ListMembers = %+v, %v", members, err)
	}
}

func TestListAccessAndWhoHasAccess(t *testing.T) {
	s := &fakeServer{
		listAccess: func(_ context.Context, r *pb.ListAccessRequest) (*pb.ListAccessResponse, error) {
			if r.GetPagination().Cursor == nil {
				return &pb.ListAccessResponse{Scopes: []*pb.AccessScope{{Uri: "/docs/1", Scope: pb.AccessScopeKind_ACCESS_SCOPE_KIND_SUBTREE}},
					Pagination: &paginationv1.PaginationResponse{NextCursor: "2"}}, nil
			}
			return &pb.ListAccessResponse{Scopes: []*pb.AccessScope{{Uri: "/docs/_/public", Scope: pb.AccessScopeKind_ACCESS_SCOPE_KIND_PATTERN}}}, nil
		},
		whoHasAccess: func(_ context.Context, r *pb.ListPrincipalsWithAccessRequest) (*pb.ListPrincipalsWithAccessResponse, error) {
			if r.GetPermission() != "docs.read" || !r.GetExpandGroups() {
				return nil, status.Error(codes.InvalidArgument, "unexpected request")
			}
			return &pb.ListPrincipalsWithAccessResponse{Principals: []*pb.PrincipalAccess{
				{PrincipalId: "zed", Via: []*pb.AccessGrant{{ResourceUri: "/docs", Inherited: true, Match: pb.AccessGrantMatch_ACCESS_GRANT_MATCH_ANCESTOR, Source: &pb.AccessGrant_Direct{Direct: &pb.AccessGrantDirect{}}}}},
				{PrincipalId: "alice", Via: []*pb.AccessGrant{{ResourceUri: "/docs/1", Match: pb.AccessGrantMatch_ACCESS_GRANT_MATCH_EXACT, Source: &pb.AccessGrant_Role{Role: &pb.AccessGrantRole{Id: "r1", Name: "Reader"}}}}},
			}}, nil
		},
	}
	c := start(t, s, Options{})
	a, err := c.ListAccess(ctx, "alice", "docs.read", "/docs")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Scopes) != 2 || !a.Allows("/docs/1/x") || !a.Allows("/docs/9/public") || a.Allows("/docs/9") || !a.HasPatterns() {
		t.Fatalf("scopes = %+v", a)
	}
	entries, err := c.WhoHasAccess(ctx, "/docs/1", &WhoHasAccessOptions{Permission: "docs.read", ExpandGroups: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Principal != "alice" || entries[0].Via[0].Source != "role" || entries[0].Via[0].RoleName != "Reader" ||
		entries[1].Via[0].Source != "direct" || entries[1].Via[0].Match != "ancestor" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestCreatePermissionErrorsMapDirectly(t *testing.T) {
	gets := 0
	code := codes.AlreadyExists
	s := &fakeServer{
		createPermission: func(context.Context, *pb.CreatePermissionRequest) (*pb.Permission, error) {
			return nil, status.Error(code, "a permission named \"docs.read\" already exists")
		},
		getPermission: func(_ context.Context, r *pb.GetPermissionRequest) (*pb.Permission, error) {
			gets++
			return &pb.Permission{Name: r.GetName()}, nil
		},
		deletePermission: func(context.Context, *pb.DeletePermissionRequest) (*emptypb.Empty, error) {
			return nil, status.Error(codes.Internal, "failed to delete permission")
		},
	}
	c := start(t, s, Options{})
	if _, err := c.CreatePermission(ctx, "docs.read", "new"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("err = %v", err)
	}
	code = codes.Internal
	if _, err := c.CreatePermission(ctx, "docs.read", "new"); KindOf(err) != KindOther || status.Code(err) != codes.Internal {
		t.Fatalf("err = %v", err)
	}
	if err := c.DeletePermission(ctx, "docs.read"); status.Code(err) != codes.Internal {
		t.Fatalf("delete err = %v", err)
	}
	if gets != 0 {
		t.Fatalf("made %d extra GetPermission calls", gets)
	}
}

func TestSDKErrorsNeverReportOK(t *testing.T) {
	c := start(t, &fakeServer{}, Options{})
	_, cfgErr := c.WithProject("").Check(ctx, "u", "p", "/a")
	denied := deniedError("alice", []MissingPermission{{Resource: "/a", Permissions: []string{"p"}}})
	for _, tc := range []struct {
		err  error
		kind Kind
		code codes.Code
	}{
		{cfgErr, KindConfig, codes.FailedPrecondition},
		{denied, KindDenied, codes.PermissionDenied},
		{invalid("bad"), KindValidation, codes.InvalidArgument},
		{&Error{Kind: KindOther, Message: "zero code"}, KindOther, codes.Unknown},
	} {
		if !errors.Is(tc.err, tc.kind) {
			t.Errorf("%v: kind = %s, want %s", tc.err, KindOf(tc.err), tc.kind)
		}
		st, ok := status.FromError(tc.err)
		if !ok || st.Code() != tc.code || status.Code(tc.err) == codes.OK {
			t.Errorf("%v: status code = %v, want %v", tc.err, st.Code(), tc.code)
		}
	}
	// Denied stays distinct from the API's own PermissionDenied (KindPermission).
	if errors.Is(denied, ErrPermission) {
		t.Error("a denied check matched ErrPermission")
	}
}

func TestCancelDuringRetryBackoff(t *testing.T) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := &fakeServer{check: func(context.Context, *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
		// Cancel shortly after the first failure, while the client is waiting
		// out its (long) backoff.
		time.AfterFunc(20*time.Millisecond, cancel)
		return nil, status.Error(codes.Unavailable, "down")
	}}
	c := start(t, s, Options{Retry: RetryOptions{MaxRetries: 3, BaseDelay: 10 * time.Second, MaxDelay: 10 * time.Second}})
	began := time.Now()
	_, err := c.Check(cctx, "u", "p", "/a")
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("Check took %s; the backoff ignored cancellation", took)
	}
	if !errors.Is(err, context.Canceled) || status.Code(err) != codes.Canceled {
		t.Fatalf("err = %v, want a cancellation error", err)
	}
	if n := s.count(mCheck); n != 1 {
		t.Fatalf("attempts = %d, want 1", n)
	}
}

func TestListAccessAndWhoHasAccessFollowEveryPage(t *testing.T) {
	var accessCursors, whoCursors []string
	cursorOf := func(p *paginationv1.PaginationRequest) string {
		if p.Cursor == nil {
			return "<first>"
		}
		return p.GetCursor()
	}
	s := &fakeServer{
		listAccess: func(_ context.Context, r *pb.ListAccessRequest) (*pb.ListAccessResponse, error) {
			cur := cursorOf(r.GetPagination())
			accessCursors = append(accessCursors, cur)
			switch cur {
			case "<first>":
				return &pb.ListAccessResponse{Scopes: []*pb.AccessScope{{Uri: "/docs/1", Scope: pb.AccessScopeKind_ACCESS_SCOPE_KIND_SUBTREE}},
					Pagination: &paginationv1.PaginationResponse{NextCursor: "c2"}}, nil
			case "c2":
				return &pb.ListAccessResponse{Scopes: []*pb.AccessScope{{Uri: "/docs/2", Scope: pb.AccessScopeKind_ACCESS_SCOPE_KIND_EXACT}},
					Pagination: &paginationv1.PaginationResponse{NextCursor: "c3"}}, nil
			default:
				return &pb.ListAccessResponse{Scopes: []*pb.AccessScope{{Uri: "/docs/_/public", Scope: pb.AccessScopeKind_ACCESS_SCOPE_KIND_PATTERN}},
					Pagination: &paginationv1.PaginationResponse{}}, nil
			}
		},
		whoHasAccess: func(_ context.Context, r *pb.ListPrincipalsWithAccessRequest) (*pb.ListPrincipalsWithAccessResponse, error) {
			cur := cursorOf(r.GetPagination())
			whoCursors = append(whoCursors, cur)
			direct := func(id string) *pb.PrincipalAccess {
				return &pb.PrincipalAccess{PrincipalId: id, Via: []*pb.AccessGrant{{ResourceUri: "/docs", Inherited: true,
					Match: pb.AccessGrantMatch_ACCESS_GRANT_MATCH_ANCESTOR, Source: &pb.AccessGrant_Direct{Direct: &pb.AccessGrantDirect{}}}}}
			}
			switch cur {
			case "<first>":
				return &pb.ListPrincipalsWithAccessResponse{Principals: []*pb.PrincipalAccess{direct("a"), direct("b")},
					Pagination: &paginationv1.PaginationResponse{NextCursor: "p2"}}, nil
			case "p2":
				return &pb.ListPrincipalsWithAccessResponse{Principals: []*pb.PrincipalAccess{direct("c")},
					Pagination: &paginationv1.PaginationResponse{NextCursor: "p3"}}, nil
			default:
				return &pb.ListPrincipalsWithAccessResponse{Principals: []*pb.PrincipalAccess{direct("d")}}, nil
			}
		},
	}
	c := start(t, s, Options{})
	a, err := c.ListAccess(ctx, "alice", "docs.read", "/docs")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(accessCursors, []string{"<first>", "c2", "c3"}) {
		t.Fatalf("ListAccess cursors = %v", accessCursors)
	}
	if len(a.Scopes) != 3 || !a.Allows("/docs/1/x") || !a.Allows("/docs/2") || a.Allows("/docs/2/x") || !a.Allows("/docs/7/public") {
		t.Fatalf("scopes = %+v", a.Scopes)
	}
	entries, err := c.WhoHasAccess(ctx, "/docs/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(whoCursors, []string{"<first>", "p2", "p3"}) {
		t.Fatalf("WhoHasAccess cursors = %v", whoCursors)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Principal)
	}
	if !reflect.DeepEqual(got, []string{"a", "b", "c", "d"}) {
		t.Fatalf("principals = %v", got)
	}

	// A failing later page fails the whole call rather than returning a
	// partial answer.
	s.whoHasAccess = func(_ context.Context, r *pb.ListPrincipalsWithAccessRequest) (*pb.ListPrincipalsWithAccessResponse, error) {
		if r.GetPagination().Cursor == nil {
			return &pb.ListPrincipalsWithAccessResponse{Principals: []*pb.PrincipalAccess{{PrincipalId: "a"}},
				Pagination: &paginationv1.PaginationResponse{NextCursor: "p2"}}, nil
		}
		return nil, status.Error(codes.PermissionDenied, "no")
	}
	if entries, err := c.WhoHasAccess(ctx, "/docs/1", nil); !errors.Is(err, ErrPermission) || entries != nil {
		t.Fatalf("WhoHasAccess = %v, %v", entries, err)
	}
}
