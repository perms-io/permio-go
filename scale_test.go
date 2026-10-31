package permio

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	paginationv1 "github.com/perms-io/permio-go/proto/pagination/v1"
	pb "github.com/perms-io/permio-go/proto/permissions/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// principalsServer serves total principals with access, in pages of the
// requested size, and records every requested page limit.
func principalsServer(total int) (*fakeServer, *[]int32, *sync.Mutex) {
	var mu sync.Mutex
	var limits []int32
	s := &fakeServer{whoHasAccess: func(_ context.Context, r *pb.ListPrincipalsWithAccessRequest) (*pb.ListPrincipalsWithAccessResponse, error) {
		start := 0
		if c := r.GetPagination().GetCursor(); c != "" {
			fmt.Sscanf(c, "%d", &start)
		}
		limit := int(r.GetPagination().GetLimit())
		mu.Lock()
		limits = append(limits, int32(limit))
		mu.Unlock()
		res := &pb.ListPrincipalsWithAccessResponse{Pagination: &paginationv1.PaginationResponse{}}
		end := min(total, start+limit)
		for i := start; i < end; i++ {
			res.Principals = append(res.Principals, &pb.PrincipalAccess{PrincipalId: fmt.Sprintf("user-%06d", i)})
		}
		if end < total {
			res.Pagination.NextCursor = fmt.Sprint(end)
		}
		return res, nil
	}}
	return s, &limits, &mu
}

func TestWhoHasAccessSeqStreamsEveryPage(t *testing.T) {
	s, limits, _ := principalsServer(25_000)
	c := start(t, s, Options{})
	n := 0
	for e, err := range c.WhoHasAccessSeq(ctx, "/docs/1", nil) {
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("user-%06d", n); e.Principal != want {
			t.Fatalf("entry %d = %q, want %q", n, e.Principal, want)
		}
		n++
	}
	if n != 25_000 || len(*limits) != 250 {
		t.Fatalf("streamed %d entries in %d pages", n, len(*limits))
	}

	// Breaking out of the loop stops fetching.
	*limits = nil
	n = 0
	for _, err := range c.WhoHasAccessSeq(ctx, "/docs/1", nil) {
		if err != nil {
			t.Fatal(err)
		}
		if n++; n == 150 {
			break
		}
	}
	if len(*limits) != 2 {
		t.Fatalf("pages after break = %d", len(*limits))
	}
}

func TestWhoHasAccessCapStopsAtCapPlusOne(t *testing.T) {
	s, limits, _ := principalsServer(1_000_000)
	c := start(t, s, Options{})
	_, err := c.WhoHasAccess(ctx, "/docs/1", &WhoHasAccessOptions{MaxResults: 250})
	var pe *Error
	if !errors.Is(err, ErrTooManyResults) || !errors.As(err, &pe) || pe.MaxResults != 250 {
		t.Fatalf("err = %v", err)
	}
	fetched := int32(0)
	for _, l := range *limits {
		fetched += l
	}
	if fetched != 251 || fmt.Sprint(*limits) != "[100 100 51]" {
		t.Fatalf("page limits = %v", *limits)
	}

	// The default cap is 10,000.
	*limits = nil
	if _, err := c.WhoHasAccess(ctx, "/docs/1", nil); !errors.Is(err, ErrTooManyResults) {
		t.Fatalf("err = %v", err)
	}
	if len(*limits) != 101 || (*limits)[100] != 1 {
		t.Fatalf("pages = %d, last = %d", len(*limits), (*limits)[len(*limits)-1])
	}

	// Exactly the cap is fine.
	s2, _, _ := principalsServer(250)
	c2 := start(t, s2, Options{})
	got, err := c2.WhoHasAccess(ctx, "/docs/1", &WhoHasAccessOptions{MaxResults: 250})
	if err != nil || len(got) != 250 {
		t.Fatalf("WhoHasAccess = %d, %v", len(got), err)
	}
	if _, err := c2.WhoHasAccess(ctx, "/docs/1", &WhoHasAccessOptions{MaxResults: -1}); !errors.Is(err, ErrValidation) {
		t.Fatalf("negative cap: %v", err)
	}
}

func TestListAccessSeqAndCap(t *testing.T) {
	var limits []int32
	s := &fakeServer{listAccess: func(_ context.Context, r *pb.ListAccessRequest) (*pb.ListAccessResponse, error) {
		if r.GetPrincipalId() == "admin" {
			return &pb.ListAccessResponse{CoversAll: true, Scopes: []*pb.AccessScope{{Uri: r.GetUnderUri(), Scope: pb.AccessScopeKind_ACCESS_SCOPE_KIND_SUBTREE}}}, nil
		}
		start := 0
		if c := r.GetPagination().GetCursor(); c != "" {
			fmt.Sscanf(c, "%d", &start)
		}
		limits = append(limits, r.GetPagination().GetLimit())
		res := &pb.ListAccessResponse{Pagination: &paginationv1.PaginationResponse{}}
		end := min(1000, start+int(r.GetPagination().GetLimit()))
		for i := start; i < end; i++ {
			res.Scopes = append(res.Scopes, &pb.AccessScope{Uri: fmt.Sprintf("/docs/%d", i), Scope: pb.AccessScopeKind_ACCESS_SCOPE_KIND_SUBTREE})
		}
		if end < 1000 {
			res.Pagination.NextCursor = fmt.Sprint(end)
		}
		return res, nil
	}}
	c := start(t, s, Options{})
	n := 0
	for sc, err := range c.ListAccessSeq(ctx, "alice", "docs.read", "/docs") {
		if err != nil || sc.URI != fmt.Sprintf("/docs/%d", n) || sc.Kind != ScopeSubtree {
			t.Fatalf("scope %d = %+v, %v", n, sc, err)
		}
		n++
	}
	if n != 1000 || len(limits) != 10 {
		t.Fatalf("streamed %d scopes in %d pages", n, len(limits))
	}

	limits = nil
	_, err := c.ListAccess(ctx, "alice", "docs.read", "/docs", ListAccessOptions{MaxResults: 150})
	if !errors.Is(err, ErrTooManyResults) || fmt.Sprint(limits) != "[100 51]" {
		t.Fatalf("err = %v, limits = %v", err, limits)
	}
	a, err := c.ListAccess(ctx, "alice", "docs.read", "/docs")
	if err != nil || len(a.Scopes) != 1000 || a.CoversAll {
		t.Fatalf("ListAccess = %d scopes, %v", len(a.Scopes), err)
	}

	// Covers-all: the stream yields the one SUBTREE scope for under.
	var got []AccessScope
	for sc, err := range c.ListAccessSeq(ctx, "admin", "docs.read", "/docs") {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, sc)
	}
	if len(got) != 1 || got[0] != (AccessScope{URI: "/docs", Kind: ScopeSubtree}) {
		t.Fatalf("covers-all stream = %+v", got)
	}
	if a, err := c.ListAccess(ctx, "admin", "docs.read", "/docs"); err != nil || !a.CoversAll || len(a.Scopes) != 1 {
		t.Fatalf("covers-all ListAccess = %+v, %v", a, err)
	}
}

func TestBatchCheckBound(t *testing.T) {
	s := &fakeServer{batchCheck: func(_ context.Context, r *pb.BatchCheckRequest) (*pb.BatchCheckResponse, error) {
		res := &pb.BatchCheckResponse{}
		for _, uri := range r.GetResourceUris() {
			res.Results = append(res.Results, &pb.BatchCheckResult{ResourceUri: uri, Allowed: true})
		}
		return res, nil
	}}
	c := start(t, s, Options{})
	resources := make([]string, 10_001)
	for i := range resources {
		resources[i] = fmt.Sprintf("/docs/%d", i)
	}
	if _, err := c.BatchCheck(ctx, "u", []string{"docs.read"}, resources); !errors.Is(err, ErrValidation) {
		t.Fatalf("10,001 resources: %v", err)
	}
	if s.count(mBatch) != 0 {
		t.Fatal("sent requests for an oversized batch")
	}
	if got, err := c.BatchCheck(ctx, "u", []string{"docs.read"}, resources[:10_000]); err != nil || len(got) != 10_000 {
		t.Fatalf("10,000 resources: %d, %v", len(got), err)
	}
	// Counted as given, before duplicates are removed.
	dupes := []string{"/docs/1", "/docs/1", "/docs/1"}
	if _, err := c.BatchCheck(ctx, "u", []string{"docs.read"}, dupes, BatchCheckOptions{MaxResources: 2}); !errors.Is(err, ErrValidation) {
		t.Fatalf("MaxResources 2: %v", err)
	}
	if _, err := c.BatchCheck(ctx, "u", []string{"docs.read"}, resources[:20_000/2+1], BatchCheckOptions{MaxResources: 20_000}); err != nil {
		t.Fatalf("raised cap: %v", err)
	}
	if _, err := c.BatchCheck(ctx, "u", []string{"docs.read"}, dupes, BatchCheckOptions{MaxResources: -1}); !errors.Is(err, ErrValidation) {
		t.Fatalf("negative cap: %v", err)
	}
}

func TestBatchCheckConcurrencyAndOrder(t *testing.T) {
	var inFlight, peak atomic.Int32
	s := &fakeServer{batchCheck: func(_ context.Context, r *pb.BatchCheckRequest) (*pb.BatchCheckResponse, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		res := &pb.BatchCheckResponse{}
		for i := len(r.GetResourceUris()) - 1; i >= 0; i-- {
			uri := r.GetResourceUris()[i]
			res.Results = append(res.Results, &pb.BatchCheckResult{ResourceUri: uri, Allowed: len(uri)%2 == 0})
		}
		return res, nil
	}}
	c := start(t, s, Options{})
	resources := make([]string, 2_000)
	for i := range resources {
		resources[i] = fmt.Sprintf("/docs/%d", i)
	}
	got, err := c.BatchCheckDetailed(ctx, "u", []string{"docs.read"}, resources)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range got {
		if r.Resource != resources[i] || r.Allowed != (len(r.Resource)%2 == 0) {
			t.Fatalf("result %d = %+v", i, r)
		}
	}
	if s.count(mBatch) != 20 || peak.Load() != BatchCheckConcurrency {
		t.Fatalf("requests = %d, peak in flight = %d", s.count(mBatch), peak.Load())
	}
}

func TestBatchCheckFirstErrorStopsTheRest(t *testing.T) {
	var sent atomic.Int32
	s := &fakeServer{batchCheck: func(ctx context.Context, r *pb.BatchCheckRequest) (*pb.BatchCheckResponse, error) {
		sent.Add(1)
		if r.GetResourceUris()[0] == "/docs/200" {
			return nil, status.Error(codes.PermissionDenied, "no permission.check")
		}
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		res := &pb.BatchCheckResponse{}
		for _, uri := range r.GetResourceUris() {
			res.Results = append(res.Results, &pb.BatchCheckResult{ResourceUri: uri, Allowed: true})
		}
		return res, nil
	}}
	c := start(t, s, Options{})
	resources := make([]string, 5_000)
	for i := range resources {
		resources[i] = fmt.Sprintf("/docs/%d", i)
	}
	_, err := c.BatchCheck(ctx, "u", []string{"docs.read"}, resources)
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("err = %v", err)
	}
	if n := sent.Load(); n > 2*BatchCheckConcurrency {
		t.Fatalf("sent %d of 50 requests after the first error", n)
	}
}

func TestListTimeoutAppliesToListPages(t *testing.T) {
	slow := func(ctx context.Context) error {
		select {
		case <-time.After(200 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	newServer := func() *fakeServer {
		return &fakeServer{
			check: func(ctx context.Context, _ *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
				if err := slow(ctx); err != nil {
					return nil, err
				}
				return &pb.CheckPermissionResponse{Passed: true}, nil
			},
			whoHasAccess: func(ctx context.Context, _ *pb.ListPrincipalsWithAccessRequest) (*pb.ListPrincipalsWithAccessResponse, error) {
				if err := slow(ctx); err != nil {
					return nil, err
				}
				return &pb.ListPrincipalsWithAccessResponse{}, nil
			},
		}
	}
	// Short list timeout, long check timeout: pages time out, checks don't.
	c := start(t, newServer(), Options{Timeout: 5 * time.Second, ListTimeout: 20 * time.Millisecond, Retry: RetryOptions{MaxRetries: -1}})
	if ok, err := c.Check(ctx, "u", "docs.read", "/docs/1"); err != nil || !ok {
		t.Fatalf("Check = %v, %v", ok, err)
	}
	if _, err := c.WhoHasAccess(ctx, "/docs/1", nil); !errors.Is(err, ErrTimeout) {
		t.Fatalf("WhoHasAccess err = %v", err)
	}
	// The reverse.
	c = start(t, newServer(), Options{Timeout: 20 * time.Millisecond, ListTimeout: 5 * time.Second, Retry: RetryOptions{MaxRetries: -1}})
	if _, err := c.Check(ctx, "u", "docs.read", "/docs/1"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Check err = %v", err)
	}
	if _, err := c.WhoHasAccess(ctx, "/docs/1", nil); err != nil {
		t.Fatalf("WhoHasAccess err = %v", err)
	}
}

func TestListPageDeadlineExceededBacksOff(t *testing.T) {
	var attempts atomic.Int32
	s := &fakeServer{whoHasAccess: func(context.Context, *pb.ListPrincipalsWithAccessRequest) (*pb.ListPrincipalsWithAccessResponse, error) {
		if attempts.Add(1) <= 2 {
			return nil, status.Error(codes.DeadlineExceeded, "slow")
		}
		return &pb.ListPrincipalsWithAccessResponse{Principals: []*pb.PrincipalAccess{{PrincipalId: "a"}}}, nil
	}}
	c := start(t, s, Options{})
	var delays []time.Duration
	c.conn.sleep = func(_ context.Context, d time.Duration) error {
		delays = append(delays, d)
		return nil
	}
	got, err := c.WhoHasAccess(ctx, "/docs/1", nil)
	if err != nil || len(got) != 1 {
		t.Fatalf("WhoHasAccess = %v, %v", got, err)
	}
	if len(delays) != 2 || delays[0] <= 0 || delays[1] <= 0 {
		t.Fatalf("backoff delays = %v", delays)
	}
}
