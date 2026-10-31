package permio

import (
	"context"
	"iter"

	paginationv1 "github.com/perms-io/permio-go/proto/pagination/v1"
	"google.golang.org/protobuf/proto"
)

// MaxPageSize is the largest page the API accepts (PaginationRequest.limit is 1..100).
const MaxPageSize = 100

// MaxBatch is the most resources or permissions one Check or BatchCheck call
// accepts, and the most principals [Groups.AddMembers] and
// [Groups.RemoveMembers] accept.
const MaxBatch = 100

// ListOptions configures a paginated listing.
type ListOptions struct {
	// Search filters by name, where the listing supports it.
	Search string
	// PageSize is the number of items per request, 1..100. Default 100.
	PageSize int
}

func (o *ListOptions) search() string {
	if o == nil {
		return ""
	}
	return o.Search
}

func (o *ListOptions) pageSize() int32 {
	if o == nil || o.PageSize <= 0 || o.PageSize > MaxPageSize {
		return MaxPageSize
	}
	return int32(o.PageSize)
}

// paginate iterates every item of a list RPC, following next_cursor until the
// API returns an empty one. A failing page yields the error once and ends the
// iteration. A cursor the API already returned would loop forever, so it
// yields an error rather than ending quietly with a partial listing.
//
// Each page request is marked as a list page, so it runs under the client's
// ListTimeout rather than its Timeout.
func paginate[T any](ctx context.Context, pageSize int32, fetch func(ctx context.Context, p *paginationv1.PaginationRequest) ([]T, string, error)) iter.Seq2[T, error] {
	return paginateLimit(ctx, pageSize, 0, fetch)
}

// paginateLimit is paginate yielding at most limit items (0 = no limit). Page
// requests ask for no more than the items still wanted, so at most limit items
// are ever fetched.
func paginateLimit[T any](ctx context.Context, pageSize int32, limit int, fetch func(ctx context.Context, p *paginationv1.PaginationRequest) ([]T, string, error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		var zero T
		var cursor *string
		seen := map[string]bool{}
		yielded := 0
		ctx := context.WithValue(ctx, listPageKey{}, true)
		for {
			if err := ctx.Err(); err != nil {
				yield(zero, toError(err, nil))
				return
			}
			size := pageSize
			if limit > 0 && int64(limit-yielded) < int64(size) {
				size = int32(limit - yielded)
			}
			items, next, err := fetch(ctx, &paginationv1.PaginationRequest{Limit: proto.Int32(size), Cursor: cursor})
			if err != nil {
				yield(zero, err)
				return
			}
			for _, it := range items {
				if !yield(it, nil) {
					return
				}
				yielded++
				if limit > 0 && yielded >= limit {
					return
				}
			}
			if next == "" {
				return
			}
			if seen[next] {
				yield(zero, inconsistent("the pagination cursor %q was returned twice; the listing is incomplete", next))
				return
			}
			seen[next] = true
			cursor = proto.String(next)
		}
	}
}

// listPageKey marks a context as fetching one page of a listing.
type listPageKey struct{}

func isListPage(ctx context.Context) bool {
	v, _ := ctx.Value(listPageKey{}).(bool)
	return v
}

// DefaultMaxResults is the default cap on the results [Client.WhoHasAccess]
// and [Client.ListAccess] collect into memory.
const DefaultMaxResults = 10_000

// maxResults resolves a MaxResults option: 0 means [DefaultMaxResults].
func maxResults(n int) (int, error) {
	switch {
	case n == 0:
		return DefaultMaxResults, nil
	case n < 0:
		return 0, invalid("MaxResults must not be negative")
	}
	return n, nil
}

// failed is an iterator that yields one error.
func failed[T any](err error) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		var zero T
		yield(zero, err)
	}
}

// Collect gathers every item of a listing into a slice, stopping at the first
// error:
//
//	roles, err := permio.Collect(client.ListRoles(ctx, nil))
func Collect[T any](seq iter.Seq2[T, error]) ([]T, error) {
	out := []T{}
	for v, err := range seq {
		if err != nil {
			return out, err
		}
		out = append(out, v)
	}
	return out, nil
}
