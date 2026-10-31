package permio

import (
	"context"
	"iter"
	"slices"
	"strings"

	paginationv1 "github.com/perms-io/permio-go/proto/pagination/v1"
	pb "github.com/perms-io/permio-go/proto/permissions/v1"
)

// Groups manages groups of principals; get it with [Client.Groups]. A group is
// referenced as the principal "group:<slug>" (see [GroupPrincipal]): grant to
// it and every member holds the grant. Groups cannot contain groups.
//
// Every method that takes a group accepts its slug ("editors") or its
// principal ID ("group:editors").
type Groups struct{ c *Client }

// Groups returns the group operations, in the client's project.
func (c *Client) Groups() *Groups { return &Groups{c: c} }

func (g *Groups) prep(name string) (project, slug string, err error) {
	if slug, err = groupSlugOf(name); err != nil {
		return "", "", err
	}
	project, err = g.c.projectName()
	return project, slug, err
}

// Create creates a group. It fails with [KindAlreadyExists] if the project
// already has a group with this name.
func (g *Groups) Create(ctx context.Context, name, description string) (*Group, error) {
	project, slug, err := g.prep(name)
	if err != nil {
		return nil, err
	}
	res, err := g.c.permissions.CreateGroup(ctx, &pb.CreateGroupRequest{ProjectName: project, Name: slug, Description: description})
	if err != nil {
		return nil, err
	}
	out := groupFromPB(res)
	return &out, nil
}

// Get returns a group, or an error of kind [KindNotFound].
func (g *Groups) Get(ctx context.Context, name string) (*Group, error) {
	project, slug, err := g.prep(name)
	if err != nil {
		return nil, err
	}
	res, err := g.c.permissions.GetGroup(ctx, &pb.GetGroupRequest{ProjectName: project, Name: slug})
	if err != nil {
		return nil, err
	}
	out := groupFromPB(res)
	return &out, nil
}

// Update replaces a group's description. A group's name cannot be changed.
func (g *Groups) Update(ctx context.Context, name, description string) (*Group, error) {
	project, slug, err := g.prep(name)
	if err != nil {
		return nil, err
	}
	res, err := g.c.permissions.UpdateGroup(ctx, &pb.UpdateGroupRequest{ProjectName: project, Name: slug, Description: description})
	if err != nil {
		return nil, err
	}
	out := groupFromPB(res)
	return &out, nil
}

// Delete deletes a group, its memberships and every grant made to it. It
// succeeds whether or not the group existed.
func (g *Groups) Delete(ctx context.Context, name string) error {
	project, slug, err := g.prep(name)
	if err != nil {
		return err
	}
	_, err = g.c.permissions.DeleteGroup(ctx, &pb.DeleteGroupRequest{ProjectName: project, Name: slug})
	return err
}

// List iterates every group in the project, ordered by name. opts may be nil.
func (g *Groups) List(ctx context.Context, opts *ListOptions) iter.Seq2[Group, error] {
	project, err := g.c.projectName()
	if err != nil {
		return failed[Group](err)
	}
	return paginate(ctx, opts.pageSize(), func(ctx context.Context, p *paginationv1.PaginationRequest) ([]Group, string, error) {
		res, err := g.c.permissions.ListGroups(ctx, &pb.ListGroupsRequest{ProjectName: project, Pagination: p, Search: optString(opts.search())})
		if err != nil {
			return nil, "", err
		}
		out := make([]Group, 0, len(res.GetGroups()))
		for _, x := range res.GetGroups() {
			out = append(out, groupFromPB(x))
		}
		return out, res.GetPagination().GetNextCursor(), nil
	})
}

func memberInputs(principals []string) ([]string, error) {
	principals = uniq(principals)
	if len(principals) == 0 {
		return nil, invalid("at least one principal is required")
	}
	for _, p := range principals {
		if p == "" {
			return nil, invalid("principal IDs must not be empty")
		}
	}
	if len(principals) > MaxBatch {
		// One call per request: splitting into several writes could leave the
		// group half changed when a later write fails.
		return nil, invalid("at most %d principals per call, got %d", MaxBatch, len(principals))
	}
	return principals, nil
}

// AddMembers adds up to [MaxBatch] (100) principals to a group in one write;
// more fail with [KindValidation] (split them yourself). Principals that were
// already members are reported in Unchanged. Group principals ("group:...")
// are rejected, because groups cannot be nested.
func (g *Groups) AddMembers(ctx context.Context, name string, principals []string) (*MembershipChange, error) {
	project, slug, err := g.prep(name)
	if err != nil {
		return nil, err
	}
	principals, err = memberInputs(principals)
	if err != nil {
		return nil, err
	}
	if slices.ContainsFunc(principals, func(p string) bool { return strings.HasPrefix(p, GroupPrefix) }) {
		return nil, invalid("groups cannot contain groups")
	}
	res, err := g.c.permissions.AddGroupMembers(ctx, &pb.AddGroupMembersRequest{ProjectName: project, Name: slug, PrincipalIds: principals})
	if err != nil {
		return nil, err
	}
	return &MembershipChange{
		Changed:   append([]string{}, res.GetAddedPrincipalIds()...),
		Unchanged: append([]string{}, res.GetExistingPrincipalIds()...),
	}, nil
}

// RemoveMembers removes up to [MaxBatch] (100) principals from a group in one
// write; more fail with [KindValidation]. Principals that were not members are
// reported in Unchanged.
func (g *Groups) RemoveMembers(ctx context.Context, name string, principals []string) (*MembershipChange, error) {
	project, slug, err := g.prep(name)
	if err != nil {
		return nil, err
	}
	principals, err = memberInputs(principals)
	if err != nil {
		return nil, err
	}
	res, err := g.c.permissions.RemoveGroupMembers(ctx, &pb.RemoveGroupMembersRequest{ProjectName: project, Name: slug, PrincipalIds: principals})
	if err != nil {
		return nil, err
	}
	return &MembershipChange{
		Changed:   append([]string{}, res.GetRemovedPrincipalIds()...),
		Unchanged: append([]string{}, res.GetNotMemberPrincipalIds()...),
	}, nil
}

// ListMembers iterates a group's members, ordered by principal ID. opts may be
// nil; Search is ignored.
func (g *Groups) ListMembers(ctx context.Context, name string, opts *ListOptions) iter.Seq2[GroupMember, error] {
	project, slug, err := g.prep(name)
	if err != nil {
		return failed[GroupMember](err)
	}
	return paginate(ctx, opts.pageSize(), func(ctx context.Context, p *paginationv1.PaginationRequest) ([]GroupMember, string, error) {
		res, err := g.c.permissions.ListGroupMembers(ctx, &pb.ListGroupMembersRequest{ProjectName: project, Name: slug, Pagination: p})
		if err != nil {
			return nil, "", err
		}
		out := make([]GroupMember, 0, len(res.GetMembers()))
		for _, m := range res.GetMembers() {
			out = append(out, memberFromPB(m))
		}
		return out, res.GetPagination().GetNextCursor(), nil
	})
}

// ListForPrincipal iterates the groups principal is a member of, ordered by
// name. opts may be nil; Search is ignored.
func (g *Groups) ListForPrincipal(ctx context.Context, principal string, opts *ListOptions) iter.Seq2[Group, error] {
	if principal == "" {
		return failed[Group](invalid("principal is required"))
	}
	project, err := g.c.projectName()
	if err != nil {
		return failed[Group](err)
	}
	return paginate(ctx, opts.pageSize(), func(ctx context.Context, p *paginationv1.PaginationRequest) ([]Group, string, error) {
		res, err := g.c.permissions.ListGroupsForPrincipal(ctx, &pb.ListGroupsForPrincipalRequest{ProjectName: project, PrincipalId: principal, Pagination: p})
		if err != nil {
			return nil, "", err
		}
		out := make([]Group, 0, len(res.GetGroups()))
		for _, x := range res.GetGroups() {
			out = append(out, groupFromPB(x))
		}
		return out, res.GetPagination().GetNextCursor(), nil
	})
}
