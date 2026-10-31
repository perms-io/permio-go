package permio

import (
	"context"
	"iter"

	paginationv1 "github.com/perms-io/permio-go/proto/pagination/v1"
	pb "github.com/perms-io/permio-go/proto/permissions/v1"
)

// GrantRequest says what to grant or revoke.
type GrantRequest struct {
	// Principal is one of your principal IDs, or GroupPrincipal(slug) for a group.
	Principal string
	// Resource is the resource URI of the grant. A grant also covers every URI
	// below it; a revoke applies to exactly this URI.
	Resource string
	// Permissions are permission names.
	Permissions []string
	// Roles are role IDs (see ListRoles).
	Roles []string
}

func (c *Client) grantInputs(req GrantRequest) (string, []string, []string, error) {
	if req.Principal == "" {
		return "", nil, nil, invalid("principal is required")
	}
	if err := ValidateResourceURI(req.Resource); err != nil {
		return "", nil, nil, err
	}
	perms, roles := uniq(req.Permissions), uniq(req.Roles)
	for _, v := range append(append([]string{}, perms...), roles...) {
		if v == "" {
			return "", nil, nil, invalid("permission names and role IDs must not be empty")
		}
	}
	if len(perms) == 0 && len(roles) == 0 {
		return "", nil, nil, invalid("at least one permission or role is required")
	}
	project, err := c.projectName()
	return project, perms, roles, err
}

// Grant grants permissions and roles to a principal on a resource, and so on
// every resource below it. Additive: what the principal already holds there
// is kept. Pass GroupPrincipal(slug) to grant to every member of a group.
//
// Like every write, a grant is sent once and never retried automatically. It
// fails with [KindValidation] if a permission or role does not exist, and
// [KindPermission] unless the API key has full access.
func (c *Client) Grant(ctx context.Context, req GrantRequest) error {
	project, perms, roles, err := c.grantInputs(req)
	if err != nil {
		return err
	}
	_, err = c.permissions.GrantUserPermissionsAndRolesOnResource(ctx, &pb.GrantUserPermissionsAndRolesOnResourceRequest{
		ProjectName: project, UserId: req.Principal, ResourceUri: req.Resource, Permissions: perms, Roles: roles,
	})
	return err
}

// Revoke removes permissions and roles from a principal's grant on exactly
// req.Resource. Names the grant does not hold are ignored, so revoking twice
// is harmless. Grants on ancestor URIs are not touched, so the principal may
// still pass a check on the resource afterwards; WhoHasAccess shows where
// access comes from.
//
// Like every write, a revoke is sent once and never retried automatically.
func (c *Client) Revoke(ctx context.Context, req GrantRequest) error {
	project, perms, roles, err := c.grantInputs(req)
	if err != nil {
		return err
	}
	_, err = c.permissions.RevokeUserPermissionsAndRolesOnResource(ctx, &pb.RevokeUserPermissionsAndRolesOnResourceRequest{
		ProjectName: project, UserId: req.Principal, ResourceUri: req.Resource, Permissions: perms, Roles: roles,
	})
	return err
}

// GetGrant returns what is granted to principal on exactly resource (not
// inherited grants). The API returns role IDs only, so RoleRef.Name is empty.
func (c *Client) GetGrant(ctx context.Context, principal, resource string) (*Grant, error) {
	if principal == "" {
		return nil, invalid("principal is required")
	}
	if err := ValidateResourceURI(resource); err != nil {
		return nil, err
	}
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	res, err := c.permissions.GetUserPermissionsAndRolesOnResource(ctx, &pb.GetUserPermissionsAndRolesOnResourceRequest{
		ProjectName: project, UserId: principal, ResourceUri: resource,
	})
	if err != nil {
		return nil, err
	}
	g := &Grant{Principal: principal, Resource: resource, Roles: []RoleRef{}, Permissions: append([]string{}, res.GetPermissions()...)}
	for _, id := range res.GetRoles() {
		g.Roles = append(g.Roles, RoleRef{ID: id})
	}
	normaliseGrant(g)
	return g, nil
}

// ListAssignments iterates every grant made to principal, one per resource
// URI (GetAllAssignmentsForPrincipal). opts may be nil; Search is ignored.
func (c *Client) ListAssignments(ctx context.Context, principal string, opts *ListOptions) iter.Seq2[Grant, error] {
	if principal == "" {
		return failed[Grant](invalid("principal is required"))
	}
	project, err := c.projectName()
	if err != nil {
		return failed[Grant](err)
	}
	return paginate(ctx, opts.pageSize(), func(ctx context.Context, p *paginationv1.PaginationRequest) ([]Grant, string, error) {
		res, err := c.permissions.GetAllAssignmentsForPrincipal(ctx, &pb.GetAllAssignmentsForPrincipalRequest{ProjectName: project, PrincipalId: principal, Pagination: p})
		if err != nil {
			return nil, "", err
		}
		out := make([]Grant, 0, len(res.GetAssignments()))
		for _, a := range res.GetAssignments() {
			out = append(out, grantFromAssignment(principal, a))
		}
		return out, res.GetPagination().GetNextCursor(), nil
	})
}

// ListPrincipals iterates the IDs of every principal with a grant in the
// project, groups included as "group:<slug>". opts may be nil.
func (c *Client) ListPrincipals(ctx context.Context, opts *ListOptions) iter.Seq2[string, error] {
	project, err := c.projectName()
	if err != nil {
		return failed[string](err)
	}
	return paginate(ctx, opts.pageSize(), func(ctx context.Context, p *paginationv1.PaginationRequest) ([]string, string, error) {
		res, err := c.permissions.ListPrincipals(ctx, &pb.ListPrincipalsRequest{ProjectName: project, Pagination: p, Search: optString(opts.search())})
		if err != nil {
			return nil, "", err
		}
		return res.GetPrincipals(), res.GetPagination().GetNextCursor(), nil
	})
}

// ListPermissions iterates every permission in the project. opts may be nil.
func (c *Client) ListPermissions(ctx context.Context, opts *ListOptions) iter.Seq2[Permission, error] {
	project, err := c.projectName()
	if err != nil {
		return failed[Permission](err)
	}
	return paginate(ctx, opts.pageSize(), func(ctx context.Context, p *paginationv1.PaginationRequest) ([]Permission, string, error) {
		res, err := c.permissions.ListPermissions(ctx, &pb.ListPermissionsRequest{ProjectName: project, Pagination: p, Search: optString(opts.search())})
		if err != nil {
			return nil, "", err
		}
		out := make([]Permission, 0, len(res.GetPermissions()))
		for _, x := range res.GetPermissions() {
			out = append(out, permissionFromPB(x))
		}
		return out, res.GetPagination().GetNextCursor(), nil
	})
}

// ListRoles iterates every role in the project. opts may be nil.
func (c *Client) ListRoles(ctx context.Context, opts *ListOptions) iter.Seq2[Role, error] {
	project, err := c.projectName()
	if err != nil {
		return failed[Role](err)
	}
	return paginate(ctx, opts.pageSize(), func(ctx context.Context, p *paginationv1.PaginationRequest) ([]Role, string, error) {
		res, err := c.permissions.ListRoles(ctx, &pb.ListRolesRequest{ProjectName: project, Pagination: p, Search: optString(opts.search())})
		if err != nil {
			return nil, "", err
		}
		out := make([]Role, 0, len(res.GetRoles()))
		for _, x := range res.GetRoles() {
			out = append(out, roleFromPB(x))
		}
		return out, res.GetPagination().GetNextCursor(), nil
	})
}

// GetPermission returns one permission by name.
func (c *Client) GetPermission(ctx context.Context, name string) (*Permission, error) {
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	res, err := c.permissions.GetPermission(ctx, &pb.GetPermissionRequest{ProjectName: project, Name: name})
	if err != nil {
		return nil, err
	}
	p := permissionFromPB(res)
	return &p, nil
}

// CreatePermission creates a permission, or returns the existing one: create
// is idempotent. If the permission already exists, a non-empty description
// that differs replaces the stored one (which needs permission.update on it);
// an empty description leaves it as it is.
func (c *Client) CreatePermission(ctx context.Context, name, description string) (*Permission, error) {
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	res, err := c.permissions.CreatePermission(ctx, &pb.CreatePermissionRequest{ProjectName: project, Name: name, Description: description})
	if err != nil {
		return nil, err
	}
	p := permissionFromPB(res)
	return &p, nil
}

// UpdatePermission replaces a permission's description and, when newName is
// not empty, renames it. Renaming to a name already in use fails with
// [KindAlreadyExists].
func (c *Client) UpdatePermission(ctx context.Context, name, newName, description string) (*Permission, error) {
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	res, err := c.permissions.UpdatePermission(ctx, &pb.UpdatePermissionRequest{ProjectName: project, Name: name, NewName: optString(newName), Description: description})
	if err != nil {
		return nil, err
	}
	p := permissionFromPB(res)
	return &p, nil
}

// DeletePermission deletes a permission and every grant of it. Deleting one
// that does not exist succeeds.
func (c *Client) DeletePermission(ctx context.Context, name string) error {
	project, err := c.projectName()
	if err != nil {
		return err
	}
	_, err = c.permissions.DeletePermission(ctx, &pb.DeletePermissionRequest{ProjectName: project, Name: name})
	return err
}

// GetRole returns a role by ID.
func (c *Client) GetRole(ctx context.Context, id string) (*Role, error) {
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	res, err := c.permissions.GetRole(ctx, &pb.GetRoleRequest{ProjectName: project, Id: id})
	if err != nil {
		return nil, err
	}
	r := roleFromPB(res)
	return &r, nil
}

// CreateRole creates a role and returns it with its ID, or returns the
// existing role with this name: create is idempotent. If the role already
// exists, a non-empty description or permission list that differs replaces
// the stored one (which needs role.update on it); empty ones leave it as it is.
func (c *Client) CreateRole(ctx context.Context, name, description string, permissions []string) (*Role, error) {
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	res, err := c.permissions.CreateRole(ctx, &pb.CreateRoleRequest{ProjectName: project, Name: name, Description: description, Permissions: uniq(permissions)})
	if err != nil {
		return nil, err
	}
	r := roleFromPB(res)
	return &r, nil
}

// UpdateRole replaces a role's name, description and permissions. Renaming
// to a name another role uses fails with [KindAlreadyExists].
func (c *Client) UpdateRole(ctx context.Context, id, name, description string, permissions []string) (*Role, error) {
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	res, err := c.permissions.UpdateRole(ctx, &pb.UpdateRoleRequest{ProjectName: project, Id: id, Name: name, Description: description, Permissions: uniq(permissions)})
	if err != nil {
		return nil, err
	}
	r := roleFromPB(res)
	return &r, nil
}

// DeleteRole deletes a role by ID.
func (c *Client) DeleteRole(ctx context.Context, id string) error {
	project, err := c.projectName()
	if err != nil {
		return err
	}
	_, err = c.permissions.DeleteRole(ctx, &pb.DeleteRoleRequest{ProjectName: project, Id: id})
	return err
}
