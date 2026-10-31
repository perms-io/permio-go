package permio

import (
	"sort"
	"time"

	permissionsv1 "github.com/perms-io/permio-go/proto/permissions/v1"
)

// Permission is a named action, e.g. "document.read".
type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Role is a named set of permissions. Roles are addressed by ID.
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// RoleRef identifies a role in a grant.
type RoleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Group is a named set of principals. Grants to Group.PrincipalID
// ("group:<name>") apply to every member.
type Group struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	PrincipalID string     `json:"principal_id"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// GroupMember is one member of a group.
type GroupMember struct {
	PrincipalID string     `json:"principal_id"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
}

// Grant is the roles and permissions granted to one principal on exactly one
// resource URI (an "assignment").
type Grant struct {
	Principal   string    `json:"principal"`
	Resource    string    `json:"resource"`
	Roles       []RoleRef `json:"roles"`
	Permissions []string  `json:"permissions"`
}

// CheckResult is the result of [Client.CheckDetailed].
type CheckResult struct {
	// Allowed is true when the principal holds every permission on every resource.
	Allowed bool `json:"allowed"`
	// Missing lists what is missing per resource. Empty when allowed.
	Missing []MissingPermission `json:"missing"`
}

// BatchResult is one resource's result from [Client.BatchCheckDetailed].
type BatchResult struct {
	Resource string `json:"resource"`
	// Allowed is true when the principal holds every requested permission on Resource.
	Allowed bool `json:"allowed"`
	// Missing is the requested permissions the principal lacks on Resource.
	Missing []string `json:"missing"`
}

// MembershipChange is the result of adding or removing group members.
type MembershipChange struct {
	// Changed are the principals added (or removed).
	Changed []string `json:"changed"`
	// Unchanged are the principals that were already members (or were not members).
	Unchanged []string `json:"unchanged"`
}

// PrincipalKind is the kind of credential a client uses, from [Client.WhoAmI].
type PrincipalKind string

const (
	PrincipalUser           PrincipalKind = "user"
	PrincipalAPIKey         PrincipalKind = "api_key"
	PrincipalServiceAccount PrincipalKind = "service_account"
	PrincipalUnknown        PrincipalKind = "unknown"
)

// APIKeyAccess is an API key's access level on its project.
type APIKeyAccess string

const (
	// APIKeyAccessCheck: checks and reads only.
	APIKeyAccessCheck APIKeyAccess = "check"
	// APIKeyAccessFull: also writes, grant and revoke.
	APIKeyAccessFull APIKeyAccess = "full"
	// APIKeyAccessUnknown: the key's rights were changed by hand.
	APIKeyAccessUnknown APIKeyAccess = "unknown"
)

// Identity describes the caller, as returned by [Client.WhoAmI].
type Identity struct {
	// PrincipalID is the caller's principal ID; for an API key, the key's ID.
	PrincipalID string `json:"principal_id"`
	// OrganisationID is the caller's organisation. Empty for a user who has not joined one.
	OrganisationID string `json:"organisation_id"`
	// Kind is the kind of credential.
	Kind PrincipalKind `json:"kind"`
	// Project is the project an API key belongs to; it can only be used
	// there. Empty for users.
	Project string `json:"project,omitempty"`
	// APIKeyAccess is set for API keys only.
	APIKeyAccess APIKeyAccess `json:"api_key_access,omitempty"`
	// Email is the user's email address, when the caller is a user with one.
	Email string `json:"email,omitempty"`
}

func permissionFromPB(p *permissionsv1.Permission) Permission {
	return Permission{Name: p.GetName(), Description: p.GetDescription()}
}

func roleFromPB(r *permissionsv1.Role) Role {
	out := Role{ID: r.GetId(), Name: r.GetName(), Description: r.GetDescription(), Permissions: []string{}}
	for _, p := range r.GetPermissions() {
		out.Permissions = append(out.Permissions, p.GetName())
	}
	sort.Strings(out.Permissions)
	return out
}

func groupFromPB(g *permissionsv1.Group) Group {
	out := Group{Name: g.GetName(), Description: g.GetDescription(), PrincipalID: g.GetPrincipalId()}
	if out.PrincipalID == "" {
		out.PrincipalID = GroupPrincipal(out.Name)
	}
	if g.GetCreatedAt() != nil {
		t := g.GetCreatedAt().AsTime()
		out.CreatedAt = &t
	}
	if g.GetUpdatedAt() != nil {
		t := g.GetUpdatedAt().AsTime()
		out.UpdatedAt = &t
	}
	return out
}

func memberFromPB(m *permissionsv1.GroupMember) GroupMember {
	out := GroupMember{PrincipalID: m.GetPrincipalId()}
	if m.GetCreatedAt() != nil {
		t := m.GetCreatedAt().AsTime()
		out.CreatedAt = &t
	}
	return out
}

func grantFromAssignment(principal string, a *permissionsv1.Assignment) Grant {
	g := Grant{Principal: principal, Resource: a.GetResourceUri(), Roles: []RoleRef{}, Permissions: []string{}}
	for _, r := range a.GetRoles() {
		g.Roles = append(g.Roles, RoleRef{ID: r.GetId(), Name: r.GetName()})
	}
	for _, x := range a.GetPermissions() {
		g.Permissions = append(g.Permissions, x.GetName())
	}
	normaliseGrant(&g)
	return g
}

// normaliseGrant sorts and deduplicates a grant's permissions and roles.
func normaliseGrant(g *Grant) {
	g.Permissions = uniq(g.Permissions)
	sort.Strings(g.Permissions)
	seen := map[string]bool{}
	roles := g.Roles[:0]
	for _, r := range g.Roles {
		if r.ID == "" || seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		roles = append(roles, r)
	}
	g.Roles = roles
	sort.Slice(g.Roles, func(i, j int) bool {
		if g.Roles[i].Name != g.Roles[j].Name {
			return g.Roles[i].Name < g.Roles[j].Name
		}
		return g.Roles[i].ID < g.Roles[j].ID
	})
}
