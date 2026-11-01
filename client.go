// Package permio is the official Go SDK for perms.io, a hosted authorization
// service for RBAC and fine-grained permissions in multi-tenant apps.
//
// A [Client] wraps the generated gRPC clients with API key auth, per-attempt
// timeouts, retries for idempotent reads, typed errors ([Error]) and helpers
// for checks, grants, groups and paginated listings:
//
//	client, err := permio.New(permio.Options{APIKey: os.Getenv("PERMIO_API_KEY"), Project: "my-app"})
//	if err != nil { ... }
//	defer client.Close()
//	resource, err := permio.Resource("docs", docID)
//	if err != nil { ... }
//	ok, err := client.Check(ctx, userID, "docs.read", resource)
//
// The generated clients stay reachable through [Client.Permissions] and
// [Client.Organisations], with the same auth, timeouts, retries and errors.
package permio

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	organisationv1 "github.com/perms-io/permio-go/proto/organisation/v1"
	permissionsv1 "github.com/perms-io/permio-go/proto/permissions/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// DefaultEndpoint is the production API.
	DefaultEndpoint = "api.perms.io:443"
	// DefaultTimeout is the default per-attempt timeout.
	DefaultTimeout = 10 * time.Second
	// EnvAPIKey is read when Options.APIKey is empty.
	EnvAPIKey = "PERMIO_API_KEY"
)

// Options configures a [Client]. Only an API key is required.
type Options struct {
	// APIKey is a "perms_" key from the dashboard, or a legacy JWT key. When
	// empty, the PERMIO_API_KEY environment variable is used.
	APIKey string
	// Endpoint is the API's "host:port" ([DefaultEndpoint] when empty), or a
	// URL such as "https://api.perms.io". "http://" URLs dial without TLS,
	// which is only allowed to a local host (see Insecure).
	// Ignored when Conn is set.
	Endpoint string
	// Insecure dials without TLS. Only for local servers: the API key would be
	// sent in clear, so New fails with [KindConfig] unless the endpoint's host
	// is a loopback address, "localhost" or a name ending in ".localhost".
	Insecure bool
	// Project is the default project_name. Use [Client.WithProject] for others.
	Project string
	// Timeout is the per-attempt timeout. Zero means [DefaultTimeout]; a
	// negative value disables it. Set an overall deadline with the context.
	Timeout time.Duration
	// ListTimeout is the per-attempt timeout for each page request made by
	// the listing helpers (iterators, Seq forms, WhoHasAccess, ListAccess).
	// Zero means the same as Timeout; a negative value disables it.
	ListTimeout time.Duration
	// Retry configures retries of idempotent reads. Writes are never retried.
	Retry RetryOptions
	// UserAgent is prepended to grpc-go's user agent.
	UserAgent string
	// DialOptions are appended to the default dial options.
	DialOptions []grpc.DialOption
	// Conn, when set, is used instead of dialling Endpoint, e.g. a bufconn
	// connection in tests. Auth, timeouts, retries and error mapping still
	// apply. The caller owns it: Close does not close it.
	Conn grpc.ClientConnInterface
}

// Client talks to the perms.io API. It is safe for concurrent use.
type Client struct {
	project       string
	conn          *resilientConn
	owned         *grpc.ClientConn
	permissions   permissionsv1.PermissionsServiceClient
	organisations organisationv1.OrganisationServiceClient
	apiKeyKind    APIKeyKind
}

// New validates the options and creates a client. It does not connect until
// the first call. Errors are of kind [KindConfig].
func New(opts Options) (*Client, error) {
	key := opts.APIKey
	if key == "" {
		key = os.Getenv(EnvAPIKey)
	}
	kind, err := ValidateAPIKey(key)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	} else if timeout < 0 {
		timeout = 0
	}
	listTimeout := opts.ListTimeout
	if listTimeout == 0 {
		listTimeout = timeout
	} else if listTimeout < 0 {
		listTimeout = 0
	}
	rc := &resilientConn{
		authorization: "Bearer " + key,
		timeout:       timeout,
		listTimeout:   listTimeout,
		retry:         opts.Retry.withDefaults(),
		sleep:         sleepCtx,
	}
	c := &Client{project: opts.Project, conn: rc, apiKeyKind: kind}
	if opts.Conn != nil {
		rc.inner = opts.Conn
	} else {
		target, tlsOn, err := parseEndpoint(opts.Endpoint)
		if err != nil {
			return nil, err
		}
		creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
		if opts.Insecure || !tlsOn {
			if !isLocalTarget(target) {
				return nil, configError("refusing to dial %q without TLS: the API key would be sent in clear; plaintext is only allowed to localhost, *.localhost or a loopback address", target)
			}
			creds = insecure.NewCredentials()
		}
		dial := []grpc.DialOption{grpc.WithTransportCredentials(creds), grpc.WithDisableServiceConfig()}
		if opts.UserAgent != "" {
			dial = append(dial, grpc.WithUserAgent(opts.UserAgent))
		}
		dial = append(dial, opts.DialOptions...)
		// passthrough: the address is dialled as given (with the system
		// resolver), like the older grpc.Dial, rather than via DNS balancing.
		cc, err := grpc.NewClient("passthrough:///"+target, dial...)
		if err != nil {
			return nil, configError("invalid endpoint %q: %v", opts.Endpoint, err)
		}
		rc.inner, c.owned = cc, cc
	}
	c.permissions = permissionsv1.NewPermissionsServiceClient(rc)
	c.organisations = organisationv1.NewOrganisationServiceClient(rc)
	return c, nil
}

// parseEndpoint turns "host:port", "host" or an http(s) URL into a dial target.
func parseEndpoint(endpoint string) (target string, tlsOn bool, err error) {
	if endpoint == "" {
		return DefaultEndpoint, true, nil
	}
	tlsOn = true
	if strings.Contains(endpoint, "://") {
		u, perr := url.Parse(endpoint)
		if perr != nil || u.Host == "" || (u.Path != "" && u.Path != "/") {
			return "", false, configError("invalid endpoint %q: use host:port or https://host", endpoint)
		}
		switch u.Scheme {
		case "https":
		case "http":
			tlsOn = false
		default:
			return "", false, configError("invalid endpoint %q: the scheme must be https or http", endpoint)
		}
		endpoint = u.Host
	}
	if _, _, serr := net.SplitHostPort(endpoint); serr != nil {
		port := "443"
		if !tlsOn {
			port = "80"
		}
		endpoint = net.JoinHostPort(strings.Trim(endpoint, "[]"), port)
	}
	return endpoint, tlsOn, nil
}

// isLocalTarget reports whether a "host:port" dial target is this machine:
// a loopback IP, "localhost" or a name ending in ".localhost".
func isLocalTarget(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Close releases the connection the client dialled. Clients made with
// [Client.WithProject] share it; close only the original.
func (c *Client) Close() error {
	if c.owned == nil {
		return nil
	}
	return c.owned.Close()
}

// WithProject returns a client that uses project instead of the default
// project. It shares c's connection.
func (c *Client) WithProject(project string) *Client {
	cp := *c
	cp.project = project
	cp.owned = nil
	return &cp
}

// Project returns the client's project, or "" if none is set.
func (c *Client) Project() string { return c.project }

// APIKeyKind reports whether the client's key is an opaque "perms_" key or a
// legacy JWT.
func (c *Client) APIKeyKind() APIKeyKind { return c.apiKeyKind }

// Permissions returns the generated PermissionsService client, with auth,
// timeouts, retries and error mapping applied. Use it for RPCs the helpers do
// not wrap; set ProjectName on requests yourself.
func (c *Client) Permissions() permissionsv1.PermissionsServiceClient { return c.permissions }

// Organisations returns the generated OrganisationService client, with auth,
// timeouts, retries and error mapping applied.
func (c *Client) Organisations() organisationv1.OrganisationServiceClient { return c.organisations }

// Conn returns the wrapped connection, for other generated clients.
func (c *Client) Conn() grpc.ClientConnInterface { return c.conn }

func (c *Client) projectName() (string, error) {
	if c.project == "" {
		return "", configError("no project configured; set Options.Project or use Client.WithProject")
	}
	return c.project, nil
}

// WhoAmI describes the credential this client uses: for an API key, its ID,
// its organisation, the project it belongs to and its access level. Useful to
// verify a key at startup. It needs no project.
func (c *Client) WhoAmI(ctx context.Context) (*Identity, error) {
	res, err := c.permissions.WhoAmI(ctx, &permissionsv1.WhoAmIRequest{})
	if err != nil {
		return nil, err
	}
	out := &Identity{
		PrincipalID:    res.GetPrincipalId(),
		OrganisationID: res.GetOrganisationId(),
		Project:        res.GetProjectName(),
		Email:          res.GetEmail(),
	}
	switch res.GetPrincipalType() {
	case permissionsv1.PrincipalType_PRINCIPAL_TYPE_USER:
		out.Kind = PrincipalUser
	case permissionsv1.PrincipalType_PRINCIPAL_TYPE_API_KEY:
		out.Kind = PrincipalAPIKey
	case permissionsv1.PrincipalType_PRINCIPAL_TYPE_SERVICE_ACCOUNT:
		out.Kind = PrincipalServiceAccount
	default:
		out.Kind = PrincipalUnknown
	}
	if out.Kind == PrincipalAPIKey {
		switch res.GetApiKeyAccess() {
		case permissionsv1.APIKeyAccess_API_KEY_ACCESS_CHECK:
			out.APIKeyAccess = APIKeyAccessCheck
		case permissionsv1.APIKeyAccess_API_KEY_ACCESS_FULL:
			out.APIKeyAccess = APIKeyAccessFull
		default:
			out.APIKeyAccess = APIKeyAccessUnknown
		}
	}
	return out, nil
}
