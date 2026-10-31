package permio

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/perms-io/permio-go/proto/permissions/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

// testKey is a well-formed opaque API key (valid checksum).
var testKey = apiKeyPrefix + "0123456789ABCDEFGHIJKLMNOPQRSTUV" + apiKeyChecksum("0123456789ABCDEFGHIJKLMNOPQRSTUV")

// fakeServer is an in-process PermissionsService. Tests set the handlers they
// need; the rest answer Unimplemented.
type fakeServer struct {
	pb.UnimplementedPermissionsServiceServer

	mu    sync.Mutex
	calls map[string]int
	auth  []string

	check             func(context.Context, *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error)
	batchCheck        func(context.Context, *pb.BatchCheckRequest) (*pb.BatchCheckResponse, error)
	grant             func(context.Context, *pb.GrantUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error)
	revoke            func(context.Context, *pb.RevokeUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error)
	listPermissions   func(context.Context, *pb.ListPermissionsRequest) (*pb.ListPermissionsResponse, error)
	listAccess        func(context.Context, *pb.ListAccessRequest) (*pb.ListAccessResponse, error)
	whoHasAccess      func(context.Context, *pb.ListPrincipalsWithAccessRequest) (*pb.ListPrincipalsWithAccessResponse, error)
	whoAmI            func(context.Context, *pb.WhoAmIRequest) (*pb.WhoAmIResponse, error)
	addGroupMembers   func(context.Context, *pb.AddGroupMembersRequest) (*pb.AddGroupMembersResponse, error)
	createGroup       func(context.Context, *pb.CreateGroupRequest) (*pb.Group, error)
	listGroupMembers  func(context.Context, *pb.ListGroupMembersRequest) (*pb.ListGroupMembersResponse, error)
	getAllAssignments func(context.Context, *pb.GetAllAssignmentsForPrincipalRequest) (*pb.GetAllAssignmentsForPrincipalResponse, error)
	createPermission  func(context.Context, *pb.CreatePermissionRequest) (*pb.Permission, error)
	getPermission     func(context.Context, *pb.GetPermissionRequest) (*pb.Permission, error)
	deletePermission  func(context.Context, *pb.DeletePermissionRequest) (*emptypb.Empty, error)
	removeMembers     func(context.Context, *pb.RemoveGroupMembersRequest) (*pb.RemoveGroupMembersResponse, error)
}

func (s *fakeServer) count(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[method]
}

func (s *fakeServer) Check(ctx context.Context, r *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
	return s.check(ctx, r)
}
func (s *fakeServer) BatchCheck(ctx context.Context, r *pb.BatchCheckRequest) (*pb.BatchCheckResponse, error) {
	return s.batchCheck(ctx, r)
}
func (s *fakeServer) GrantUserPermissionsAndRolesOnResource(ctx context.Context, r *pb.GrantUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error) {
	return s.grant(ctx, r)
}
func (s *fakeServer) RevokeUserPermissionsAndRolesOnResource(ctx context.Context, r *pb.RevokeUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error) {
	return s.revoke(ctx, r)
}
func (s *fakeServer) ListPermissions(ctx context.Context, r *pb.ListPermissionsRequest) (*pb.ListPermissionsResponse, error) {
	return s.listPermissions(ctx, r)
}
func (s *fakeServer) ListAccess(ctx context.Context, r *pb.ListAccessRequest) (*pb.ListAccessResponse, error) {
	return s.listAccess(ctx, r)
}
func (s *fakeServer) ListPrincipalsWithAccess(ctx context.Context, r *pb.ListPrincipalsWithAccessRequest) (*pb.ListPrincipalsWithAccessResponse, error) {
	return s.whoHasAccess(ctx, r)
}
func (s *fakeServer) WhoAmI(ctx context.Context, r *pb.WhoAmIRequest) (*pb.WhoAmIResponse, error) {
	return s.whoAmI(ctx, r)
}
func (s *fakeServer) AddGroupMembers(ctx context.Context, r *pb.AddGroupMembersRequest) (*pb.AddGroupMembersResponse, error) {
	return s.addGroupMembers(ctx, r)
}
func (s *fakeServer) CreateGroup(ctx context.Context, r *pb.CreateGroupRequest) (*pb.Group, error) {
	return s.createGroup(ctx, r)
}
func (s *fakeServer) ListGroupMembers(ctx context.Context, r *pb.ListGroupMembersRequest) (*pb.ListGroupMembersResponse, error) {
	return s.listGroupMembers(ctx, r)
}
func (s *fakeServer) GetAllAssignmentsForPrincipal(ctx context.Context, r *pb.GetAllAssignmentsForPrincipalRequest) (*pb.GetAllAssignmentsForPrincipalResponse, error) {
	return s.getAllAssignments(ctx, r)
}
func (s *fakeServer) CreatePermission(ctx context.Context, r *pb.CreatePermissionRequest) (*pb.Permission, error) {
	return s.createPermission(ctx, r)
}
func (s *fakeServer) GetPermission(ctx context.Context, r *pb.GetPermissionRequest) (*pb.Permission, error) {
	return s.getPermission(ctx, r)
}
func (s *fakeServer) DeletePermission(ctx context.Context, r *pb.DeletePermissionRequest) (*emptypb.Empty, error) {
	return s.deletePermission(ctx, r)
}
func (s *fakeServer) RemoveGroupMembers(ctx context.Context, r *pb.RemoveGroupMembersRequest) (*pb.RemoveGroupMembersResponse, error) {
	return s.removeMembers(ctx, r)
}

// start serves s over bufconn and returns a client for it. Retry delays are
// shortened unless opts sets them.
func start(t *testing.T, s *fakeServer, opts Options) *Client {
	t.Helper()
	s.calls = map[string]int{}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		s.mu.Lock()
		s.calls[info.FullMethod]++
		s.auth = append(s.auth, md.Get("authorization")...)
		s.mu.Unlock()
		return h(ctx, req)
	}))
	pb.RegisterPermissionsServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	if opts.APIKey == "" {
		opts.APIKey = testKey
	}
	if opts.Project == "" {
		opts.Project = "proj"
	}
	if opts.Retry.BaseDelay == 0 {
		opts.Retry.BaseDelay = time.Millisecond
	}
	opts.Conn = conn
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const (
	mCheck  = "/permio.permissions.v1.PermissionsService/Check"
	mGrant  = "/permio.permissions.v1.PermissionsService/GrantUserPermissionsAndRolesOnResource"
	mRevoke = "/permio.permissions.v1.PermissionsService/RevokeUserPermissionsAndRolesOnResource"
	mBatch  = "/permio.permissions.v1.PermissionsService/BatchCheck"
	mList   = "/permio.permissions.v1.PermissionsService/ListPermissions"
	mWhoAmI = "/permio.permissions.v1.PermissionsService/WhoAmI"
)
