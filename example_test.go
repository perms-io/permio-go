package permio_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	permio "github.com/perms-io/permio-go"
	permissionsv1 "github.com/perms-io/permio-go/proto/permissions/v1"
)

func Example() {
	client, err := permio.New(permio.Options{APIKey: os.Getenv("PERMIO_API_KEY"), Project: "my-app"})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ok, err := client.Check(context.Background(), "user-123", "docs.read", permio.MustResource("docs", "42"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("allowed:", ok)
}

func ExampleClient_Grant() {
	var client *permio.Client // from permio.New
	ctx := context.Background()

	// Grant to a group: every member holds the grant.
	err := client.Grant(ctx, permio.GrantRequest{
		Principal:   permio.GroupPrincipal("editors"),
		Resource:    permio.MustResource("docs"),
		Permissions: []string{"docs.read", "docs.write"},
	})
	if errors.Is(err, permio.ErrPermission) {
		log.Fatal("this API key is check-only; grants need a full-access key")
	}
}

func ExampleClient_ListRoles() {
	var client *permio.Client // from permio.New
	for role, err := range client.ListRoles(context.Background(), nil) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(role.ID, role.Name)
	}
}

func ExampleClient_ListAccess() {
	var client *permio.Client // from permio.New
	access, err := client.ListAccess(context.Background(), "user-123", "docs.read", "/docs")
	if err != nil {
		log.Fatal(err)
	}
	switch {
	case access.CoversAll:
		// No filter needed.
	case !access.HasPatterns():
		fmt.Println("path prefixes:", access.Prefixes())
	default:
		fmt.Println("regex:", access.RegexpSource())
	}
}

func ExampleClient_Permissions() {
	var client *permio.Client // from permio.New
	// The generated client, with auth, timeouts, retries and typed errors.
	res, err := client.Permissions().GetTotalRolesAndPermissionsForOrganisation(context.Background(),
		&permissionsv1.GetTotalRolesAndPermissionsForOrganisationRequest{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res)
}
