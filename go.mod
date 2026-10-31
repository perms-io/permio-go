module github.com/perms-io/permio-go

go 1.24

// v0.0.1 to v0.0.18 contained only the generated gRPC stubs under proto/, not
// the permio SDK package. Retracting them makes `go get ...@latest` skip them
// once a later version that carries this directive is published.
retract [v0.0.1, v0.0.18]

require (
	github.com/envoyproxy/protoc-gen-validate v1.2.1
	google.golang.org/genproto/googleapis/api v0.0.0-20250124145028-65684f501c47
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f
	google.golang.org/grpc v1.70.0
	google.golang.org/protobuf v1.36.4
)

require (
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
