// keygen: generate the identity pair used by the cross-language interop
// matrix (../../scripts/xlang-matrix.sh).
//
// It writes a "server" and a "client" identity into a directory using the
// shared layout all four SDKs produce — <name>.key.pem (PKCS#8 Ed25519) /
// <name>.crt.pem / <name>.identity.json — and prints both fingerprints. The
// PEM files must be loadable by the TypeScript and Python loaders as well;
// that cross-loading is part of what the matrix exercises.
//
// Usage:
//
//	go run ./examples/keygen -dir ./xlang-id
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/fly88oj/krymux-go/pkg/keys"
)

func main() {
	dir := flag.String("dir", "xlang-id", "output directory for the identity pair")
	flag.Parse()

	server, err := keys.GenerateIdentity("krymux-xlang-server")
	if err != nil {
		log.Fatalf("server identity: %v", err)
	}
	client, err := keys.GenerateIdentity("krymux-xlang-client")
	if err != nil {
		log.Fatalf("client identity: %v", err)
	}
	if _, _, err := keys.SaveIdentity(*dir, server, "server"); err != nil {
		log.Fatalf("save server identity: %v", err)
	}
	if _, _, err := keys.SaveIdentity(*dir, client, "client"); err != nil {
		log.Fatalf("save client identity: %v", err)
	}
	fmt.Printf("server fingerprint: %s\n", server.Fingerprint)
	fmt.Printf("client fingerprint: %s\n", client.Fingerprint)
}
