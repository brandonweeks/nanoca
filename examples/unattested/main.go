// Command unattested mints one-time tokens for TokenGate, an example
// nanoca.UnattestedAuthorizer for Apple devices that cannot attest (macOS
// VMs, Intel Macs).
//
// Copy TokenGate into your server and configure it with
// nanoca.WithUnattestedAuthorizer. Put each minted token in one ACME
// payload's ClientIdentifier, with Attest false. The token is the whole
// security boundary for these certificates, so treat it like a password.
//
// Usage: unattested -dir DIR mint
package main

import (
	"flag"
	"fmt"
	"log"
	"time"
)

func main() {
	dir := flag.String("dir", "tokens", "token directory")
	flag.Parse()
	if flag.Arg(0) != "mint" {
		log.Fatal("usage: unattested -dir DIR mint")
	}
	tok, err := NewTokenGate(*dir, 7*24*time.Hour).Mint()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(tok)
}
