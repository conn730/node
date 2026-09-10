package main

// CUSTOM: not upstream. Backs the OpenVPN backend's
// `auth-user-pass-verify "<this binary> openvpn-auth <dir>" via-file` hook
// (see backend/openvpn/serverconfig.go). OpenVPN appends the path to a
// temporary file holding the username and password (one per line) as the
// final argument, then treats exit code 0 as accept and non-zero as reject.
// See CONTRIBUTING-custom.md.

import (
	"bufio"
	"fmt"
	"os"

	"github.com/pasarguard/node/backend/openvpn"
)

// maybeRunOpenVPNAuthHook handles the `openvpn-auth <dir> <credsFile>`
// invocation and, if this process was invoked that way, exits the process
// itself — the normal node server never starts for this invocation. Call
// this first thing in main(), before config.Load()/server startup, since a
// short-lived auth check must not pay the cost of (or interfere with) a full
// node bring-up.
func maybeRunOpenVPNAuthHook() {
	if len(os.Args) < 4 || os.Args[1] != "openvpn-auth" {
		return
	}
	dir := os.Args[2]
	credsFile := os.Args[3]

	username, password, err := readOpenVPNCreds(credsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "openvpn-auth: reading credentials file:", err)
		os.Exit(1)
	}

	if openvpn.CheckAuth(dir, username, password) {
		os.Exit(0)
	}
	os.Exit(1)
}

func readOpenVPNCreds(path string) (username, password string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		username = scanner.Text()
	}
	if scanner.Scan() {
		password = scanner.Text()
	}
	return username, password, scanner.Err()
}
