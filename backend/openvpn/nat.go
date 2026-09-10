package openvpn

import (
	"fmt"
	"os/exec"
)

// natTable is a dedicated nftables table this package owns exclusively, so
// enabling/disabling NAT for the OpenVPN subnet never touches rules any other
// backend (or the operator) created. Same "own what you create" discipline
// vpn-ui's ownPrepareDir follows for files.
const natTable = "pg_ovpn_nat"

// setupNAT enables IPv4 forwarding and masquerades the given client subnet
// out whatever interface has the default route, so tunneled clients reach
// the internet. This is a plain NAT egress — NOT routed through Xray yet
// (that TPROXY integration is a later phase, see package doc).
func setupNAT(subnetCIDR string) error {
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}

	// Idempotent: delete-if-exists then (re)create, so calling this on every
	// Restart never accumulates duplicate rules.
	_ = teardownNAT()

	if err := run("nft", "add", "table", "ip", natTable); err != nil {
		return fmt.Errorf("nft add table: %w", err)
	}
	if err := run("nft", "add", "chain", "ip", natTable, "postrouting",
		"{ type nat hook postrouting priority 100 ; }"); err != nil {
		return fmt.Errorf("nft add chain: %w", err)
	}
	if err := run("nft", "add", "rule", "ip", natTable, "postrouting",
		"ip", "saddr", subnetCIDR, "masquerade"); err != nil {
		return fmt.Errorf("nft add masquerade rule: %w", err)
	}
	return nil
}

// teardownNAT removes the table setupNAT created, if any. Safe to call when
// nothing exists yet (nft exits non-zero, which we ignore here).
func teardownNAT() error {
	return run("nft", "delete", "table", "ip", natTable)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, string(out))
	}
	return nil
}
