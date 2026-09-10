// Package openvpn is a CUSTOM backend (not part of upstream PasarGuard) that
// implements the backend.Backend interface for an OpenVPN server, mirroring
// the shape of backend/xray and backend/wireguard so it plugs into the same
// Controller.StartBackend switch. See CONTRIBUTING-custom.md at the repo root
// for the fork-maintenance rules this package follows.
//
// v1 scope (deliberately narrow — see the panel-side protocol catalog):
//   - one transport per instance (proto: "udp" or "tcp"), not both at once
//   - username/password auth only (no client certificates)
//   - no per-device limits / client-config-dir IP pinning yet
//   - traffic is NAT'd straight out (no TPROXY-into-Xray routing yet)
//
// Each of these matches a "next" item once this proof of concept is confirmed
// working end to end.
package openvpn

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Config is the OpenVPN backend configuration, sent by the panel as the
// Backend.config JSON string (same convention as wireguard.NewConfig).
type Config struct {
	// Port is the UDP/TCP port the OpenVPN server listens on.
	Port int `json:"port"`
	// Proto is "udp" (default) or "tcp".
	Proto string `json:"proto"`
	// Subnet is the client address pool, e.g. "10.9.0.0/24". The server takes
	// the first usable address.
	Subnet string `json:"subnet"`
	// Dns1/Dns2 are pushed to clients as their DNS servers.
	Dns1 string `json:"dns1"`
	Dns2 string `json:"dns2"`
	// Device is the tun interface name. Kept short: the kernel caps IFNAMSIZ
	// at 15 bytes.
	Device string `json:"device"`
	// Mtu is the tun-mtu; 0 means OpenVPN's own default (1500).
	Mtu int `json:"mtu"`
}

// NewConfig parses the backend config JSON, filling in defaults for anything
// left unset — mirrors wireguard.NewConfig's fill-in-defaults convention.
func NewConfig(raw string) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("openvpn: failed to unmarshal config: %w", err)
	}

	if cfg.Port <= 0 {
		cfg.Port = 1194
	}
	cfg.Proto = strings.ToLower(strings.TrimSpace(cfg.Proto))
	if cfg.Proto != "tcp" {
		cfg.Proto = "udp" // default and only other supported value in v1
	}
	if strings.TrimSpace(cfg.Subnet) == "" {
		cfg.Subnet = "10.9.0.0/24"
	}
	if strings.TrimSpace(cfg.Dns1) == "" {
		cfg.Dns1 = "1.1.1.1"
	}
	if strings.TrimSpace(cfg.Dns2) == "" {
		cfg.Dns2 = "1.0.0.1"
	}
	if strings.TrimSpace(cfg.Device) == "" {
		cfg.Device = "tun-pg-ovpn"
	}
	if cfg.Mtu <= 0 {
		cfg.Mtu = 1500
	}

	return &cfg, nil
}

// serverProto returns the value OpenVPN's `proto` directive expects: `tcp`
// needs the server-mode suffix, `udp` does not.
func (c *Config) serverProto() string {
	if c.Proto == "tcp" {
		return "tcp-server"
	}
	return "udp"
}
