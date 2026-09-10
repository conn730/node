package openvpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/stats"
)

type lifecycleState uint8

const (
	lifecycleStopped lifecycleState = iota
	lifecycleRunning
)

var errNotStarted = errors.New("openvpn not started")

// OpenVpn implements backend.Backend for a single OpenVPN server instance.
// See package doc in config.go for the v1 scope this deliberately covers.
type OpenVpn struct {
	mu sync.RWMutex

	nodeCfg *config.Config
	ovCfg   *Config
	dir     string // GeneratedConfigPath/openvpn — config, certs, users.json, status log

	proc         *procSupervisor
	statsTracker *stats.Tracker
	updateTicker *time.Ticker
	cancelFunc   context.CancelFunc

	users       []storedUser      // current account list (username/password)
	emailByUser map[string]string // username -> email, for stats attribution

	state     lifecycleState
	version   string
	startTime time.Time
}

// New starts (or re-starts, if dir already has a config from a previous run)
// an OpenVPN server matching ovCfg and syncs the given users.
func New(nodeCfg *config.Config, ovCfg *Config, users []*common.User) (*OpenVpn, error) {
	if ovCfg == nil {
		return nil, errors.New("openvpn config must not be nil")
	}

	bin, err := resolveOpenVPNBinary()
	if err != nil {
		return nil, err
	}

	dir := filepath.Join(strings.TrimRight(nodeCfg.GeneratedConfigPath, "/"), "openvpn")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	if err := loadOrCreateCerts(dir); err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}

	o := &OpenVpn{
		nodeCfg:      nodeCfg,
		ovCfg:        ovCfg,
		dir:          dir,
		proc:         newProcSupervisor(nodeCfg.LogBufferSize),
		statsTracker: stats.New(),
		emailByUser:  map[string]string{},
		version:      openvpnVersion(bin),
	}

	o.setUsersLocked(users)
	if err := writeUsersFile(o.dir, o.users); err != nil {
		return nil, fmt.Errorf("write users file: %w", err)
	}

	if err := o.writeServerConfig(); err != nil {
		return nil, err
	}
	if err := setupNAT(o.ovCfg.Subnet); err != nil {
		// Not fatal: the tunnel still comes up, it just won't reach the
		// internet until this is fixed — surfaced via logs rather than
		// failing startup outright, same tolerance vpn-ui's SetupRouting has.
		o.emitLog(fmt.Sprintf("warning: NAT setup failed: %v", err))
	}

	if err := o.proc.start(bin, []string{"--config", o.confPath()}, o.dir); err != nil {
		return nil, fmt.Errorf("start openvpn: %w", err)
	}

	o.mu.Lock()
	o.state = lifecycleRunning
	o.startTime = time.Now()
	o.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	o.cancelFunc = cancel
	interval := time.Duration(nodeCfg.StatsUpdateIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	o.updateTicker = time.NewTicker(interval)
	go o.runStatsLoop(ctx)

	return o, nil
}

func (o *OpenVpn) confPath() string     { return filepath.Join(o.dir, "server.conf") }
func (o *OpenVpn) statusPath() string   { return filepath.Join(o.dir, "status.log") }
func (o *OpenVpn) mgmtSockPath() string { return filepath.Join(o.dir, "mgmt.sock") }

// Started reports whether the OpenVPN process is alive.
func (o *OpenVpn) Started() bool {
	o.mu.RLock()
	state := o.state
	o.mu.RUnlock()
	return state == lifecycleRunning && o.proc.running()
}

// Version returns the openvpn binary version string.
func (o *OpenVpn) Version() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.version
}

// Logs returns the process's combined stdout/stderr as a line channel.
func (o *OpenVpn) Logs() <-chan string {
	return o.proc.logChan
}

// Restart regenerates the server config (in case ovCfg or the account list
// changed) and bounces the OpenVPN process.
func (o *OpenVpn) Restart() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if err := o.proc.stop(); err != nil {
		return err
	}
	if err := o.writeServerConfig(); err != nil {
		return err
	}
	bin, err := resolveOpenVPNBinary()
	if err != nil {
		return err
	}
	if err := o.proc.start(bin, []string{"--config", o.confPath()}, o.dir); err != nil {
		return fmt.Errorf("restart openvpn: %w", err)
	}
	o.state = lifecycleRunning
	o.startTime = time.Now()
	return nil
}

// Shutdown stops the OpenVPN process and tears down NAT. Idempotent.
func (o *OpenVpn) Shutdown() {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.cancelFunc != nil {
		o.cancelFunc()
		o.cancelFunc = nil
	}
	if o.updateTicker != nil {
		o.updateTicker.Stop()
	}
	_ = o.proc.stop()
	_ = teardownNAT()
	o.state = lifecycleStopped
}

func (o *OpenVpn) emitLog(line string) {
	select {
	case o.proc.logChan <- line:
	default:
	}
}

// resolveOpenVPNBinary looks for openvpn on PATH. v1 relies on the distro
// package (`apt install openvpn` / equivalent) rather than bundling a static
// binary the way vpn-ui does — bundling is a reasonable follow-up once the
// proof of concept is confirmed working.
func resolveOpenVPNBinary() (string, error) {
	path, err := exec.LookPath("openvpn")
	if err != nil {
		return "", fmt.Errorf("openvpn binary not found on PATH — install it first (e.g. `apt install openvpn`): %w", err)
	}
	return path, nil
}

func openvpnVersion(bin string) string {
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	lines := strings.SplitN(string(out), "\n", 2)
	return strings.TrimSpace(lines[0])
}

// serverSubnetAddr returns the server's own address inside its client
// subnet (the first usable host address, i.e. netAddr+1) and the subnet mask.
func serverSubnetAddr(cidr string) (serverIP net.IP, netAddr net.IP, mask net.IP, err error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid subnet %q: %w", cidr, err)
	}
	netAddr = ipNet.IP.To4()
	if netAddr == nil {
		return nil, nil, nil, fmt.Errorf("subnet %q must be IPv4", cidr)
	}
	mask = net.IP(ipNet.Mask)
	server := make(net.IP, 4)
	copy(server, netAddr)
	server[3]++ // netAddr.1
	return server, netAddr, mask, nil
}
