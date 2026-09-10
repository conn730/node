package openvpn

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// procSupervisor manages exactly one OpenVPN child process, started and
// owned directly by this Go process (no systemd unit). This mirrors how
// vpn-ui's own procMgr runs OpenVPN: the binary path in `args` is expected to
// be resolved by the caller (bundled binary if present, else `openvpn` from
// PATH), same fallback vpn-ui uses.
type procSupervisor struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	logChan chan string
	done    chan struct{}
}

func newProcSupervisor(logBufferSize int) *procSupervisor {
	if logBufferSize <= 0 {
		logBufferSize = 1000
	}
	return &procSupervisor{logChan: make(chan string, logBufferSize)}
}

// start launches bin with args in dir. Only one instance may run at a time;
// call stop first to replace it.
func (p *procSupervisor) start(bin string, args []string, dir string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cmd != nil {
		return errors.New("openvpn: process already running")
	}

	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	// New process group so stop() can signal the whole group (openvpn does
	// not fork further children in server mode, but this keeps the signal
	// semantics consistent with how vpn-ui manages the same binary).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", bin, err)
	}

	p.cmd = cmd
	p.done = make(chan struct{})
	done := p.done
	logChan := p.logChan

	go pipeLines(stdout, logChan)
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	return nil
}

func pipeLines(r io.Reader, out chan<- string) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for scanner.Scan() {
		select {
		case out <- scanner.Text():
		default:
			// Drop the line rather than block the process on a full/unread channel.
		}
	}
}

// running reports whether the child process is still alive.
func (p *procSupervisor) running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// stop sends SIGTERM, waits up to 5s, then SIGKILLs the process group.
// Always clears p.cmd so a subsequent start() is allowed.
func (p *procSupervisor) stop() error {
	p.mu.Lock()
	cmd := p.cmd
	done := p.done
	p.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		p.mu.Lock()
		p.cmd = nil
		p.mu.Unlock()
		return nil
	}

	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}

	p.mu.Lock()
	p.cmd = nil
	p.mu.Unlock()
	return nil
}

// pid returns the current child PID, or 0 if not running.
func (p *procSupervisor) pid() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}
