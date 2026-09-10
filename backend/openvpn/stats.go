package openvpn

import (
	"bufio"
	"context"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
)

const onlineActivityThreshold = 45 * time.Second

func (o *OpenVpn) runStatsLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-o.updateTicker.C:
			o.updateStatsFromStatusFile()
		}
	}
}

// updateStatsFromStatusFile parses the OpenVPN status-version 3 log (written
// every 5s per the `status` directive) and feeds per-user samples into the
// shared stats.Tracker, keyed by username (== Common Name, thanks to
// username-as-common-name).
//
// NOTE: field positions are read from the log's own HEADER line rather than
// hardcoded, to tolerate minor version differences in status-version 3's
// column set. This has not been exercised against a live openvpn process in
// this environment — verify the parsed byte counts look sane against `cat
// status.log` on a real box before trusting GetStats in production.
func (o *OpenVpn) updateStatsFromStatusFile() {
	f, err := os.Open(o.statusPath())
	if err != nil {
		return // not started yet / no clients connected yet
	}
	defer f.Close()

	var fieldIndex map[string]int
	var samples []stats.Sample

	o.mu.RLock()
	emailByUser := o.emailByUser
	o.mu.RUnlock()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "HEADER":
			if len(fields) > 1 && fields[1] == "CLIENT_LIST" {
				fieldIndex = map[string]int{}
				for i, name := range fields[2:] {
					fieldIndex[name] = i + 2
				}
			}
		case "CLIENT_LIST":
			if fieldIndex == nil {
				continue // saw a row before its header; skip rather than guess positions
			}
			username := fieldAt(fields, fieldIndex, "Common Name")
			if username == "" {
				continue
			}
			rx := parseInt64(fieldAt(fields, fieldIndex, "Bytes Received"))
			tx := parseInt64(fieldAt(fields, fieldIndex, "Bytes Sent"))
			endpoint := fieldAt(fields, fieldIndex, "Real Address")
			if idx := strings.LastIndex(endpoint, ":"); idx > 0 {
				endpoint = endpoint[:idx] // strip the port, Sample.EndpointIP wants the IP
			}
			samples = append(samples, stats.Sample{
				PublicKey:  username,
				Email:      emailByUser[username],
				Rx:         rx,
				Tx:         tx,
				EndpointIP: endpoint,
			})
		}
	}

	if len(samples) > 0 {
		o.statsTracker.UpdateStatsBatch(samples)
	}
}

func fieldAt(fields []string, index map[string]int, name string) string {
	i, ok := index[name]
	if !ok || i >= len(fields) {
		return ""
	}
	return fields[i]
}

func parseInt64(s string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return v
}

func (o *OpenVpn) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}

	switch request.GetType() {
	case common.StatType_UserStat:
		return o.statsTracker.GetStats(ctx, []string{request.GetName()}, request.GetReset_()), nil
	case common.StatType_UsersStat:
		return o.statsTracker.GetUsersStats(ctx, request.GetReset_()), nil
	case common.StatType_Outbound, common.StatType_Outbounds, common.StatType_Inbound, common.StatType_Inbounds:
		return nil, errors.New("interface-level stats not implemented yet for openvpn")
	default:
		return nil, errors.New("unsupported stat type")
	}
}

func (o *OpenVpn) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	username := o.usernameForEmail(email)
	if username == "" {
		return &common.OnlineStatResponse{Name: email, Value: 0}, nil
	}
	if o.statsTracker.AnyActiveSince([]string{username}, time.Now().Add(-onlineActivityThreshold)) {
		return &common.OnlineStatResponse{Name: email, Value: 1}, nil
	}
	return &common.OnlineStatResponse{Name: email, Value: 0}, nil
}

func (o *OpenVpn) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}
	resp := &common.StatsOnlineIpListResponse{Name: email, Ips: map[string]int64{}}
	username := o.usernameForEmail(email)
	if username == "" {
		return resp, nil
	}
	for k, v := range o.statsTracker.EndpointActivity([]string{username}) {
		resp.Ips[k] = v
	}
	return resp, nil
}

func (o *OpenVpn) usernameForEmail(email string) string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	for username, e := range o.emailByUser {
		if e == email {
			return username
		}
	}
	return ""
}

// GetOutboundsLatency is not applicable to OpenVPN (there is no
// xray-style outbound graph here) — matches wireguard's "not applicable"
// stance rather than the RoutingBackend behavior, which only xray implements.
func (o *OpenVpn) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	return nil, errors.New("outbound latency not applicable for openvpn")
}

func (o *OpenVpn) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	if !o.Started() {
		return nil, errNotStarted
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	o.mu.RLock()
	uptime := time.Since(o.startTime)
	o.mu.RUnlock()

	return &common.BackendStatsResponse{
		NumGoroutine: uint32(runtime.NumGoroutine()),
		NumGc:        mem.NumGC,
		Alloc:        mem.Alloc,
		TotalAlloc:   mem.TotalAlloc,
		Sys:          mem.Sys,
		Mallocs:      mem.Mallocs,
		Frees:        mem.Frees,
		LiveObjects:  mem.Mallocs - mem.Frees,
		PauseTotalNs: mem.PauseTotalNs,
		Uptime:       uint32(uptime.Seconds()),
	}, nil
}
