# This fork's own conventions

This file only applies to `conn730/node` (and its sibling `conn730/panel`) —
it is not part of upstream PasarGuard and should never be merged upstream.

## Why this file exists

We add protocols upstream PasarGuard doesn't have (OpenVPN first, then
L2TP/PPTP/etc.) while still pulling in upstream's own updates regularly.
Every rule below exists to keep that merge cheap.

## Rules for anything we add here

1. **New code goes in new files/packages.** A new protocol gets its own
   `backend/<protocol>/` package. Never grow an existing upstream file to add
   our functionality — a new file can never conflict with an upstream change
   to a file it doesn't touch; an edited shared file can.

2. **Touching an existing upstream file is sometimes unavoidable** (wiring a
   new `BackendType` into `controller.go`'s switch, for instance). Keep that
   touch to the smallest possible diff, and mark it:
   ```go
   // CUSTOM: not upstream. See CONTRIBUTING-custom.md.
   ```
   so `grep -rn "CUSTOM: not upstream" .` always finds every place upstream
   and our fork share a file.

3. **Reserve a high number range for our own enum values.** `BackendType`
   values we add start at `1000` (`OPENVPN = 1000`), not `2`. If upstream
   adds its own next backend (their roadmap already hints at `MTPROTO`/
   `SINGBOX`), it gets `2` or `3` without ever colliding with ours. Same rule
   for any new `Proxy` field number we add.

4. **Merge upstream often, not eventually.** Small, regular merges
   (`git fetch upstream && git merge upstream/main`, weekly-ish) stay
   resolvable. A merge left for months turns into the `vpn-ui` vs. `3x-ui`
   situation this fork exists to avoid — two codebases that no longer share
   enough history to merge at all. Tag every successful merge
   (`git tag sync-YYYY-MM-DD`) so there's always a known-good point to fall
   back to.

5. **Prefer upstreaming the hook, not the feature.** If a limitation in
   upstream is what's forcing a bigger touch than rule 2 allows for (the
   current example: a node can only run one `Backend` at a time — see the
   note in `controller.go`), consider proposing that flexibility as a PR to
   `PasarGuard/node` itself instead of working around it here. A hook
   upstream maintains needs no re-applying after every sync; a workaround we
   maintain does.

## Current custom additions

| Area | What | Where |
|---|---|---|
| Node | OpenVPN backend (v1: single transport, username/password auth, no TPROXY-into-Xray yet — see the package doc in `backend/openvpn/config.go`) | `backend/openvpn/`, plus the marked touches in `controller/controller.go` and `cmd/node/main.go` |

Known follow-ups, roughly in the order we'll tackle them: TCP+UDP dual
transport, per-account device limits, TPROXY routing through Xray (matching
what `vpn-ui` does today), then the next protocol (L2TP).
