package openvpn

import (
	"context"

	"github.com/pasarguard/node/common"
)

// setUsersLocked rebuilds o.users/o.emailByUser from the panel's user list.
// Callers must hold o.mu (or call this only before o is shared, as New does).
// Users without an OpenVPN proxy entry (i.e. not provisioned on this
// backend) are silently skipped — the same convention xray/wireguard use for
// users that don't apply to them.
func (o *OpenVpn) setUsersLocked(users []*common.User) {
	stored := make([]storedUser, 0, len(users))
	emailByUser := make(map[string]string, len(users))
	for _, u := range users {
		if u == nil || u.GetProxies() == nil || u.GetProxies().GetOpenvpn() == nil {
			continue
		}
		ov := u.GetProxies().GetOpenvpn()
		if ov.GetUsername() == "" {
			continue
		}
		stored = append(stored, storedUser{Username: ov.GetUsername(), Password: ov.GetPassword()})
		emailByUser[ov.GetUsername()] = u.GetEmail()
	}
	o.users = stored
	o.emailByUser = emailByUser
}

// SyncUser adds or updates a single user's credentials on disk. No restart:
// auth-user-pass-verify re-reads the file on every connection attempt, so a
// credential change takes effect on the client's next connect without
// disturbing anyone already connected.
func (o *OpenVpn) SyncUser(_ context.Context, user *common.User) error {
	return o.UpdateUsers(context.Background(), []*common.User{user})
}

// SyncUsers replaces the entire account list.
func (o *OpenVpn) SyncUsers(_ context.Context, users []*common.User) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.setUsersLocked(users)
	return writeUsersFile(o.dir, o.users)
}

// UpdateUsers merges the given users into the current list (add/update by
// username; a user with no OpenVPN proxy entry is treated as "remove this
// account" if it was previously present, mirroring xray/wireguard semantics
// for a user that no longer applies to this backend).
func (o *OpenVpn) UpdateUsers(_ context.Context, users []*common.User) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	byUsername := make(map[string]storedUser, len(o.users))
	for _, u := range o.users {
		byUsername[u.Username] = u
	}
	emailByUser := o.emailByUser
	if emailByUser == nil {
		emailByUser = map[string]string{}
	}

	for _, u := range users {
		if u == nil {
			continue
		}
		ov := u.GetProxies().GetOpenvpn()
		if ov == nil || ov.GetUsername() == "" {
			// This user no longer has an OpenVPN entry: drop any stored
			// credential under their previous username, found by email.
			for name, email := range emailByUser {
				if email == u.GetEmail() {
					delete(byUsername, name)
					delete(emailByUser, name)
				}
			}
			continue
		}
		byUsername[ov.GetUsername()] = storedUser{Username: ov.GetUsername(), Password: ov.GetPassword()}
		emailByUser[ov.GetUsername()] = u.GetEmail()
	}

	merged := make([]storedUser, 0, len(byUsername))
	for _, u := range byUsername {
		merged = append(merged, u)
	}
	o.users = merged
	o.emailByUser = emailByUser

	return writeUsersFile(o.dir, o.users)
}

// UpdateUsersAndRestart updates users, then bounces the OpenVPN process so
// any server-wide settings that only apply on (re)start are reapplied. Not
// strictly required for credentials alone (see UpdateUsers), but the Backend
// interface contract expects a restart here, matching wireguard's behavior.
func (o *OpenVpn) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	if err := o.UpdateUsers(ctx, users); err != nil {
		return err
	}
	return o.Restart()
}
