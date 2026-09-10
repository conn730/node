package openvpn

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// The OpenVPN server authenticates each connecting client by shelling out to
// `pasarguard-node openvpn-auth <dir>` (see cmd/node's dispatch and
// --auth-user-pass-verify ... via-file) as a FRESH process for every login
// attempt. That process has no access to this backend's in-memory maps, so
// credentials live on disk instead — this is the same trick vpn-ui's OpenVPN
// service uses (it shells back into its own panel binary for the same
// reason). SyncUsers/SyncUser below keep this file in sync with the panel's
// user list; CheckAuth (called from the hook subcommand) re-reads it fresh
// on every call, so there is nothing to keep "warm" or invalidate.

type storedUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func usersFilePath(dir string) string { return filepath.Join(dir, "users.json") }

// writeUsersFile atomically replaces the on-disk credential file (write to a
// temp file, then rename — rename is atomic on the same filesystem, so a
// concurrently-starting auth hook never observes a half-written file).
func writeUsersFile(dir string, users []storedUser) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(users)
	if err != nil {
		return err
	}
	path := usersFilePath(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readUsersFile(dir string) ([]storedUser, error) {
	data, err := os.ReadFile(usersFilePath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var users []storedUser
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// CheckAuth reports whether username/password matches an enabled account in
// dir's credential file. Exported for cmd/node's openvpn-auth subcommand.
func CheckAuth(dir, username, password string) bool {
	users, err := readUsersFile(dir)
	if err != nil {
		return false
	}
	for _, u := range users {
		if u.Username == username {
			return u.Password == password
		}
	}
	return false
}
