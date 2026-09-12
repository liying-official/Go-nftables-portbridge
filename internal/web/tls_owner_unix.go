//go:build !windows

package web

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func validateTLSKeyOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine web TLS private key owner")
	}
	euid := uint32(os.Geteuid()) // #nosec G115 -- Unix effective UIDs use the same unsigned 32-bit representation here.
	if stat.Uid != 0 && stat.Uid != euid {
		// Installation preflight runs as root, while an existing valid key
		// can be owned by the service account rather than root.
		if euid == 0 {
			if account, err := user.Lookup("portbridge"); err == nil && account.Uid == strconv.FormatUint(uint64(stat.Uid), 10) {
				return nil
			}
		}
		return fmt.Errorf("web TLS private key must be owned by root or the service account")
	}
	return nil
}
