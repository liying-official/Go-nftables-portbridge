//go:build windows

package web

import "os"

func validateTLSKeyOwner(_ os.FileInfo) error { return nil }
