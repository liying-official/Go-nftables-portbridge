package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const maxNFTOutputBytes = 16 << 20

// Typed private operations permit fault injection without introducing a
// configurable executable, shell command, or management API command entrypoint.
type nftKernelIO interface {
	Tables() ([]byte, error)
	Chains() ([]byte, error)
	Table() ([]byte, error)
	Apply(script string) ([]byte, error)
}

type nftCommandIO struct {
	binary  string
	initErr error
}

func (k *nftCommandIO) Tables() ([]byte, error) {
	return k.command(5*time.Second, "", "-j", "list", "tables")
}
func (k *nftCommandIO) Chains() ([]byte, error) {
	return k.command(5*time.Second, "", "-j", "list", "chains")
}

func (k *nftCommandIO) Ruleset() ([]byte, error) {
	return k.command(5*time.Second, "", "-j", "list", "ruleset")
}

func (k *nftCommandIO) Table() ([]byte, error) {
	return k.command(5*time.Second, "", "-j", "list", "table", "inet", nftTableName)
}
func (k *nftCommandIO) Apply(script string) ([]byte, error) {
	return k.command(10*time.Second, script, "-f", "-")
}

type nftBoundedOutput struct {
	buffer bytes.Buffer
	limit  int
}

var errNFTOutputLimit = errors.New("nftables output exceeds the bounded inspection limit")

func (b *nftBoundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errNFTOutputLimit
	}
	return b.buffer.Write(p)
}

func (b *nftBoundedOutput) Len() int      { return b.buffer.Len() }
func (b *nftBoundedOutput) Bytes() []byte { return b.buffer.Bytes() }

func (k *nftCommandIO) command(timeout time.Duration, input string, args ...string) ([]byte, error) {
	if k.initErr != nil {
		return nil, k.initErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, k.binary, args...) // #nosec G204 -- fixed trusted binary and private fixed operation arguments.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdin = bytes.NewBufferString(input)
	out := nftBoundedOutput{limit: maxNFTOutputBytes}
	errOut := nftBoundedOutput{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("nftables operation: %w", ctx.Err())
		}
		// Do not copy arbitrary kernel rule/connection output into public logs.
		return nil, fmt.Errorf("nftables operation failed: %w", err)
	}
	return out.Bytes(), nil
}
