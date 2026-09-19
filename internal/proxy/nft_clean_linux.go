package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// This deliberately is not an alternative nft/conntrack backend. It can only
// prove an EMPTY, unfiltered nftables and conntrack inventory. It has no write,
// delete, attribute interpreter, executable override, or assume-clean switch.
// Any object, partial dump, unavailable subsystem or permission error is Unknown.
func verifyEmptyNetfilter() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	leader, err := os.Readlink("/proc/self/ns/net")
	if err != nil || before != leader {
		return errors.New("network namespace identity cannot be verified")
	}
	deadline := time.Now().Add(2 * time.Second)
	// Repeat the table inventory around the conntrack inventory. This is a
	// bounded observation, not protection against a concurrent privileged writer.
	for _, kind := range []uint16{0x0a01, 0x0101, 0x0a01} { // NFT_GETTABLE / CT_GET, nfgen_family=UNSPEC
		if err := emptyNetfilterDump(kind, deadline); err != nil {
			return fmt.Errorf("kernel state is not proven empty: %w", err)
		}
	}
	after, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil || after != before {
		return errors.New("network namespace changed during empty-state verification")
	}
	return nil
}

func emptyNetfilterDump(kind uint16, deadline time.Time) error {
	if kind != 0x0a01 && kind != 0x0101 {
		return errors.New("unsupported read-only netfilter query")
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	addr, err := unix.Getsockname(fd)
	if err != nil {
		return err
	}
	local, ok := addr.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 {
		return errors.New("invalid netlink port identity")
	}
	const seq uint32 = 1 // private new socket, no multicast subscriptions
	request := make([]byte, 20)
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], kind)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:], seq)
	binary.NativeEndian.PutUint32(request[12:], local.Pid)
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 64<<10)
	for attempts := 0; attempts < 64; attempts++ {
		left := time.Until(deadline)
		if left <= 0 {
			return errors.New("empty-state verification deadline exceeded")
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		count, err := unix.Poll(poll, int((left+time.Millisecond-1)/time.Millisecond))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return errors.New("empty-state verification timed out")
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("netlink dump socket failed")
		}
		size, _, flags, from, err := unix.Recvmsg(fd, buf, nil, 0)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || sender.Groups != 0 || flags&unix.MSG_TRUNC != 0 {
			return errors.New("untrusted or truncated netfilter dump")
		}
		done, err := emptyNetfilterReply(buf[:size], seq, local.Pid)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return errors.New("empty-state verification retry bound exceeded")
}

func emptyNetfilterReply(data []byte, seq, port uint32) (bool, error) {
	// A truly empty dump is exactly one successful NLMSG_DONE. In particular,
	// an ACK, ENOENT, DUMP_INTR, filtered dump or missing DONE is never emptiness.
	if len(data) != 20 {
		return false, errors.New("netfilter inventory is nonempty or incomplete")
	}
	size := binary.NativeEndian.Uint32(data)
	kind := binary.NativeEndian.Uint16(data[4:])
	flags := binary.NativeEndian.Uint16(data[6:])
	if size != 20 || binary.NativeEndian.Uint32(data[8:]) != seq || binary.NativeEndian.Uint32(data[12:]) != port || flags != unix.NLM_F_MULTI {
		return false, errors.New("invalid or interrupted netfilter dump completion")
	}
	if kind != unix.NLMSG_DONE || int32(binary.NativeEndian.Uint32(data[16:])) != 0 {
		return false, errors.New("netfilter dump did not complete successfully")
	}
	return true, nil
}
