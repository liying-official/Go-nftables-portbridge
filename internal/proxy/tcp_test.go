package proxy

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"portbridge/internal/config"
)

type trackingReaderFromConn struct {
	net.Conn
	called bool
}

func (c *trackingReaderFromConn) ReadFrom(r io.Reader) (int64, error) {
	c.called = true
	return io.Copy(io.Discard, r)
}

func TestCopyTCPStreamPrefersReaderFrom(t *testing.T) {
	source, sourceWriter := net.Pipe()
	destination, destinationPeer := net.Pipe()
	defer source.Close()
	defer destination.Close()
	defer destinationPeer.Close()

	payload := bytes.Repeat([]byte("portbridge-fast-path"), 1024)
	go func() {
		_, _ = sourceWriter.Write(payload)
		_ = sourceWriter.Close()
	}()

	tracked := &trackingReaderFromConn{Conn: destination}
	n, err := copyTCPStream(tracked, source)
	if err != nil {
		t.Fatal(err)
	}
	if !tracked.called {
		t.Fatal("ReaderFrom fast path was not used")
	}
	if n != int64(len(payload)) {
		t.Fatalf("copied %d bytes, want %d", n, len(payload))
	}
}

func TestCopyTCPStreamBufferedFallback(t *testing.T) {
	source, sourceWriter := net.Pipe()
	destination, destinationPeer := net.Pipe()
	defer source.Close()
	defer destinationPeer.Close()

	payload := bytes.Repeat([]byte("portbridge-buffered-path"), 1024)
	copyDone := make(chan error, 1)
	go func() {
		_, err := copyTCPStream(destination, source)
		_ = destination.Close()
		copyDone <- err
	}()
	go func() {
		_, _ = sourceWriter.Write(payload)
		_ = sourceWriter.Close()
	}()

	got, err := io.ReadAll(destinationPeer)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-copyDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("copied payload differs: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestTCPProxyPreservesHalfClose(t *testing.T) {
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network unavailable: %v", err)
	}
	defer targetListener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		request, readErr := io.ReadAll(conn)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		_, writeErr := conn.Write(append([]byte("ack:"), request...))
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		serverDone <- writeErr
	}()

	targetAddress := targetListener.Addr().(*net.TCPAddr)
	proxyPort := freeTCPPort(t, "tcp4", "127.0.0.1:0")
	rule := config.NormalizeRule(config.Rule{
		ID: "half-close", Name: "half-close", Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: proxyPort,
		TargetHost: "127.0.0.1", TargetPort: targetAddress.Port, Enabled: true,
	})
	runner := newRunner(rule, &Stats{}, testLogger())
	if err := runner.start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer runner.stop()

	clientConn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := clientConn.(*net.TCPConn)
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))

	payload := []byte("request-needs-eof")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("ack:"), payload...)
	if !bytes.Equal(response, want) {
		t.Fatalf("response %q, want %q", response, want)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
