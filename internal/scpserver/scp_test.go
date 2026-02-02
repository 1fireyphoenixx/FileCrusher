// Package scpserver tests validate basic SCP upload/download flows.
package scpserver

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSCPUploadSink verifies scp -t upload handling.
func TestSCPUploadSink(t *testing.T) {
	root := t.TempDir()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- HandleExec(server, root, "scp -t /") }()

	br := bufio.NewReader(client)
	// initial ack
	if b, err := br.ReadByte(); err != nil || b != 0 {
		t.Fatalf("initial ack: %v %v", b, err)
	}
	_, _ = client.Write([]byte("C0644 5 hello.txt\n"))
	if b, err := br.ReadByte(); err != nil || b != 0 {
		t.Fatalf("ack header: %v %v", b, err)
	}
	_, _ = client.Write([]byte("hello"))
	_, _ = client.Write([]byte{0})
	if b, err := br.ReadByte(); err != nil || b != 0 {
		t.Fatalf("ack file: %v %v", b, err)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(root, "hello.txt"))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(b) != "hello" {
		t.Fatalf("unexpected contents: %q", string(b))
	}
}

// TestSCPDownloadSource verifies scp -f download handling.
func TestSCPDownloadSource(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("abc"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- HandleExec(server, root, "scp -f /a.txt") }()

	// initial ok to start
	_, _ = client.Write([]byte{0})
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if !strings.HasPrefix(line, "C") {
		t.Fatalf("bad header: %q", line)
	}
	_, _ = client.Write([]byte{0})

	// parse size
	parts := strings.SplitN(strings.TrimSpace(line[1:]), " ", 3)
	if len(parts) != 3 {
		t.Fatalf("bad header: %q", line)
	}
	sz := 0
	for _, ch := range parts[1] {
		if ch < '0' || ch > '9' {
			t.Fatalf("bad size: %q", parts[1])
		}
		sz = sz*10 + int(ch-'0')
	}

	buf := make([]byte, sz)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read body: %v", err)
	}
	term, err := br.ReadByte()
	if err != nil || term != 0 {
		t.Fatalf("term: %v %v", term, err)
	}
	_, _ = client.Write([]byte{0})
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
	if !bytes.Equal(buf, []byte("abc")) {
		t.Fatalf("unexpected body: %q", string(buf))
	}
}
