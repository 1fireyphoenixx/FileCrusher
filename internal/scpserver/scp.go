package scpserver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"filecrusher/internal/fsutil"
)

const (
	ackOK    byte = 0
	ackError byte = 1
	ackFatal byte = 2
)

func CanHandle(cmd string) bool {
	op, _, err := parseCommand(cmd)
	return err == nil && (op == "-t" || op == "-f")
}

// HandleExec handles a minimal subset of SCP over an SSH exec channel.
// Supported:
// - scp -t <path> (upload to server)
// - scp -f <path> (download from server)
// Optional flags: -p (ignored)
// Not supported: -r (recursive)
func HandleExec(ch io.ReadWriter, userRoot string, cmd string) error {
	op, target, err := parseCommand(cmd)
	if err != nil {
		return err
	}
	switch op {
	case "-t":
		return handleSink(ch, userRoot, target)
	case "-f":
		return handleSource(ch, userRoot, target)
	default:
		return errors.New("unsupported scp mode")
	}
}

func parseCommand(cmd string) (op string, target string, err error) {
	fields := strings.Fields(cmd)
	if len(fields) < 3 {
		return "", "", errors.New("invalid scp command")
	}
	if fields[0] != "scp" {
		return "", "", errors.New("not scp")
	}
	// Typical: scp -t <path> or scp -f <path>
	// Some clients may include -p.
	seenP := false
	seenR := false
	for i := 1; i < len(fields)-1; i++ {
		s := fields[i]
		if s == "-p" {
			seenP = true
			_ = seenP
			continue
		}
		if s == "-r" {
			seenR = true
			break
		}
		if s == "-t" || s == "-f" {
			op = s
			continue
		}
		// Unknown flag
		if strings.HasPrefix(s, "-") {
			return "", "", errors.New("unsupported scp flags")
		}
	}
	if seenR {
		return "", "", errors.New("recursive scp not supported")
	}
	if op == "" {
		return "", "", errors.New("missing scp mode")
	}
	target = fields[len(fields)-1]
	if target == "" {
		return "", "", errors.New("missing scp path")
	}
	return op, target, nil
}

func handleSink(rw io.ReadWriter, root, target string) error {
	// Initial OK.
	if err := writeAck(rw, ackOK, ""); err != nil {
		return err
	}

	baseLocal, err := fsutil.ResolveWithinRoot(root, target)
	if err != nil {
		_ = writeAck(rw, ackFatal, "invalid path")
		return err
	}
	baseIsDir := false
	if st, err := os.Stat(baseLocal); err == nil && st.IsDir() {
		baseIsDir = true
	}

	br := bufio.NewReader(rw)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		line = strings.TrimRight(line, "\n")
		if line == "" {
			continue
		}

		switch line[0] {
		case 'T':
			// Timestamp: ignore.
			if err := writeAck(rw, ackOK, ""); err != nil {
				return err
			}
			continue
		case 'C':
			mode, size, name, err := parseCLine(line)
			if err != nil {
				_ = writeAck(rw, ackFatal, "bad file header")
				return err
			}
			if hasPathSep(name) {
				_ = writeAck(rw, ackFatal, "invalid filename")
				return errors.New("invalid filename")
			}

			// OK to send file.
			if err := writeAck(rw, ackOK, ""); err != nil {
				return err
			}

			dst := baseLocal
			if baseIsDir {
				dst = filepath.Join(baseLocal, name)
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				_ = writeAck(rw, ackFatal, "mkdir failed")
				return err
			}
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				_ = writeAck(rw, ackFatal, "open failed")
				return err
			}
			_, copyErr := io.CopyN(f, br, size)
			_ = f.Close()
			if copyErr != nil {
				_ = writeAck(rw, ackFatal, "write failed")
				return copyErr
			}
			if err := chmodBestEffort(dst, mode); err != nil {
				// ignore
			}

			b, err := br.ReadByte()
			if err != nil {
				return err
			}
			if b != ackOK {
				return errors.New("unexpected scp terminator")
			}
			if err := writeAck(rw, ackOK, ""); err != nil {
				return err
			}
			continue
		default:
			_ = writeAck(rw, ackFatal, "unsupported")
			return errors.New("unsupported scp command")
		}
	}
}

func handleSource(rw io.ReadWriter, root, target string) error {
	br := bufio.NewReader(rw)
	if err := readAck(br); err != nil {
		return err
	}

	local, err := fsutil.ResolveWithinRoot(root, target)
	if err != nil {
		_ = writeAck(rw, ackFatal, "invalid path")
		return err
	}
	st, err := os.Stat(local)
	if err != nil || st.IsDir() {
		_ = writeAck(rw, ackFatal, "not found")
		return errors.New("not found")
	}

	name := filepath.Base(local)
	mode := st.Mode() & 0o777
	if _, err := fmt.Fprintf(rw, "C%04o %d %s\n", mode, st.Size(), name); err != nil {
		return err
	}
	if err := readAck(br); err != nil {
		return err
	}

	f, err := os.Open(local)
	if err != nil {
		return err
	}
	_, err = io.Copy(rw, f)
	_ = f.Close()
	if err != nil {
		return err
	}
	if err := writeAck(rw, ackOK, ""); err != nil {
		return err
	}
	return readAck(br)
}

func parseCLine(line string) (mode os.FileMode, size int64, name string, err error) {
	// C<mode> <size> <name>
	if len(line) < 2 || line[0] != 'C' {
		return 0, 0, "", errors.New("bad C line")
	}
	parts := strings.SplitN(line[1:], " ", 3)
	if len(parts) != 3 {
		return 0, 0, "", errors.New("bad C line")
	}
	m, err := strconv.ParseUint(parts[0], 8, 32)
	if err != nil {
		return 0, 0, "", err
	}
	sz, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || sz < 0 {
		return 0, 0, "", errors.New("bad size")
	}
	name = strings.TrimSpace(parts[2])
	if name == "" {
		return 0, 0, "", errors.New("bad name")
	}
	return os.FileMode(m), sz, name, nil
}

func readAck(r *bufio.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	if b == ackOK {
		return nil
	}
	// Try to read message line.
	msg, _ := r.ReadString('\n')
	msg = strings.TrimSpace(msg)
	if b == ackError || b == ackFatal {
		if msg != "" {
			return errors.New(msg)
		}
		return errors.New("scp error")
	}
	return errors.New("invalid scp ack")
}

func writeAck(w io.Writer, code byte, msg string) error {
	if code == ackOK {
		_, err := w.Write([]byte{ackOK})
		return err
	}
	if msg == "" {
		msg = "error"
	}
	_, err := w.Write(append([]byte{code}, append([]byte(msg), '\n')...))
	return err
}

func hasPathSep(name string) bool {
	return strings.ContainsAny(name, "/\\")
}

func chmodBestEffort(path string, mode os.FileMode) error {
	if mode == 0 {
		return nil
	}
	return os.Chmod(path, mode)
}
