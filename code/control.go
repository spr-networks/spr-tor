package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Minimal tor control-port client (control-spec.txt), unix socket + cookie
// auth only. A fresh connection is made per request; the plugin is the only
// consumer and requests are rare.

type ControlClient struct {
	SocketPath string
	CookiePath string
}

type controlConn struct {
	conn net.Conn
	r    *bufio.Reader
}

// reply is one complete control-port reply: the final status code plus every
// payload line (from "-", "+" and the final " " line).
type reply struct {
	code  int
	lines []string
}

func (c *ControlClient) connect() (*controlConn, error) {
	cookie, err := os.ReadFile(c.CookiePath)
	if err != nil {
		return nil, fmt.Errorf("reading control auth cookie: %w", err)
	}
	conn, err := net.DialTimeout("unix", c.SocketPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	cc := &controlConn{conn: conn, r: bufio.NewReader(conn)}
	if _, err := cc.cmd("AUTHENTICATE " + hex.EncodeToString(cookie)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("control auth failed: %w", err)
	}
	return cc, nil
}

func (cc *controlConn) Close() {
	fmt.Fprintf(cc.conn, "QUIT\r\n")
	cc.conn.Close()
}

// cmd sends one command and reads the full reply, failing on non-250 codes.
func (cc *controlConn) cmd(command string) (*reply, error) {
	cc.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(cc.conn, "%s\r\n", command); err != nil {
		return nil, err
	}
	rep := &reply{}
	for {
		line, err := cc.r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			return nil, fmt.Errorf("short control reply %q", line)
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return nil, fmt.Errorf("bad control reply %q", line)
		}
		rep.code = code
		sep, rest := line[3], line[4:]
		switch sep {
		case '-':
			rep.lines = append(rep.lines, rest)
		case '+':
			// multiline data block, terminated by "." on its own line
			data := []string{rest}
			for {
				dline, err := cc.r.ReadString('\n')
				if err != nil {
					return nil, err
				}
				dline = strings.TrimRight(dline, "\r\n")
				if dline == "." {
					break
				}
				data = append(data, strings.TrimPrefix(dline, ".."))
			}
			rep.lines = append(rep.lines, strings.Join(data, "\n"))
		case ' ':
			if rest != "OK" {
				rep.lines = append(rep.lines, rest)
			}
			if code != 250 {
				return rep, fmt.Errorf("control error %d %s", code, rest)
			}
			return rep, nil
		default:
			return nil, fmt.Errorf("bad control reply %q", line)
		}
	}
}

// GetInfo issues GETINFO for the given keys and returns key -> value.
func (c *ControlClient) GetInfo(keys ...string) (map[string]string, error) {
	cc, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer cc.Close()

	rep, err := cc.cmd("GETINFO " + strings.Join(keys, " "))
	if err != nil {
		return nil, err
	}
	return parseGetInfoLines(rep.lines), nil
}

var allowedSignals = map[string]bool{"NEWNYM": true, "RELOAD": true}

// Signal sends an allow-listed signal (NEWNYM, RELOAD) to tor.
func (c *ControlClient) Signal(sig string) error {
	if !allowedSignals[sig] {
		return fmt.Errorf("signal %q not allowed", sig)
	}
	cc, err := c.connect()
	if err != nil {
		return err
	}
	defer cc.Close()
	_, err = cc.cmd("SIGNAL " + sig)
	return err
}

// ---- pure parsing helpers (unit tested) ----

func parseGetInfoLines(lines []string) map[string]string {
	info := map[string]string{}
	for _, l := range lines {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		info[k] = strings.TrimSpace(v)
	}
	return info
}

// parseBootstrapPhase parses a status/bootstrap-phase value like:
//
//	NOTICE BOOTSTRAP PROGRESS=85 TAG=ap_conn SUMMARY="Connecting to a relay..."
func parseBootstrapPhase(s string) (progress int, summary string) {
	for _, f := range strings.Fields(s) {
		if v, ok := strings.CutPrefix(f, "PROGRESS="); ok {
			if p, err := strconv.Atoi(v); err == nil {
				progress = p
			}
		}
	}
	if i := strings.Index(s, "SUMMARY=\""); i >= 0 {
		rest := s[i+len("SUMMARY=\""):]
		if j := strings.Index(rest, "\""); j >= 0 {
			summary = rest[:j]
		}
	}
	return
}

type Circuit struct {
	ID          string
	Status      string
	Path        []string
	BuildFlags  []string
	Purpose     string
	TimeCreated string
}

// parseCircuitStatus parses a GETINFO circuit-status data block, one circuit
// per line:
//
//	<id> <status> [$FP~nick,$FP~nick,...] [BUILD_FLAGS=..] [PURPOSE=..] [TIME_CREATED=..]
func parseCircuitStatus(data string) []Circuit {
	circuits := []Circuit{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		c := Circuit{ID: fields[0], Status: fields[1], Path: []string{}}
		for _, f := range fields[2:] {
			switch {
			case strings.HasPrefix(f, "$"):
				for _, hop := range strings.Split(f, ",") {
					if _, nick, ok := strings.Cut(hop, "~"); ok {
						c.Path = append(c.Path, nick)
					} else {
						c.Path = append(c.Path, strings.TrimPrefix(hop, "$"))
					}
				}
			case strings.HasPrefix(f, "BUILD_FLAGS="):
				c.BuildFlags = strings.Split(strings.TrimPrefix(f, "BUILD_FLAGS="), ",")
			case strings.HasPrefix(f, "PURPOSE="):
				c.Purpose = strings.TrimPrefix(f, "PURPOSE=")
			case strings.HasPrefix(f, "TIME_CREATED="):
				c.TimeCreated = strings.TrimPrefix(f, "TIME_CREATED=")
			}
		}
		circuits = append(circuits, c)
	}
	return circuits
}
