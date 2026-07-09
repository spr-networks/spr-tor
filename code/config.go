package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Config is the full, user-editable plugin configuration. It is the ONLY
// source for the generated torrc: users can never inject raw torrc lines,
// every field is validated before it is written anywhere.
type Config struct {
	// TransPortEnabled opens a transparent proxy port (container-IP:9040)
	// so SPR devices/groups can be routed through tor. Off by default.
	TransPortEnabled bool
	// DNSPortEnabled opens a DNS resolver port (container-IP:9053) that
	// resolves through tor. Off by default.
	DNSPortEnabled bool
	// ExitCountry restricts exit relays to a 2-letter country code
	// (ISO 3166-1 alpha-2, e.g. "us", "de"). Empty = no restriction.
	ExitCountry string
	// UseBridges enables the bridge lines below.
	UseBridges bool
	// Bridges are plain or obfs4 bridge lines, strictly format-validated.
	Bridges []string
	// SocksPolicy is a list of "accept <addr>[/<mask>]" / "reject ..."
	// entries applied to the SocksPort. Empty = tor default (accept all
	// that can reach the port; reachability is already gated by the
	// docker bridge + SPR firewall groups).
	SocksPolicy []string
	// SafeSocks makes tor reject SOCKS requests that leak DNS (i.e.
	// connections made by IP-resolved-locally). Off by default because it
	// breaks many apps; see README.
	SafeSocks bool
}

var TEST_PREFIX = os.Getenv("TEST_PREFIX")

var (
	ConfigFile = TEST_PREFIX + "/configs/spr-tor/config.json"
	TorrcPath  = TEST_PREFIX + "/state/plugins/spr-tor/torrc"
)

// container-internal paths written literally into torrc
const (
	TorDataDir       = "/state/plugins/spr-tor/tor"
	TorControlSocket = "/run/tor/control.sock"
	TorCookieFile    = "/run/tor/control.authcookie"
	TorGeoIPFile     = "/usr/share/tor/geoip"
	TorGeoIPv6File   = "/usr/share/tor/geoip6"
	Obfs4ProxyBinary = "/usr/bin/obfs4proxy"
	TorSocksPortNum  = 9050
	TorTransPortNum  = 9040
	TorDNSPortNum    = 9053
	maxBridges       = 50
	maxPolicyEntries = 50
	maxBridgeLineLen = 500
)

var (
	Configmtx sync.RWMutex
	gConfig   = Config{}
)

func loadConfig() error {
	Configmtx.Lock()
	defer Configmtx.Unlock()
	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // start with defaults
		}
		return err
	}
	cfg := Config{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if err := validateConfig(&cfg); err != nil {
		return fmt.Errorf("stored config invalid, using defaults: %w", err)
	}
	gConfig = cfg
	return nil
}

// writeConfigLocked atomically persists gConfig (caller holds Configmtx).
func writeConfigLocked() error {
	data, err := json.MarshalIndent(gConfig, "", " ")
	if err != nil {
		return err
	}
	tmp := ConfigFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, ConfigFile)
}

var (
	countryRe   = regexp.MustCompile(`^[a-zA-Z]{2}$`)
	fpRe        = regexp.MustCompile(`^[A-Fa-f0-9]{40}$`)
	transportRe = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	argKeyRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	argValRe    = regexp.MustCompile(`^[A-Za-z0-9+/=_.:~-]{1,256}$`)
)

// allowed pluggable transports (must have a matching ClientTransportPlugin)
var allowedTransports = map[string]bool{"obfs4": true}

func validateConfig(cfg *Config) error {
	cfg.ExitCountry = strings.ToLower(strings.TrimSpace(cfg.ExitCountry))
	if cfg.ExitCountry != "" && !countryRe.MatchString(cfg.ExitCountry) {
		return fmt.Errorf("ExitCountry must be a 2-letter country code")
	}

	if len(cfg.Bridges) > maxBridges {
		return fmt.Errorf("too many bridge lines (max %d)", maxBridges)
	}
	bridges := []string{}
	for _, line := range cfg.Bridges {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := validateBridgeLine(line); err != nil {
			return fmt.Errorf("bridge %q: %w", line, err)
		}
		bridges = append(bridges, line)
	}
	cfg.Bridges = bridges
	if cfg.UseBridges && len(cfg.Bridges) == 0 {
		return fmt.Errorf("UseBridges is set but no valid bridge lines were provided")
	}

	if len(cfg.SocksPolicy) > maxPolicyEntries {
		return fmt.Errorf("too many SocksPolicy entries (max %d)", maxPolicyEntries)
	}
	policy := []string{}
	for _, line := range cfg.SocksPolicy {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		norm, err := validateSocksPolicyLine(line)
		if err != nil {
			return fmt.Errorf("SocksPolicy %q: %w", line, err)
		}
		policy = append(policy, norm)
	}
	cfg.SocksPolicy = policy

	return nil
}

// validateBridgeLine accepts exactly two shapes:
//
//	vanilla: <ip>:<port> [<40-hex-fingerprint>]
//	obfs4:   obfs4 <ip>:<port> <40-hex-fingerprint> k=v ...
//
// Anything else (other transports, hostnames, shell/config metacharacters)
// is rejected. Validated tokens are the only thing ever written to torrc.
func validateBridgeLine(line string) error {
	if len(line) > maxBridgeLineLen {
		return fmt.Errorf("line too long")
	}
	if strings.ContainsAny(line, "\r\n\t\"'\\#") {
		return fmt.Errorf("contains forbidden characters")
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return fmt.Errorf("empty line")
	}

	idx := 0
	transport := ""
	if !looksLikeHostPort(fields[0]) {
		transport = fields[0]
		if !transportRe.MatchString(transport) || !allowedTransports[transport] {
			return fmt.Errorf("unsupported transport %q (supported: obfs4)", transport)
		}
		idx++
	}

	if idx >= len(fields) {
		return fmt.Errorf("missing address")
	}
	if err := validateHostPort(fields[idx]); err != nil {
		return err
	}
	idx++

	haveFP := false
	if idx < len(fields) && fpRe.MatchString(fields[idx]) {
		haveFP = true
		idx++
	}
	if transport != "" && !haveFP {
		return fmt.Errorf("%s bridges require a 40-hex-digit fingerprint", transport)
	}

	// remaining tokens must be k=v transport args (obfs4: cert=..., iat-mode=N)
	for ; idx < len(fields); idx++ {
		if transport == "" {
			return fmt.Errorf("unexpected token %q", fields[idx])
		}
		k, v, ok := strings.Cut(fields[idx], "=")
		if !ok || !argKeyRe.MatchString(k) || !argValRe.MatchString(v) {
			return fmt.Errorf("invalid transport argument %q", fields[idx])
		}
	}
	return nil
}

func looksLikeHostPort(s string) bool {
	_, _, err := net.SplitHostPort(s)
	return err == nil
}

func validateHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("invalid address %q", s)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("bridge address must be an IP literal, got %q", host)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

// validateSocksPolicyLine accepts "accept|reject <*|ip|cidr>" and returns
// the normalized entry.
func validateSocksPolicyLine(line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return "", fmt.Errorf("must be \"accept|reject <address>\"")
	}
	verb := strings.ToLower(fields[0])
	if verb != "accept" && verb != "reject" {
		return "", fmt.Errorf("must start with accept or reject")
	}
	addr := fields[1]
	if addr != "*" {
		if strings.Contains(addr, "/") {
			if _, err := netip.ParsePrefix(addr); err != nil {
				return "", fmt.Errorf("invalid CIDR %q", addr)
			}
		} else if _, err := netip.ParseAddr(addr); err != nil {
			return "", fmt.Errorf("invalid address %q", addr)
		}
	}
	return verb + " " + addr, nil
}

// generateTorrc renders the tor client configuration from a validated
// Config. Client-only hardening is fixed here: no ORPort/DirPort, cookie
// auth on a unix control socket, ports bound to the container IP only.
func generateTorrc(cfg *Config, containerIP string) string {
	var b strings.Builder
	w := func(format string, args ...interface{}) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	w("# Generated by spr-tor from /configs/spr-tor/config.json — DO NOT EDIT.")
	w("# Edit the plugin config via the SPR UI or API instead.")
	w("User debian-tor")
	w("DataDirectory %s", TorDataDir)
	w("Log notice stdout")
	w("RunAsDaemon 0")
	w("")
	w("# client only: never a relay, exit, directory or hidden service host")
	w("ClientOnly 1")
	w("ORPort 0")
	w("DirPort 0")
	w("ExitRelay 0")
	w("")
	w("# control channel: unix socket + cookie auth only, never TCP")
	w("ControlPort 0")
	w("ControlSocket %s", TorControlSocket)
	w("CookieAuthentication 1")
	w("CookieAuthFile %s", TorCookieFile)
	w("")
	w("GeoIPFile %s", TorGeoIPFile)
	w("GeoIPv6File %s", TorGeoIPv6File)
	w("")
	w("# proxy ports: bound to the container IP on the spr-tor bridge, never the host")
	w("SocksPort %s:%d", containerIP, TorSocksPortNum)
	for _, p := range cfg.SocksPolicy {
		w("SocksPolicy %s", p)
	}
	if cfg.SafeSocks {
		w("SafeSocks 1")
	}
	if cfg.TransPortEnabled {
		w("TransPort %s:%d", containerIP, TorTransPortNum)
	}
	if cfg.DNSPortEnabled {
		w("DNSPort %s:%d", containerIP, TorDNSPortNum)
	}
	if cfg.TransPortEnabled || cfg.DNSPortEnabled {
		w("VirtualAddrNetworkIPv4 10.192.0.0/10")
		w("AutomapHostsOnResolve 1")
	}
	if cfg.ExitCountry != "" {
		w("")
		w("ExitNodes {%s}", cfg.ExitCountry)
		w("StrictNodes 1")
	}
	if cfg.UseBridges && len(cfg.Bridges) > 0 {
		w("")
		w("UseBridges 1")
		needObfs4 := false
		for _, br := range cfg.Bridges {
			if strings.HasPrefix(br, "obfs4 ") {
				needObfs4 = true
			}
		}
		if needObfs4 {
			w("ClientTransportPlugin obfs4 exec %s", Obfs4ProxyBinary)
		}
		for _, br := range cfg.Bridges {
			w("Bridge %s", br)
		}
	}
	return b.String()
}

// writeTorrc renders and atomically installs the torrc for cfg.
func writeTorrc(cfg *Config, containerIP string) error {
	if err := os.MkdirAll(filepath.Dir(TorrcPath), 0755); err != nil {
		return err
	}
	data := []byte(generateTorrc(cfg, containerIP))
	tmp := TorrcPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, TorrcPath)
}
