package main

import (
	"strings"
	"testing"
)

const (
	validObfs4 = "obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA iat-mode=0"
	validPlain = "192.0.2.10:9001 0123456789abcdef0123456789abcdef01234567"
)

func TestValidateBridgeLineValid(t *testing.T) {
	valid := []string{
		validObfs4,
		validPlain,
		"192.0.2.10:9001",
		"[2001:db8::1]:9001",
	}
	for _, line := range valid {
		if err := validateBridgeLine(line); err != nil {
			t.Errorf("expected valid: %q, got %v", line, err)
		}
	}
}

func TestValidateBridgeLineInvalid(t *testing.T) {
	invalid := []string{
		"",
		"meek_lite 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567", // transport not allow-listed
		"obfs4 192.0.2.10:443", // obfs4 requires fingerprint
		"obfs4 example.com:443 0123456789ABCDEF0123456789ABCDEF01234567", // hostname not allowed
		"192.0.2.10", // no port
		"192.0.2.10:99999 0123456789ABCDEF0123456789ABCDEF01234567", // bad port
		"192.0.2.10:9001 0123456789ABCDEF",                          // short fingerprint
		"192.0.2.10:9001 0123456789abcdef0123456789abcdef01234567 extra-token",
		"obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=\"quoted\"",
		"obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc\ndef",
		"192.0.2.10:9001 0123456789abcdef0123456789abcdef01234567 # comment",
		"obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=$(reboot)",
		"obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 =noval",
		strings.Repeat("a", 501),
	}
	for _, line := range invalid {
		if err := validateBridgeLine(line); err == nil {
			t.Errorf("expected invalid: %q", line)
		}
	}
}

func TestValidateSocksPolicyLine(t *testing.T) {
	good := map[string]string{
		"accept 192.168.2.0/24": "accept 192.168.2.0/24",
		"REJECT *":              "reject *",
		"accept 10.1.2.3":       "accept 10.1.2.3",
		"reject  0.0.0.0/0":     "reject 0.0.0.0/0",
	}
	for in, want := range good {
		got, err := validateSocksPolicyLine(in)
		if err != nil {
			t.Errorf("expected valid: %q, got %v", in, err)
		} else if got != want {
			t.Errorf("normalize %q: got %q want %q", in, got, want)
		}
	}

	bad := []string{
		"accept",
		"allow 192.168.2.0/24",
		"accept 192.168.2.0/33",
		"accept not-an-ip",
		"accept 1.2.3.4 extra",
		"accept 1.2.3.4\nSocksPort 0.0.0.0:9050",
	}
	for _, in := range bad {
		if _, err := validateSocksPolicyLine(in); err == nil {
			t.Errorf("expected invalid: %q", in)
		}
	}
}

func TestValidateConfig(t *testing.T) {
	cfg := Config{
		ExitCountry: " DE ",
		Bridges:     []string{validObfs4, "  ", ""},
		SocksPolicy: []string{"ACCEPT 192.168.2.0/24", ""},
		UseBridges:  true,
	}
	if err := validateConfig(&cfg); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if cfg.ExitCountry != "de" {
		t.Errorf("ExitCountry not normalized: %q", cfg.ExitCountry)
	}
	if len(cfg.Bridges) != 1 {
		t.Errorf("blank bridge lines not dropped: %v", cfg.Bridges)
	}
	if len(cfg.SocksPolicy) != 1 || cfg.SocksPolicy[0] != "accept 192.168.2.0/24" {
		t.Errorf("SocksPolicy not normalized: %v", cfg.SocksPolicy)
	}

	bad := []Config{
		{ExitCountry: "usa"},
		{ExitCountry: "u"},
		{ExitCountry: "{u}"},
		{UseBridges: true},
		{UseBridges: true, Bridges: []string{"nonsense"}},
		{SocksPolicy: []string{"accept 1.2.3.4; rm -rf /"}},
	}
	for i := range bad {
		if err := validateConfig(&bad[i]); err == nil {
			t.Errorf("expected invalid config #%d: %+v", i, bad[i])
		}
	}
}

func TestGenerateTorrcDefaults(t *testing.T) {
	cfg := Config{}
	if err := validateConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	rc := generateTorrc(&cfg, "172.18.0.2")

	mustHave := []string{
		"SocksPort 172.18.0.2:9050",
		"ControlSocket /run/tor/control.sock",
		"CookieAuthentication 1",
		"ControlPort 0",
		"ClientOnly 1",
		"ORPort 0",
		"DirPort 0",
		"ExitRelay 0",
		"User debian-tor",
		"DataDirectory /state/plugins/spr-tor/tor",
	}
	for _, s := range mustHave {
		if !strings.Contains(rc, s+"\n") {
			t.Errorf("torrc missing %q:\n%s", s, rc)
		}
	}

	mustNotHave := []string{"TransPort", "DNSPort", "UseBridges", "ExitNodes", "SafeSocks", "Bridge "}
	for _, s := range mustNotHave {
		if strings.Contains(rc, s) {
			t.Errorf("default torrc must not contain %q:\n%s", s, rc)
		}
	}
}

func TestGenerateTorrcFull(t *testing.T) {
	cfg := Config{
		TransPortEnabled: true,
		DNSPortEnabled:   true,
		ExitCountry:      "de",
		UseBridges:       true,
		Bridges:          []string{validObfs4, validPlain},
		SocksPolicy:      []string{"accept 192.168.2.0/24", "reject *"},
		SafeSocks:        true,
	}
	if err := validateConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	rc := generateTorrc(&cfg, "172.18.0.2")

	mustHave := []string{
		"TransPort 172.18.0.2:9040",
		"DNSPort 172.18.0.2:9053",
		"ExitNodes {de}",
		"StrictNodes 1",
		"UseBridges 1",
		"ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy",
		"Bridge " + validObfs4,
		"Bridge " + validPlain,
		"SocksPolicy accept 192.168.2.0/24",
		"SocksPolicy reject *",
		"SafeSocks 1",
		"VirtualAddrNetworkIPv4 10.192.0.0/10",
	}
	for _, s := range mustHave {
		if !strings.Contains(rc, s+"\n") {
			t.Errorf("torrc missing %q:\n%s", s, rc)
		}
	}
	// ports must never bind beyond the container IP
	if strings.Contains(rc, "0.0.0.0") {
		t.Errorf("torrc must not bind 0.0.0.0:\n%s", rc)
	}
}

func TestGenerateTorrcNoObfs4PluginForPlainBridges(t *testing.T) {
	cfg := Config{UseBridges: true, Bridges: []string{validPlain}}
	if err := validateConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	rc := generateTorrc(&cfg, "172.18.0.2")
	if strings.Contains(rc, "ClientTransportPlugin") {
		t.Errorf("plain bridges must not enable a transport plugin:\n%s", rc)
	}
}
