package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// spr-tor is reachable as a transparent-proxy sink: SPR policy-routes a
// device's outbound traffic to this container (default via <container-ip> dev
// spr-tor), so packets arrive with their original foreign destination. Tor's
// TransPort/DNSPort can only intercept them if the kernel first REDIRECTs them
// locally — that is what this nft ruleset does. Rules are (re)synced whenever
// the torrc is written, so they track the TransPortEnabled/DNSPortEnabled
// toggles exactly; with TransPort off the table is torn down entirely.

const transNFTTable = "spr_tor_trans"

// syncTransProxy installs or removes the transparent-redirect ruleset to match
// cfg. It is best-effort: a failure is logged but never blocks tor itself,
// since the SOCKS proxy works without any of this.
func syncTransProxy(cfg *Config, containerIP string) {
	// always start from a clean slate so toggles and IP changes don't leak
	// stale rules (delete is idempotent-enough; ignore "No such file" errors)
	runNFT("delete", "table", "inet", transNFTTable)

	if !cfg.TransPortEnabled {
		return
	}
	if containerIP == "" || containerIP == "127.0.0.1" {
		log.Println("[-] transproxy: no container IP, not installing redirect rules")
		return
	}

	// Build the ruleset as a single nft script. Transit traffic (destined
	// somewhere other than the container's own services) is redirected into
	// TransPort; DNS is sent to DNSPort when it is enabled so plaintext
	// lookups resolve through tor instead of leaking.
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", transNFTTable)
	fmt.Fprintf(&b, "add chain inet %s prerouting { type nat hook prerouting priority dstnat ; policy accept ; }\n", transNFTTable)

	if cfg.DNSPortEnabled {
		// catch DNS first (both to the container's own IP — the sink's DNS
		// rewrite target — and to any foreign resolver, to prevent leaks)
		fmt.Fprintf(&b, "add rule inet %s prerouting udp dport 53 redirect to :%d\n", transNFTTable, TorDNSPortNum)
		fmt.Fprintf(&b, "add rule inet %s prerouting tcp dport 53 redirect to :%d\n", transNFTTable, TorDNSPortNum)
	}

	// leave traffic to the container's own services (SOCKS/UI/control) alone;
	// redirect the rest of transit TCP into the transparent proxy
	fmt.Fprintf(&b, "add rule inet %s prerouting ip daddr %s accept\n", transNFTTable, containerIP)
	fmt.Fprintf(&b, "add rule inet %s prerouting meta l4proto tcp redirect to :%d\n", transNFTTable, TorTransPortNum)

	if err := runNFTScript(b.String()); err != nil {
		log.Println("[-] transproxy: installing redirect rules failed:", err)
	} else {
		log.Println("[+] transproxy: transparent redirect active on", gSPRTorInterface)
	}
}

func runNFT(args ...string) error {
	cmd := exec.Command("nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file or directory") {
		return fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runNFTScript(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
