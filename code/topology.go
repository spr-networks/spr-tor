package main

import (
	"net/http"
	"strings"
)

// Topology structs mirror the SPR host contract (see spr-tailscale): the
// host merges the plugin graph into the router topology at the "root" node.

type TopoNode struct {
	ID       string
	Kind     string
	Name     string
	IP       string `json:",omitempty"`
	ConnType string `json:",omitempty"`
	Online   bool
}

type TopoEdge struct {
	From  string
	To    string
	Layer string
	Kind  string
}

type Topology struct {
	Nodes []TopoNode
	Edges []TopoEdge
}

// shortFP abbreviates a 40-hex relay fingerprint for display when tor did
// not report a nickname.
func shortFP(fp string) string {
	if len(fp) > 8 {
		return fp[:8]
	}
	return fp
}

// buildTorTopology renders the current BUILT circuits as relay chains hanging
// off the root anchor: root -> guard -> middle -> exit. Relays shared between
// circuits are deduplicated by fingerprint. When exitCountry is configured,
// exit relays (the last hop of a BUILT general-purpose circuit) are labeled
// with it. Pure function so it is unit-testable from parsed circuit fixtures.
func buildTorTopology(circuits []Circuit, exitCountry string) Topology {
	topo := Topology{
		Nodes: []TopoNode{{ID: "root", ConnType: "tor", Online: true}},
		Edges: []TopoEdge{},
	}

	nodeIdx := map[string]int{}   // fingerprint -> index into topo.Nodes
	edgeSeen := map[string]bool{} // "from->to"

	addNode := func(hop CircuitHop) string {
		id := hop.Fingerprint
		if id == "" {
			id = hop.Nickname
		}
		if id == "" {
			return ""
		}
		if _, ok := nodeIdx[id]; !ok {
			name := hop.Nickname
			if name == "" {
				name = shortFP(hop.Fingerprint)
			}
			nodeIdx[id] = len(topo.Nodes)
			topo.Nodes = append(topo.Nodes, TopoNode{
				ID:     id,
				Kind:   "relay",
				Name:   name,
				Online: true,
			})
		}
		return id
	}

	addEdge := func(from, to string) {
		key := from + "->" + to
		if edgeSeen[key] {
			return
		}
		edgeSeen[key] = true
		topo.Edges = append(topo.Edges, TopoEdge{From: from, To: to, Layer: "tor", Kind: "tor"})
	}

	for _, c := range circuits {
		if c.Status != "BUILT" || len(c.Hops) == 0 {
			continue
		}
		prev := "root"
		for i, hop := range c.Hops {
			id := addNode(hop)
			if id == "" {
				continue
			}
			// label the exit relay with the configured exit country
			if exitCountry != "" && i == len(c.Hops)-1 && c.Purpose == "GENERAL" {
				n := &topo.Nodes[nodeIdx[id]]
				suffix := " (" + strings.ToUpper(exitCountry) + ")"
				if !strings.HasSuffix(n.Name, suffix) {
					n.Name += suffix
				}
			}
			addEdge(prev, id)
			prev = id
		}
	}

	return topo
}

// handleGetTopology reports the live circuit graph. When the tor daemon (or
// its control socket) is down, it returns just the root anchor so the SPR
// topology view still shows the plugin, offline.
func handleGetTopology(w http.ResponseWriter, r *http.Request) {
	Configmtx.RLock()
	exitCountry := gConfig.ExitCountry
	Configmtx.RUnlock()

	circuits := []Circuit{}
	if info, err := gControl.GetInfo("circuit-status"); err == nil {
		circuits = parseCircuitStatus(info["circuit-status"])
	}

	httpJSON(w, buildTorTopology(circuits, exitCountry))
}
