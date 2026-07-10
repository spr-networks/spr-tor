package main

import (
	"reflect"
	"testing"
)

const fpA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const fpB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
const fpC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
const fpD = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"

func nodeByID(t *testing.T, topo Topology, id string) TopoNode {
	t.Helper()
	for _, n := range topo.Nodes {
		if n.ID == id {
			return n
		}
	}
	t.Fatalf("node %q not found in %+v", id, topo.Nodes)
	return TopoNode{}
}

func TestBuildTorTopologyEmpty(t *testing.T) {
	topo := buildTorTopology(nil, "")
	want := Topology{
		Nodes: []TopoNode{{ID: "root", ConnType: "tor", Online: true}},
		Edges: []TopoEdge{},
	}
	if !reflect.DeepEqual(topo, want) {
		t.Errorf("empty topology: got %+v want %+v", topo, want)
	}
}

func TestBuildTorTopologyBuiltCircuit(t *testing.T) {
	// fixture goes through the real circuit parser, as the handler does
	circuits := parseCircuitStatus(
		"1 BUILT $" + fpA + "~guard,$" + fpB + "~middle,$" + fpC + "~exit " +
			"BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-07-08T12:00:00.000000")

	topo := buildTorTopology(circuits, "")

	if len(topo.Nodes) != 4 {
		t.Fatalf("got %d nodes, want 4 (root + 3 relays): %+v", len(topo.Nodes), topo.Nodes)
	}
	root := nodeByID(t, topo, "root")
	if root.ConnType != "tor" || !root.Online {
		t.Errorf("root anchor wrong: %+v", root)
	}
	guard := nodeByID(t, topo, fpA)
	if guard.Kind != "relay" || guard.Name != "guard" || !guard.Online {
		t.Errorf("guard node wrong: %+v", guard)
	}

	wantEdges := []TopoEdge{
		{From: "root", To: fpA, Layer: "tor", Kind: "tor"},
		{From: fpA, To: fpB, Layer: "tor", Kind: "tor"},
		{From: fpB, To: fpC, Layer: "tor", Kind: "tor"},
	}
	if !reflect.DeepEqual(topo.Edges, wantEdges) {
		t.Errorf("edges: got %+v want %+v", topo.Edges, wantEdges)
	}
}

func TestBuildTorTopologySkipsUnbuiltCircuits(t *testing.T) {
	circuits := parseCircuitStatus(
		"1 LAUNCHED PURPOSE=GENERAL\n" +
			"2 EXTENDED $" + fpA + "~guard PURPOSE=GENERAL\n" +
			"3 FAILED $" + fpA + "~guard,$" + fpB + "~middle PURPOSE=GENERAL")

	topo := buildTorTopology(circuits, "")
	if len(topo.Nodes) != 1 || len(topo.Edges) != 0 {
		t.Errorf("non-BUILT circuits must not add nodes/edges: %+v", topo)
	}
}

func TestBuildTorTopologyDedupesSharedRelays(t *testing.T) {
	// two circuits sharing the same guard
	circuits := parseCircuitStatus(
		"1 BUILT $" + fpA + "~guard,$" + fpB + "~mid1,$" + fpC + "~exit1 PURPOSE=GENERAL\n" +
			"2 BUILT $" + fpA + "~guard,$" + fpD + "~exit2 PURPOSE=GENERAL")

	topo := buildTorTopology(circuits, "")
	if len(topo.Nodes) != 5 { // root, guard, mid1, exit1, exit2
		t.Fatalf("got %d nodes, want 5: %+v", len(topo.Nodes), topo.Nodes)
	}
	rootEdges := 0
	for _, e := range topo.Edges {
		if e.From == "root" {
			rootEdges++
		}
	}
	if rootEdges != 1 {
		t.Errorf("shared guard should yield one root edge, got %d: %+v", rootEdges, topo.Edges)
	}
	if len(topo.Edges) != 4 { // root->guard, guard->mid1, mid1->exit1, guard->exit2
		t.Errorf("got %d edges, want 4: %+v", len(topo.Edges), topo.Edges)
	}
}

func TestBuildTorTopologyExitCountrySuffix(t *testing.T) {
	circuits := parseCircuitStatus(
		"1 BUILT $" + fpA + "~guard,$" + fpB + "~middle,$" + fpC + "~exit PURPOSE=GENERAL\n" +
			// internal (non-GENERAL) circuit: last hop is not an exit
			"2 BUILT $" + fpA + "~guard,$" + fpD + "~hsdir PURPOSE=HS_CLIENT_HSDIR")

	topo := buildTorTopology(circuits, "de")
	if got := nodeByID(t, topo, fpC).Name; got != "exit (DE)" {
		t.Errorf("exit name: got %q want %q", got, "exit (DE)")
	}
	if got := nodeByID(t, topo, fpD).Name; got != "hsdir" {
		t.Errorf("non-GENERAL last hop must not get country suffix: got %q", got)
	}
	if got := nodeByID(t, topo, fpA).Name; got != "guard" {
		t.Errorf("guard name: got %q", got)
	}
}

func TestBuildTorTopologyFingerprintOnlyHop(t *testing.T) {
	circuits := parseCircuitStatus("1 BUILT $" + fpA + " PURPOSE=GENERAL")
	topo := buildTorTopology(circuits, "")
	n := nodeByID(t, topo, fpA)
	if n.Name != "AAAAAAAA" {
		t.Errorf("nickname-less relay should display abbreviated fingerprint, got %q", n.Name)
	}
}

func TestTorSinkGatedOnTransPort(t *testing.T) {
	// TransPort off -> no sink (routed traffic would blackhole)
	if s := torSink(Config{TransPortEnabled: false}, "172.19.0.2", true); s != nil {
		t.Errorf("sink must not be advertised when TransPort is disabled, got %+v", s)
	}

	// TransPort on -> one sink on the bridge iface, tied to running state
	s := torSink(Config{TransPortEnabled: true}, "172.19.0.2", true)
	if len(s) != 1 {
		t.Fatalf("expected 1 sink, got %+v", s)
	}
	if s[0].ID != "tor" || s[0].Iface != gSPRTorInterface || s[0].IP != "172.19.0.2" || !s[0].Online {
		t.Errorf("bad sink advertisement: %+v", s[0])
	}

	if s := torSink(Config{TransPortEnabled: true}, "172.19.0.2", false); s[0].Online {
		t.Errorf("sink should be offline when tor is not running")
	}
}
