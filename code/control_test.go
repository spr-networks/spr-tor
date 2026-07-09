package main

import (
	"reflect"
	"testing"
)

func TestParseBootstrapPhase(t *testing.T) {
	progress, summary := parseBootstrapPhase(
		`NOTICE BOOTSTRAP PROGRESS=85 TAG=ap_conn SUMMARY="Connecting to a relay to build circuits"`)
	if progress != 85 {
		t.Errorf("progress: got %d want 85", progress)
	}
	if summary != "Connecting to a relay to build circuits" {
		t.Errorf("summary: got %q", summary)
	}

	progress, summary = parseBootstrapPhase("")
	if progress != 0 || summary != "" {
		t.Errorf("empty input: got %d %q", progress, summary)
	}
}

func TestParseGetInfoLines(t *testing.T) {
	info := parseGetInfoLines([]string{
		"version=0.4.8.10",
		"status/circuit-established=1",
		"not a pair",
	})
	if info["version"] != "0.4.8.10" {
		t.Errorf("version: got %q", info["version"])
	}
	if info["status/circuit-established"] != "1" {
		t.Errorf("circuit-established: got %q", info["status/circuit-established"])
	}
	if len(info) != 2 {
		t.Errorf("unexpected entries: %v", info)
	}
}

func TestParseCircuitStatus(t *testing.T) {
	data := "1 BUILT $ABCDEF0123456789ABCDEF0123456789ABCDEF01~guard,$FEDCBA9876543210FEDCBA9876543210FEDCBA98~middle BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-07-08T12:00:00.000000\n" +
		"2 LAUNCHED PURPOSE=GENERAL"

	circuits := parseCircuitStatus(data)
	if len(circuits) != 2 {
		t.Fatalf("got %d circuits, want 2", len(circuits))
	}

	c := circuits[0]
	if c.ID != "1" || c.Status != "BUILT" || c.Purpose != "GENERAL" {
		t.Errorf("circuit 1 parsed wrong: %+v", c)
	}
	if !reflect.DeepEqual(c.Path, []string{"guard", "middle"}) {
		t.Errorf("path parsed wrong: %v", c.Path)
	}
	if !reflect.DeepEqual(c.BuildFlags, []string{"NEED_CAPACITY"}) {
		t.Errorf("build flags parsed wrong: %v", c.BuildFlags)
	}
	if c.TimeCreated != "2026-07-08T12:00:00.000000" {
		t.Errorf("time parsed wrong: %q", c.TimeCreated)
	}

	c = circuits[1]
	if c.ID != "2" || c.Status != "LAUNCHED" || len(c.Path) != 0 {
		t.Errorf("circuit 2 parsed wrong: %+v", c)
	}

	if got := parseCircuitStatus(""); len(got) != 0 {
		t.Errorf("empty status should parse to no circuits: %v", got)
	}
}
