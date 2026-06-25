package threatdragon

import (
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

// A compact Threat Dragon v2 model: an external actor, a process, and a store
// across two trust boundaries (an untrusted internet box and a data box), with
// flows actor→process→store.
const sampleTD = `{
  "version": "2.0",
  "summary": {"title": "Test TM", "owner": "me"},
  "detail": {
    "diagrams": [
      {
        "id": 0, "title": "d", "cells": [
          {"shape": "trust-boundary-box", "id": "tb-net", "position": {"x": 0, "y": 0}, "size": {"width": 300, "height": 400},
           "data": {"type": "tm.BoundaryBox", "name": "Internet Boundary", "description": "untrusted external network", "isTrustBoundary": true}},
          {"shape": "trust-boundary-box", "id": "tb-data", "position": {"x": 400, "y": 0}, "size": {"width": 300, "height": 400},
           "data": {"type": "tm.BoundaryBox", "name": "Data Boundary", "isTrustBoundary": true}},
          {"shape": "actor", "id": "user", "position": {"x": 40, "y": 180}, "size": {"width": 120, "height": 60},
           "data": {"type": "tm.Actor", "name": "End User"}},
          {"shape": "process", "id": "web", "position": {"x": 60, "y": 280}, "size": {"width": 120, "height": 60},
           "data": {"type": "tm.Process", "name": "Web App", "isWebApplication": true}},
          {"shape": "store", "id": "db", "position": {"x": 460, "y": 180}, "size": {"width": 160, "height": 60},
           "data": {"type": "tm.Store", "name": "PostgreSQL Database"}},
          {"shape": "flow", "id": "f1", "source": {"cell": "user"}, "target": {"cell": "web"},
           "data": {"type": "tm.Flow", "name": "HTTPS", "isEncrypted": true}},
          {"shape": "flow", "id": "f2", "source": {"cell": "web"}, "target": {"cell": "db"},
           "data": {"type": "tm.Flow", "name": "SQL"}}
        ]
      }
    ]
  }
}`

func importSample(t *testing.T) *types.Model {
	t.Helper()
	m, err := Import([]byte(sampleTD), ImportOptions{})
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	return m
}

func TestNodesClassified(t *testing.T) {
	m := importSample(t)
	if m.Title != "Test TM" {
		t.Errorf("title = %q", m.Title)
	}
	user := m.TechnicalAssets["user-td"]
	if user == nil || user.Type != types.ExternalEntity || !user.Internet {
		t.Fatalf("actor should be internet-facing external entity: %+v", user)
	}
	web := m.TechnicalAssets["web-td"]
	if web == nil || web.Type != types.Process || web.Technologies[0].Name != types.WebApplication {
		t.Fatalf("process should be a web-application: %+v", web)
	}
	db := m.TechnicalAssets["db-td"]
	if db == nil || db.Type != types.Datastore || db.Technologies[0].Name != types.Database {
		t.Fatalf("postgres store should be a database datastore: %+v", db)
	}
}

func TestFlowsBecomeLinks(t *testing.T) {
	m := importSample(t)
	if len(m.CommunicationLinks) != 2 {
		t.Fatalf("expected 2 communication links, got %d", len(m.CommunicationLinks))
	}
	var userToWeb, webToDB *types.CommunicationLink
	for _, l := range m.CommunicationLinks {
		if l.SourceId == "user-td" && l.TargetId == "web-td" {
			userToWeb = l
		}
		if l.SourceId == "web-td" && l.TargetId == "db-td" {
			webToDB = l
		}
	}
	if userToWeb == nil || webToDB == nil {
		t.Fatal("expected user→web and web→db links")
	}
	if userToWeb.Protocol != types.HTTPS {
		t.Errorf("encrypted flow should be HTTPS, got %s", userToWeb.Protocol)
	}
}

func TestInternetExposureFromActorFlow(t *testing.T) {
	m := importSample(t)
	// web is the direct target of a flow from the actor -> internet-facing.
	if !m.TechnicalAssets["web-td"].Internet {
		t.Error("web process reached directly from an actor should be internet-facing")
	}
	// db is only reached from web -> not internet.
	if m.TechnicalAssets["db-td"].Internet {
		t.Error("db should not be internet-facing")
	}
}

func TestBoundaryMembershipByGeometry(t *testing.T) {
	m := importSample(t)
	net := m.TrustBoundaries["boundary-tb-net-td"]
	data := m.TrustBoundaries["boundary-tb-data-td"]
	if net == nil || data == nil {
		t.Fatal("both boundaries should exist")
	}
	// user + web are in the internet box; db is in the data box.
	if !contains(net.TechnicalAssetsInside, "user-td") || !contains(net.TechnicalAssetsInside, "web-td") {
		t.Errorf("internet boundary should contain user+web: %v", net.TechnicalAssetsInside)
	}
	if !contains(data.TechnicalAssetsInside, "db-td") {
		t.Errorf("data boundary should contain db: %v", data.TechnicalAssetsInside)
	}
	// "untrusted/internet" boundary -> network-on-prem type.
	if net.Type != types.NetworkOnPrem {
		t.Errorf("internet boundary type = %s, want on-prem", net.Type)
	}
}

func TestMultiDiagramNoCollision(t *testing.T) {
	// Two pages each with a cell id "svc" must not collide.
	doc := `{"version":"2.0","summary":{"title":"Multi"},"detail":{"diagrams":[
	  {"id":0,"cells":[{"shape":"process","id":"svc","position":{"x":0,"y":0},"size":{"width":40,"height":40},"data":{"type":"tm.Process","name":"Service A"}}]},
	  {"id":1,"cells":[{"shape":"process","id":"svc","position":{"x":0,"y":0},"size":{"width":40,"height":40},"data":{"type":"tm.Process","name":"Service B"}}]}
	]}}`
	m, err := Import([]byte(doc), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.TechnicalAssets) != 2 {
		t.Fatalf("two same-id cells on different pages must both survive, got %d assets", len(m.TechnicalAssets))
	}
}

func TestImportErrors(t *testing.T) {
	if _, err := Import([]byte(`{"version":"2.0"}`), ImportOptions{}); err == nil {
		t.Error("no diagrams should error")
	}
	if _, err := Import([]byte("not json"), ImportOptions{}); err == nil {
		t.Error("invalid JSON should error")
	}
	if _, err := Import([]byte(`{"detail":{"diagrams":[{"cells":[]}]}}`), ImportOptions{}); err == nil {
		t.Error("no nodes should error")
	}
}

func TestDeterministic(t *testing.T) {
	first := importSample(t)
	for i := 0; i < 10; i++ {
		m := importSample(t)
		if len(m.TechnicalAssets) != len(first.TechnicalAssets) ||
			len(m.TrustBoundaries) != len(first.TrustBoundaries) ||
			len(m.CommunicationLinks) != len(first.CommunicationLinks) {
			t.Fatal("non-deterministic import")
		}
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
