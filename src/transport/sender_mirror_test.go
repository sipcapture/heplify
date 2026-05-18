package transport

import (
	"errors"
	"testing"
)

// connectedStubClient returns a HEP client backed by a stubConn in connected state.
func connectedStubClient(conn *stubConn) *HEPClient {
	return &HEPClient{
		addr:    "127.0.0.1:0",
		proto:   "tcp",
		conn:    conn,
		state:   stateConnected,
		backoff: initialReconnectBackoff,
	}
}

func TestSendToAllMirrorsToMultiplePrimaries(t *testing.T) {
	primary1 := &stubConn{}
	primary2 := &stubConn{}
	sender := &Sender{
		clients: []*transportClient{
			{kind: kindHEP, failoverOnly: false, hep: connectedStubClient(primary1)},
			{kind: kindHEP, failoverOnly: false, hep: connectedStubClient(primary2)},
		},
	}

	sender.sendToAll([]byte("mirror-packet"))

	if got := primary1.writes.Load(); got != 1 {
		t.Fatalf("primary1 writes = %d, want 1", got)
	}
	if got := primary2.writes.Load(); got != 1 {
		t.Fatalf("primary2 writes = %d, want 1", got)
	}
}

func TestSendToAllSkipsBackupWhenPrimarySucceeds(t *testing.T) {
	primary := &stubConn{}
	backup := &stubConn{}
	sender := &Sender{
		clients: []*transportClient{
			{kind: kindHEP, failoverOnly: false, hep: connectedStubClient(primary)},
			{kind: kindHEP, failoverOnly: true, hep: connectedStubClient(backup)},
		},
	}

	sender.sendToAll([]byte("primary-only"))

	if got := primary.writes.Load(); got != 1 {
		t.Fatalf("primary writes = %d, want 1", got)
	}
	if got := backup.writes.Load(); got != 0 {
		t.Fatalf("backup writes = %d, want 0 while primary is up", got)
	}
}

func TestSendToAllUsesBackupWhenAllPrimariesFail(t *testing.T) {
	failingPrimary := &stubConn{writeErr: errors.New("primary down")}
	backup := &stubConn{}
	sender := &Sender{
		clients: []*transportClient{
			{kind: kindHEP, failoverOnly: false, hep: connectedStubClient(failingPrimary)},
			{kind: kindHEP, failoverOnly: true, hep: connectedStubClient(backup)},
		},
	}

	sender.sendToAll([]byte("failover-packet"))

	if got := backup.writes.Load(); got != 1 {
		t.Fatalf("backup writes = %d, want 1 after primary failure", got)
	}
}

func TestSendToAllPartialPrimaryMirror(t *testing.T) {
	up := &stubConn{}
	down := &stubConn{writeErr: errors.New("peer down")}
	sender := &Sender{
		clients: []*transportClient{
			{kind: kindHEP, failoverOnly: false, hep: connectedStubClient(up)},
			{kind: kindHEP, failoverOnly: false, hep: connectedStubClient(down)},
		},
	}

	sender.sendToAll([]byte("partial-mirror"))

	if got := up.writes.Load(); got != 1 {
		t.Fatalf("healthy primary writes = %d, want 1", got)
	}
	// sendToGroup returns true when at least one primary succeeds — mirror is best-effort per peer.
	if got := down.writes.Load(); got != 0 {
		t.Fatalf("failed primary writes = %d, want 0", got)
	}
}
