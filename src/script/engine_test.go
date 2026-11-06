package script

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sipcapture/heplify/src/config"
	"github.com/sipcapture/heplify/src/decoder"
)

func newTestEngine(t *testing.T, src string) *Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.lua")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	e := New(&config.Config{})
	t.Cleanup(e.Close)
	if err := e.LoadScript(path); err != nil {
		t.Fatal(err)
	}
	return e
}

// A script that reads the packet used to deadlock: OnPacket held e.mu and
// GetHEPSrcPort locked it again.
func TestProcessPacketDoesNotDeadlock(t *testing.T) {
	e := newTestEngine(t, `function onPacket(x)
  local p = GetHEPSrcPort()
  HashTable("set", "k", GetHEPSrcIP())
  SetHEPField("DstPort", tostring(p + 1))
  SetRawMessage(GetRawMessage() .. "!")
end`)
	pkt := &decoder.Packet{SrcPort: 5060, Payload: []byte("hi")}
	done := make(chan struct{})
	go func() {
		e.ProcessPacket(pkt, "1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ProcessPacket deadlocked")
	}
	if pkt.DstPort != 5061 || string(pkt.Payload) != "hi!" {
		t.Fatalf("script changes not applied: DstPort=%d payload=%q", pkt.DstPort, pkt.Payload)
	}
}

func TestProcessPacketConcurrentWorkersSeeOwnPacket(t *testing.T) {
	e := newTestEngine(t, `function onPacket(x) SetHEPField("DstPort", tostring(GetHEPSrcPort())) end`)
	var wg sync.WaitGroup
	for i := 1; i <= 50; i++ {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			pkt := &decoder.Packet{SrcPort: port}
			e.ProcessPacket(pkt, "1")
			if pkt.DstPort != port {
				t.Errorf("worker %d saw another packet: DstPort=%d", port, pkt.DstPort)
			}
		}(uint16(i))
	}
	wg.Wait()
}
