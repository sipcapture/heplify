package script

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sipcapture/heplify/src/config"
	"github.com/sipcapture/heplify/src/decoder"
	lua "github.com/yuin/gopher-lua"
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

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.lua")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSandboxBlocksDangerousLibs(t *testing.T) {
	e := New(&config.Config{})
	defer e.Close()
	path := writeScript(t, `
blocked = {}
if io == nil then table.insert(blocked, "io") end
if os.execute == nil then table.insert(blocked, "os.execute") end
if os.remove == nil then table.insert(blocked, "os.remove") end
if dofile == nil then table.insert(blocked, "dofile") end
if load == nil then table.insert(blocked, "load") end
if require == nil then table.insert(blocked, "require") end
if os.time() > 0 then table.insert(blocked, "time-ok") end
result = table.concat(blocked, ",")
`)
	if err := e.LoadScript(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	got := e.L.GetGlobal("result").String()
	want := "io,os.execute,os.remove,dofile,load,require,time-ok"
	if got != want {
		t.Fatalf("sandbox: got %q, want %q", got, want)
	}
}

func TestUnsafeKeepsFullStdlib(t *testing.T) {
	cfg := &config.Config{}
	cfg.ScriptSettings.Unsafe = true
	e := New(cfg)
	defer e.Close()
	path := writeScript(t, `ok = (io ~= nil and os.execute ~= nil)`)
	if err := e.LoadScript(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if e.L.GetGlobal("ok") != lua.LTrue {
		t.Fatal("unsafe mode should open io and os")
	}
}

func TestScriptTimeoutStopsRunawayLoop(t *testing.T) {
	cfg := &config.Config{}
	cfg.ScriptSettings.TimeoutMs = 50
	e := New(cfg)
	defer e.Close()
	path := writeScript(t, `
calls = 0
function onPacket(info)
  calls = calls + 1
  if calls == 1 then while true do end end
end
`)
	if err := e.LoadScript(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	done := make(chan struct{})
	go func() {
		e.ProcessPacket(&decoder.Packet{}, "x")
		e.ProcessPacket(&decoder.Packet{}, "x")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runaway onPacket was not stopped by the timeout")
	}
	if n := e.L.GetGlobal("calls"); n.String() != "2" {
		t.Fatalf("engine unusable after a timeout, calls=%v", n)
	}
}
