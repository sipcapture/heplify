package script

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/config"
	"github.com/sipcapture/heplify/src/decoder"
	lua "github.com/yuin/gopher-lua"
)

// Engine is the Lua script engine
type Engine struct {
	L          *lua.LState
	cfg        *config.Config
	pkt        *decoder.Packet
	mu         sync.Mutex
	hashData   map[string]interface{}
	scriptFile string
	stopCh     chan struct{}
}

// New creates a new Lua engine
func New(cfg *config.Config) *Engine {
	L := lua.NewState(lua.Options{
		CallStackSize: 120,
		RegistrySize:  120 * 20,
	})

	e := &Engine{
		L:        L,
		cfg:      cfg,
		hashData: make(map[string]interface{}),
		stopCh:   make(chan struct{}),
	}

	// Register functions
	e.registerFunctions()

	return e
}

func (e *Engine) registerFunctions() {
	// HEP field getters
	e.L.SetGlobal("GetHEPProtoType", e.L.NewFunction(e.getHEPProtoType))
	e.L.SetGlobal("GetHEPSrcIP", e.L.NewFunction(e.getHEPSrcIP))
	e.L.SetGlobal("GetHEPSrcPort", e.L.NewFunction(e.getHEPSrcPort))
	e.L.SetGlobal("GetHEPDstIP", e.L.NewFunction(e.getHEPDstIP))
	e.L.SetGlobal("GetHEPDstPort", e.L.NewFunction(e.getHEPDstPort))
	e.L.SetGlobal("GetHEPTimeSeconds", e.L.NewFunction(e.getHEPTimeSeconds))
	e.L.SetGlobal("GetHEPTimeUseconds", e.L.NewFunction(e.getHEPTimeUseconds))

	// Message getters/setters
	e.L.SetGlobal("GetRawMessage", e.L.NewFunction(e.getRawMessage))
	e.L.SetGlobal("SetRawMessage", e.L.NewFunction(e.setRawMessage))
	e.L.SetGlobal("SetHEPField", e.L.NewFunction(e.setHEPField))

	// Utility functions
	e.L.SetGlobal("HashTable", e.L.NewFunction(e.hashTable))
	e.L.SetGlobal("HashString", e.L.NewFunction(e.hashString))
	e.L.SetGlobal("Logp", e.L.NewFunction(e.logp))
	e.L.SetGlobal("Print", e.L.NewFunction(e.print))
}

// LoadScript loads a Lua script from file
func (e *Engine) LoadScript(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.scriptFile = path
	return e.loadScriptLocked(path)
}

func (e *Engine) loadScriptLocked(path string) error {
	if err := e.L.DoFile(path); err != nil {
		log.Error().Err(err).Str("file", path).Msg("Failed to load Lua script")
		return err
	}
	log.Info().Str("file", path).Msg("Lua script loaded")
	return nil
}

// Reload reloads the Lua script from the original file (e.g. on SIGHUP).
func (e *Engine) Reload() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.scriptFile == "" {
		return nil
	}

	// Reset the Lua state
	e.L.Close()
	e.L = lua.NewState(lua.Options{
		CallStackSize: 120,
		RegistrySize:  120 * 20,
	})
	e.registerFunctions()

	return e.loadScriptLocked(e.scriptFile)
}

// Close closes the Lua engine and stops the SIGHUP watcher.
func (e *Engine) Close() {
	close(e.stopCh)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.L.Close()
}

// SetPacket sets the current packet for Lua functions
func (e *Engine) SetPacket(pkt *decoder.Packet) {
	e.mu.Lock()
	e.pkt = pkt
	e.mu.Unlock()
}

// OnPacket calls the onPacket function in Lua with protocol info
func (e *Engine) OnPacket(packetInfo string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	fn := e.L.GetGlobal("onPacket")
	if fn == lua.LNil {
		return
	}

	if err := e.L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    0,
		Protect: true,
	}, lua.LString(packetInfo)); err != nil {
		log.Debug().Err(err).Msg("Lua onPacket error")
	}
}

// Run executes custom Lua functions
func (e *Engine) Run(funcName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	fn := e.L.GetGlobal(funcName)
	if fn == lua.LNil {
		return nil
	}

	return e.L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    0,
		Protect: true,
	})
}

// Lua function implementations

func (e *Engine) getHEPProtoType(L *lua.LState) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pkt == nil {
		L.Push(lua.LNumber(0))
		return 1
	}
	L.Push(lua.LNumber(e.pkt.GetProtoType()))
	return 1
}

func (e *Engine) getHEPSrcIP(L *lua.LState) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pkt == nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(e.pkt.GetSrcIP()))
	return 1
}

func (e *Engine) getHEPSrcPort(L *lua.LState) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pkt == nil {
		L.Push(lua.LNumber(0))
		return 1
	}
	L.Push(lua.LNumber(e.pkt.GetSrcPort()))
	return 1
}

func (e *Engine) getHEPDstIP(L *lua.LState) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pkt == nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(e.pkt.GetDstIP()))
	return 1
}

func (e *Engine) getHEPDstPort(L *lua.LState) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pkt == nil {
		L.Push(lua.LNumber(0))
		return 1
	}
	L.Push(lua.LNumber(e.pkt.GetDstPort()))
	return 1
}

func (e *Engine) getHEPTimeSeconds(L *lua.LState) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pkt == nil {
		L.Push(lua.LNumber(0))
		return 1
	}
	L.Push(lua.LNumber(e.pkt.GetTsec()))
	return 1
}

func (e *Engine) getHEPTimeUseconds(L *lua.LState) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pkt == nil {
		L.Push(lua.LNumber(0))
		return 1
	}
	L.Push(lua.LNumber(e.pkt.GetTmsec()))
	return 1
}

func (e *Engine) getRawMessage(L *lua.LState) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pkt == nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(e.pkt.GetPayload()))
	return 1
}

func (e *Engine) setRawMessage(L *lua.LState) int {
	value := L.CheckString(1)

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pkt == nil {
		log.Error().Msg("Cannot set RawMessage: packet is nil")
		return 0
	}
	e.pkt.Payload = []byte(value)
	return 0
}

func (e *Engine) setHEPField(L *lua.LState) int {
	field := L.CheckString(1)
	value := L.CheckString(2)

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pkt == nil {
		log.Error().Msg("Cannot set HEP field: packet is nil")
		return 0
	}

	switch field {
	case "ProtoType":
		if i, err := strconv.Atoi(value); err == nil {
			e.pkt.ProtoType = byte(i)
		}
	case "SrcIP":
		e.pkt.SrcIP = net.ParseIP(value)
	case "SrcPort":
		if i, err := strconv.Atoi(value); err == nil {
			e.pkt.SrcPort = uint16(i)
		}
	case "DstIP":
		e.pkt.DstIP = net.ParseIP(value)
	case "DstPort":
		if i, err := strconv.Atoi(value); err == nil {
			e.pkt.DstPort = uint16(i)
		}
	case "CID":
		e.pkt.CID = []byte(value)
	default:
		log.Warn().Str("field", field).Msg("Unknown HEP field")
	}

	return 0
}

// hashTable provides get/set/delete operations on the in-memory KV store.
// Usage: HashTable("get", key) → value | HashTable("set", key, value) | HashTable("del", key)
func (e *Engine) hashTable(L *lua.LState) int {
	op := L.CheckString(1)
	key := L.CheckString(2)

	e.mu.Lock()
	defer e.mu.Unlock()

	switch op {
	case "set":
		val := L.Get(3)
		switch v := val.(type) {
		case lua.LString:
			e.hashData[key] = string(v)
		case lua.LNumber:
			e.hashData[key] = float64(v)
		case lua.LBool:
			e.hashData[key] = bool(v)
		default:
			e.hashData[key] = v.String()
		}
		return 0
	case "del":
		delete(e.hashData, key)
		return 0
	default: // "get"
		if val, ok := e.hashData[key]; ok {
			switch v := val.(type) {
			case string:
				L.Push(lua.LString(v))
			case float64:
				L.Push(lua.LNumber(v))
			case bool:
				L.Push(lua.LBool(v))
			default:
				L.Push(lua.LNil)
			}
		} else {
			L.Push(lua.LNil)
		}
		return 1
	}
}

// hashString computes a hash of the input string.
// Usage: HashString(algo, input) where algo is "md5", "sha1", or "sha256".
// For backward compat HashString(input) uses md5.
func (e *Engine) hashString(L *lua.LState) int {
	arg1 := L.CheckString(1)
	arg2 := L.OptString(2, "")

	var algo, input string
	if arg2 == "" {
		// Legacy: HashString(input) → md5
		algo = "md5"
		input = arg1
	} else {
		algo = arg1
		input = arg2
	}

	var result string
	switch algo {
	case "sha1":
		h := sha1.Sum([]byte(input))
		result = hex.EncodeToString(h[:])
	case "sha256":
		h := sha256.Sum256([]byte(input))
		result = hex.EncodeToString(h[:])
	default: // md5
		h := md5.Sum([]byte(input))
		result = hex.EncodeToString(h[:])
	}

	L.Push(lua.LString(result))
	return 1
}

func (e *Engine) logp(L *lua.LState) int {
	level := L.CheckString(1)
	message := L.CheckString(2)
	data := L.Get(3)

	var dataStr string
	if data != lua.LNil {
		dataStr = data.String()
	}

	switch level {
	case "ERROR":
		log.Error().Str("data", dataStr).Msg("[script] " + message)
	case "WARN":
		log.Warn().Str("data", dataStr).Msg("[script] " + message)
	case "INFO":
		log.Info().Str("data", dataStr).Msg("[script] " + message)
	default:
		log.Debug().Str("data", dataStr).Msg("[script] " + message)
	}

	return 0
}

func (e *Engine) print(L *lua.LState) int {
	top := L.GetTop()
	for i := 1; i <= top; i++ {
		if i > 1 {
			fmt.Print("\t")
		}
		fmt.Print(L.Get(i).String())
	}
	fmt.Println()
	return 0
}
