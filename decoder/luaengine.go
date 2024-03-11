package decoder

import (
	"fmt"
	"net"
	"strconv"

	"github.com/negbie/logp"
	"github.com/sipcapture/golua/lua"
	"github.com/sipcapture/heplify/decoder/luar"
)

// LuaEngine
type LuaEngine struct {
	/* pointer to modify */
	pkt       **Packet
	functions []string
	LuaEngine *lua.State
}

func (d *LuaEngine) GetHEPProtoType() uint32 {
	return (*d.pkt).GetProtoType()
}

func (d *LuaEngine) GetHEPSrcIP() string {
	return (*d.pkt).GetSrcIP()
}

func (d *LuaEngine) GetHEPSrcPort() uint16 {
	return (*d.pkt).GetSrcPort()
}

func (d *LuaEngine) GetHEPDstIP() string {
	return (*d.pkt).GetDstIP()
}

func (d *LuaEngine) GetHEPDstPort() uint16 {
	return (*d.pkt).GetDstPort()
}

func (d *LuaEngine) GetHEPTimeSeconds() uint32 {
	return (*d.pkt).GetTsec()
}

func (d *LuaEngine) GetHEPTimeUseconds() uint32 {
	return (*d.pkt).GetTmsec()
}

func (d *LuaEngine) GetRawMessage() string {
	return (*d.pkt).GetPayload()
}

func (d *LuaEngine) SetRawMessage(value string) {
	if (*d.pkt) == nil {
		logp.Err("can't set Raw message if HEP struct is nil, please check for nil in lua script")
		return
	}
	pkt := *d.pkt
	pkt.Payload = []byte(value)
}

func (d *LuaEngine) SetHEPField(field string, value string) {
	if (*d.pkt) == nil {
		logp.Err("can't set HEP field if HEP struct is nil, please check for nil in lua script")
		return
	}
	pkt := *d.pkt

	switch field {
	case "ProtoType":
		if i, err := strconv.Atoi(value); err == nil {
			pkt.ProtoType = byte(i)
		}
	case "SrcIP":
		pkt.SrcIP = net.ParseIP(value)
	case "SrcPort":
		if i, err := strconv.Atoi(value); err == nil {
			pkt.SrcPort = uint16(i)
		}
	case "DstIP":
		pkt.DstIP = net.ParseIP(value)
	case "DstPort":
		if i, err := strconv.Atoi(value); err == nil {
			pkt.DstPort = uint16(i)
		}

	case "CID":
		pkt.CID = []byte(value)

	}
}

func (d *LuaEngine) Logp(level string, message string, data interface{}) {
	if level == "ERROR" {
		logp.Err("[script] %s: %v", message, data)
	} else {
		logp.Debug("[script] %s: %v", message, data)
	}
}

func (d *LuaEngine) Close() {
	d.LuaEngine.Close()
}

// NewLuaEngine returns the script engine struct
func NewLuaEngine() (*LuaEngine, error) {
	logp.Debug("script", "register Lua engine")

	d := &LuaEngine{}
	d.LuaEngine = lua.NewState()
	d.LuaEngine.OpenLibs()

	/* luar.Register(d.LuaEngine, "", luar.Map{
		"GetHEPProtoType":    d.GetHEPProtoType,
		"GetHEPSrcIP":        d.GetHEPSrcIP,
		"GetHEPSrcPort":      d.GetHEPSrcPort,
		"GetHEPDstIP":        d.GetHEPDstIP,
		"GetHEPDstPort":      d.GetHEPDstPort,
		"GetHEPTimeSeconds":  d.GetHEPTimeSeconds,
		"GetHEPTimeUseconds": d.GetHEPTimeUseconds,
		"GetRawMessage":      d.GetRawMessage,
		"SetRawMessage":      d.SetRawMessage,
		"SetHEPField":        d.SetHEPField,
		"HashTable":          HashTable,
		"HashString":         HashString,
		"Logp":               d.Logp,
		"Print":              fmt.Println,
	})
	*/

	luar.Register(d.LuaEngine, "", luar.Map{
		"Logp":  d.Logp,
		"Print": fmt.Println,
	})
	_, code, err := scanCode()
	if err != nil {
		logp.Err("Error in scan script: %v", err)
		return nil, err
	}

	logp.Debug("script", "load lua script: %v", code.String())

	err = d.LuaEngine.DoString(code.String())
	if err != nil {
		logp.Err("Error in lua script: %v", err)
		return nil, err
	}

	d.functions = extractFunc(code)
	if len(d.functions) < 1 {
		logp.Err("no function name found in lua scripts: %v", err)
		return nil, fmt.Errorf("no function name found in lua scripts")
	}

	//	d.functions = append(d.functions, code.String())

	return d, nil
}

// Run will execute the script
func (d *LuaEngine) Run(pkt *Packet) error {
	/* preload */
	d.pkt = &pkt
	logp.Debug("data file", "DATA %s", pkt.GetPayload())

	for _, v := range d.functions {
		logp.Debug("script", "run function %s", v)
		err := d.LuaEngine.DoString(v)
		if err != nil {
			return err
		}
	}
	return nil
}
