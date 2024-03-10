package decoder

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/negbie/logp"
	"github.com/sipcapture/golua/lua"
	"github.com/sipcapture/heplify/decoder/luar"
)

// LuaEngine
type LuaEngine struct {
	/* pointer to modify */
	hepPkt    **HEP
	functions []string
	LuaEngine *lua.State
}

func (d *LuaEngine) GetHEPStruct() interface{} {
	if (*d.hepPkt) == nil {
		return ""
	}
	return (*d.hepPkt)
}

func (d *LuaEngine) GetHEPProtoType() uint32 {
	return (*d.hepPkt).GetProtoType()
}

func (d *LuaEngine) GetHEPSrcIP() string {
	return (*d.hepPkt).GetSrcIP()
}

func (d *LuaEngine) GetHEPSrcPort() uint32 {
	return (*d.hepPkt).GetSrcPort()
}

func (d *LuaEngine) GetHEPDstIP() string {
	return (*d.hepPkt).GetDstIP()
}

func (d *LuaEngine) GetHEPDstPort() uint32 {
	return (*d.hepPkt).GetDstPort()
}

func (d *LuaEngine) GetHEPTimeSeconds() uint32 {
	return (*d.hepPkt).GetTsec()
}

func (d *LuaEngine) GetHEPTimeUseconds() uint32 {
	return (*d.hepPkt).GetTmsec()
}

func (d *LuaEngine) GetHEPNodeID() uint32 {
	return (*d.hepPkt).GetNodeID()
}

func (d *LuaEngine) GetRawMessage() string {
	return (*d.hepPkt).GetPayload()
}

func (d *LuaEngine) SetRawMessage(value string) {
	if (*d.hepPkt) == nil {
		logp.Err("can't set Raw message if HEP struct is nil, please check for nil in lua script")
		return
	}
	hepPkt := *d.hepPkt
	hepPkt.Payload = value
}

func (d *LuaEngine) SetCustomSIPHeader(m *map[string]string) {
	if (*d.hepPkt).SIP == nil {
		logp.Err("can't set custom SIP header if SIP struct is nil, please check for nil in lua script")
		return
	}
	hepPkt := *d.hepPkt

	if hepPkt.SIP.CustomHeader == nil {
		hepPkt.SIP.CustomHeader = make(map[string]string)
	}

	for k, v := range *m {
		hepPkt.SIP.CustomHeader[k] = v
	}
}

func (d *LuaEngine) SetHEPField(field string, value string) {
	if (*d.hepPkt) == nil {
		logp.Err("can't set HEP field if HEP struct is nil, please check for nil in lua script")
		return
	}
	hepPkt := *d.hepPkt

	switch field {
	case "ProtoType":
		if i, err := strconv.Atoi(value); err == nil {
			hepPkt.ProtoType = uint32(i)
		}
	case "SrcIP":
		hepPkt.SrcIP = value
	case "SrcPort":
		if i, err := strconv.Atoi(value); err == nil {
			hepPkt.SrcPort = uint32(i)
		}
	case "DstIP":
		hepPkt.DstIP = value
	case "DstPort":
		if i, err := strconv.Atoi(value); err == nil {
			hepPkt.DstPort = uint32(i)
		}
	case "NodeID":
		if i, err := strconv.Atoi(value); err == nil {
			hepPkt.NodeID = uint32(i)
		}
	case "CID":
		hepPkt.CID = value
	case "SID":
		hepPkt.SID = value
	case "NodeName":
		hepPkt.NodeName = value
	case "TargetName":
		hepPkt.TargetName = value
	}
}

func (d *LuaEngine) SetSIPProfile(p string) {
	hepPkt := *d.hepPkt
	if strings.HasPrefix(p, "c") || strings.HasPrefix(p, "C") {
		hepPkt.SIP.Profile = "call"
	} else if strings.HasPrefix(p, "r") || strings.HasPrefix(p, "R") {
		hepPkt.SIP.Profile = "registration"
	} else {
		hepPkt.SIP.Profile = "default"
	}
}

func (d *LuaEngine) SetSIPHeader(header string, value string) {
	if (*d.hepPkt).SIP == nil {
		logp.Err("can't set SIP header if SIP struct is nil, please check for nil in lua script")
		return
	}
	hepPkt := *d.hepPkt

	switch header {
	case "FromUser", "from_user":
		hepPkt.SIP.FromUser = value
	case "FromHost", "from_domain":
		hepPkt.SIP.FromHost = value
	case "FromTag", "from_tag":
		hepPkt.SIP.FromTag = value
	case "ToUser", "to_user":
		hepPkt.SIP.ToUser = value
	case "ToHost", "to_domain":
		hepPkt.SIP.ToHost = value
	case "ToTag", "to_tag":
		hepPkt.SIP.ToTag = value
	case "URIUser", "ruri_user":
		hepPkt.SIP.URIUser = value
	case "URIHost", "ruri_domain":
		hepPkt.SIP.URIHost = value
	case "CallID":
		hepPkt.SIP.CallID = value
	case "Method":
		hepPkt.SIP.FirstMethod = value
	case "ContactUser", "contact_user":
		hepPkt.SIP.ContactUser = value
	case "ContactHost", "contact_domain":
		hepPkt.SIP.ContactHost = value
	case "AuthUser", "auth_user":
		hepPkt.SIP.AuthUser = value
	case "UserAgent", "user_agent":
		hepPkt.SIP.UserAgent = value
	case "Server":
		hepPkt.SIP.Server = value
	case "PaiUser", "pid_user":
		hepPkt.SIP.PaiUser = value
	case "PaiHost", "pid_domain":
		hepPkt.SIP.PaiHost = value
	case "ViaOne", "via":
		hepPkt.SIP.ViaOne = value
	case "XCallID", "callid_aleg":
		hepPkt.SIP.XCallID = value
	default:
		if hepPkt.SIP.CustomHeader == nil {
			hepPkt.SIP.CustomHeader = make(map[string]string)
		}
		hepPkt.SIP.CustomHeader[header] = value
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

	luar.Register(d.LuaEngine, "", luar.Map{
		"GetHEPStruct":       d.GetHEPStruct,
		"GetSIPStruct":       d.GetSIPStruct,
		"GetHEPProtoType":    d.GetHEPProtoType,
		"GetHEPSrcIP":        d.GetHEPSrcIP,
		"GetHEPSrcPort":      d.GetHEPSrcPort,
		"GetHEPDstIP":        d.GetHEPDstIP,
		"GetHEPDstPort":      d.GetHEPDstPort,
		"GetHEPTimeSeconds":  d.GetHEPTimeSeconds,
		"GetHEPTimeUseconds": d.GetHEPTimeUseconds,
		"GetHEPNodeID":       d.GetHEPNodeID,
		"GetRawMessage":      d.GetRawMessage,
		"SetRawMessage":      d.SetRawMessage,
		"SetCustomSIPHeader": d.SetCustomSIPHeader,
		"SetHEPField":        d.SetHEPField,
		"SetSIPProfile":      d.SetSIPProfile,
		"SetSIPHeader":       d.SetSIPHeader,
		"HashTable":          HashTable,
		"HashString":         HashString,
		"Logp":               d.Logp,
		"Print":              fmt.Println,
	})

	_, code, err := scanCode()
	if err != nil {
		return nil, err
	}

	err = d.LuaEngine.DoString(code.String())
	if err != nil {
		return nil, err
	}

	d.functions = extractFunc(code)
	if len(d.functions) < 1 {
		return nil, fmt.Errorf("no function name found in lua scripts")
	}

	return d, nil
}

// Run will execute the script
func (d *LuaEngine) Run(hep *HEP) error {
	/* preload */
	d.hepPkt = &hep

	for _, v := range d.functions {
		err := d.LuaEngine.DoString(v)
		if err != nil {
			return err
		}
	}
	return nil
}
