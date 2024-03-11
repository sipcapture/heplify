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

func (d *LuaEngine) GetHEPStruct() interface{} {
	if (*d.pkt) == nil {
		return ""
	}
	return (*d.pkt)
}

/*
func (d *LuaEngine) GetSIPStruct() interface{} {

	return (*d.pkt).SIP
}
*/

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

func (d *LuaEngine) SetCustomSIPHeader(m *map[string]string) {
	/*if (*d.pkt).SIP == nil {
		logp.Err("can't set custom SIP header if SIP struct is nil, please check for nil in lua script")
		return
	}
	pkt := *d.pkt

	if pkt.SIP.CustomHeader == nil {
		pkt.SIP.CustomHeader = make(map[string]string)
	}

	for k, v := range *m {
		pkt.SIP.CustomHeader[k] = v
	}
	*/
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

func (d *LuaEngine) SetSIPProfile(p string) {
	/*pkt := *d.pkt
	if strings.HasPrefix(p, "c") || strings.HasPrefix(p, "C") {
		pkt.SIP.Profile = "call"
	} else if strings.HasPrefix(p, "r") || strings.HasPrefix(p, "R") {
		pkt.SIP.Profile = "registration"
	} else {
		pkt.SIP.Profile = "default"
	}
	*/
}

func (d *LuaEngine) SetSIPHeader(header string, value string) {

	/*
		if (*d.pkt).SIP == nil {
			logp.Err("can't set SIP header if SIP struct is nil, please check for nil in lua script")
			return
		}
		pkt := *d.pkt

		switch header {
		case "FromUser", "from_user":
			pkt.SIP.FromUser = value
		case "FromHost", "from_domain":
			pkt.SIP.FromHost = value
		case "FromTag", "from_tag":
			pkt.SIP.FromTag = value
		case "ToUser", "to_user":
			pkt.SIP.ToUser = value
		case "ToHost", "to_domain":
			pkt.SIP.ToHost = value
		case "ToTag", "to_tag":
			pkt.SIP.ToTag = value
		case "URIUser", "ruri_user":
			pkt.SIP.URIUser = value
		case "URIHost", "ruri_domain":
			pkt.SIP.URIHost = value
		case "CallID":
			pkt.SIP.CallID = value
		case "Method":
			pkt.SIP.FirstMethod = value
		case "ContactUser", "contact_user":
			pkt.SIP.ContactUser = value
		case "ContactHost", "contact_domain":
			pkt.SIP.ContactHost = value
		case "AuthUser", "auth_user":
			pkt.SIP.AuthUser = value
		case "UserAgent", "user_agent":
			pkt.SIP.UserAgent = value
		case "Server":
			pkt.SIP.Server = value
		case "PaiUser", "pid_user":
			pkt.SIP.PaiUser = value
		case "PaiHost", "pid_domain":
			pkt.SIP.PaiHost = value
		case "ViaOne", "via":
			pkt.SIP.ViaOne = value
		case "XCallID", "callid_aleg":
			pkt.SIP.XCallID = value
		default:
			if pkt.SIP.CustomHeader == nil {
				pkt.SIP.CustomHeader = make(map[string]string)
			}
			pkt.SIP.CustomHeader[header] = value
		}
	*/
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
		"GetHEPStruct": d.GetHEPStruct,
		//"GetSIPStruct":       d.GetSIPStruct,
		"GetHEPProtoType":    d.GetHEPProtoType,
		"GetHEPSrcIP":        d.GetHEPSrcIP,
		"GetHEPSrcPort":      d.GetHEPSrcPort,
		"GetHEPDstIP":        d.GetHEPDstIP,
		"GetHEPDstPort":      d.GetHEPDstPort,
		"GetHEPTimeSeconds":  d.GetHEPTimeSeconds,
		"GetHEPTimeUseconds": d.GetHEPTimeUseconds,
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
func (d *LuaEngine) Run(pkt *Packet) error {
	/* preload */
	d.pkt = &pkt

	for _, v := range d.functions {
		err := d.LuaEngine.DoString(v)
		if err != nil {
			return err
		}
	}
	return nil
}
