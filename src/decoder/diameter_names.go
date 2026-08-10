package decoder

func diameterCommandName(code uint32) string {
	switch code {
	case 257:
		return "Capabilities-Exchange (CER/CEA)"
	case 258:
		return "Re-Authorization (RAR/RAA)"
	case 271:
		return "Accounting (ACR/ACA)"
	case 272:
		return "Credit-Control (CCR/CCA)"
	case 274:
		return "Abort-Session (ASR/ASA)"
	case 275:
		return "Session-Termination (STR/STA)"
	case 280:
		return "Device-Watchdog (DWR/DWA)"
	case 282:
		return "Disconnect-Peer (DPR/DPA)"
	case 300:
		return "User-Authorization (UAR/UAA)"
	case 301:
		return "Server-Assignment (SAR/SAA)"
	case 303:
		return "Multimedia-Auth (MAR/MAA)"
	case 304:
		return "Registration-Termination (RTR/RTA)"
	case 305:
		return "Push-Profile (PPR/PPA)"
	case 306:
		return "User-Data (UDR/UDA)"
	case 307:
		return "Profile-Update (PUR/PUA)"
	case 308:
		return "Subscribe-Notifications (SNR/SNA)"
	case 309:
		return "Push-Notification (PNR/PNA)"
	case 316:
		return "3GPP-Update-Location (ULR/ULA)"
	case 317:
		return "3GPP-Cancel-Location (CLR/CLA)"
	case 318:
		return "3GPP-Authentication-Information (AIR/AIA)"
	case 319:
		return "3GPP-Insert-Subscriber-Data (IDR/IDA)"
	case 320:
		return "3GPP-Delete-Subscriber-Data (DSR/DSA)"
	case 321:
		return "3GPP-Purge-UE (PUR/PUA)"
	case 322:
		return "3GPP-Reset (RSR/RSA)"
	case 323:
		return "3GPP-Notify (NFR/NFA)"
	case 324:
		return "3GPP-ME-Identity-Check (MIC/MIA)"
	default:
		return ""
	}
}

func diameterApplicationName(id uint32) string {
	switch id {
	case 0:
		return "Diameter common message"
	case 3:
		return "Diameter base accounting"
	case 4:
		return "Diameter Credit Control"
	case 6:
		return "Diameter SIP Application"
	case 16777216:
		return "3GPP Cx"
	case 16777217:
		return "3GPP Sh"
	case 16777224, 16777238:
		return "3GPP Gx"
	case 16777229, 16777236:
		return "3GPP Rx"
	case 16777251:
		return "3GPP S6a"
	case 16777252:
		return "3GPP S13"
	case 16777255:
		return "3GPP SLg"
	case 16777345:
		return "3GPP S6t"
	default:
		return "unknown"
	}
}

func diameterCommandFlagsName(f uint8) string {
	var s string
	if f&0x80 != 0 {
		s += "Request"
	}
	if f&0x40 != 0 {
		if s != "" {
			s += "|"
		}
		s += "Proxyable"
	}
	if f&0x20 != 0 {
		if s != "" {
			s += "|"
		}
		s += "Error"
	}
	if f&0x10 != 0 {
		if s != "" {
			s += "|"
		}
		s += "reTransmit"
	}
	return s
}

func diameterVendorName(vendorID uint32) string {
	switch vendorID {
	case 0:
		return "IETF"
	case 10415:
		return "3GPP"
	case 13019:
		return "ETSI"
	case 193:
		return "Nokia"
	case 263:
		return "Ericsson"
	case 127:
		return "Huawei"
	default:
		return ""
	}
}

func diameterAVPName(code uint32) string {
	switch code {
	case 1:
		return "User-Name"
	case 25:
		return "Class"
	case 27:
		return "Session-Timeout"
	case 33:
		return "Proxy-State"
	case 44:
		return "Accounting-Session-Id"
	case 55:
		return "Event-Timestamp"
	case 85:
		return "Acct-Interim-Interval"
	case 257:
		return "Host-IP-Address"
	case 258:
		return "Auth-Application-Id"
	case 259:
		return "Acct-Application-Id"
	case 260:
		return "Vendor-Specific-Application-Id"
	case 261:
		return "Redirect-Host-Usage"
	case 262:
		return "Redirect-Max-Cache-Time"
	case 263:
		return "Session-Id"
	case 264:
		return "Origin-Host"
	case 265:
		return "Supported-Vendor-Id"
	case 266:
		return "Vendor-Id"
	case 267:
		return "Firmware-Revision"
	case 268:
		return "Result-Code"
	case 269:
		return "Product-Name"
	case 270:
		return "Session-Binding"
	case 271:
		return "Session-Server-Failover"
	case 272:
		return "Multi-Round-Time-Out"
	case 273:
		return "Disconnect-Cause"
	case 274:
		return "Auth-Request-Type"
	case 276:
		return "Auth-Grace-Period"
	case 277:
		return "Auth-Session-State"
	case 278:
		return "Origin-State-Id"
	case 279:
		return "Failed-AVP"
	case 280:
		return "Proxy-Host"
	case 281:
		return "Error-Message"
	case 282:
		return "Route-Record"
	case 283:
		return "Destination-Realm"
	case 284:
		return "Proxy-Info"
	case 285:
		return "Re-Auth-Request-Type"
	case 291:
		return "Authorization-Lifetime"
	case 292:
		return "Redirect-Host"
	case 293:
		return "Destination-Host"
	case 294:
		return "Error-Reporting-Host"
	case 295:
		return "Termination-Cause"
	case 296:
		return "Origin-Realm"
	case 297:
		return "Experimental-Result"
	case 298:
		return "Experimental-Result-Code"
	case 299:
		return "Inband-Security-Id"
	case 415:
		return "CC-Request-Number"
	case 416:
		return "CC-Request-Type"
	case 461:
		return "Service-Context-Id"
	case 480:
		return "Accounting-Record-Type"
	case 485:
		return "Accounting-Record-Number"
	case 601:
		return "Public-Identity"
	case 602:
		return "Server-Name"
	case 603:
		return "Server-Capabilities"
	case 604:
		return "Mandatory-Capability"
	case 605:
		return "Optional-Capability"
	case 606:
		return "User-Data"
	case 607:
		return "SIP-Number-Auth-Items"
	case 608:
		return "SIP-Authentication-Scheme"
	case 609:
		return "SIP-Authenticate"
	case 610:
		return "SIP-Authorization"
	case 612:
		return "SIP-Auth-Data-Item"
	case 613:
		return "SIP-Item-Number"
	case 628:
		return "Supported-Features"
	case 629:
		return "Feature-List-ID"
	case 630:
		return "Feature-List"
	case 700:
		return "User-Identity"
	case 701:
		return "MSISDN"
	case 1400:
		return "Subscription-Data"
	case 1401:
		return "Terminal-Information"
	case 1402:
		return "IMEI"
	case 1403:
		return "Software-Version"
	case 1406:
		return "ULR-Flags"
	case 1407:
		return "ULA-Flags"
	case 1408:
		return "Visited-PLMN-Id"
	case 1410:
		return "Cancellation-Type"
	case 1412:
		return "CLR-Flags"
	case 1413:
		return "Authentication-Info"
	case 1414:
		return "E-UTRAN-Vector"
	default:
		return ""
	}
}
