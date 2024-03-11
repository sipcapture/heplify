-- this function will be executed first
function checkRAW()

    local protoType = GetHEPProtoType()

    Logp("DEBUG", "protoType", protoType)

    -- Check if we have SIP type 
    if protoType ~= 1 then
        return
    end

    -- original SIP message Payload
    local raw = GetRawMessage()
    Logp("DEBUG", "raw", raw)

    local _, _, name, value = string.find(raw, "(Call-ID:)%s*:%s*(.+)")
    --- local name, value = raw:match("(CSeq):%s+(.-)\n")

    -- do something with the raw message
    Logp("DEBUG", "name", name)
    Logp("DEBUG", "value", value)

    -- Set the raw message back
    SetRawMessage(raw)

    return

end

-- this function will be executed second
function checkHEP()

    -- get GetHEPSrcIP
    local src_ip = GetHEPSrcIP()

    -- a struct can be nil so better check it
    if (src_ip == nil or src_ip == '') then
        return
    end

    if src_ip == "127.0.0.1" then
        Logp("ERROR", "found bad src IP:", src_ip)
    end

    SetHEPField("SrcIP", "1.1.1.1")

    local dst_ip = GetHEPDstIP()

    -- a struct can be nil so better check it
    if (dst_ip == nil or dst_ip == '') then
        return
    end

    if dst_ip == "10.0.0.1" then
        Logp("ERROR", "found bad dst IP:", dst_ip)
    end

    SetHEPField("DstIP", "10.1.1.1")

    local src_port = GetHEPSrcPort()

    if src_port == 5060 then
        Logp("ERROR", "found bad src port", src_port)
    end

    SetHEPField("SrcPort", "9060")

    local dst_port = GetHEPDstPort()

    if dst_port == 5060 then
        Logp("ERROR", "found bad dst port", dst_port)
    end

    SetHEPField("DstPort", "9999")

    return

end

