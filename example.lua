-- Example Lua Script for heplify-ng

function onPacket(proto)
    print("Lua: Packet captured! Protocol: " .. proto)
end

print("Lua: Script loaded successfully")
