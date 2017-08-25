
local _map = {}
      _map['0'] = '00000'
      _map['1'] = '00001'
      _map['2'] = '00010'
      _map['3'] = '00011'
      _map['4'] = '00100'
      _map['5'] = '00101'
      _map['6'] = '00110'
      _map['7'] = '00111'
      _map['8'] = '01000'
      _map['9'] = '01001'
      _map['b'] = '01010'
      _map['c'] = '01011'
      _map['d'] = '01100'
      _map['e'] = '01101'
      _map['f'] = '01110'
      _map['g'] = '01111'
      _map['h'] = '10000'
      _map['j'] = '10001'
      _map['k'] = '10010'
      _map['m'] = '10011'
      _map['n'] = '10100'
      _map['p'] = '10101'
      _map['q'] = '10110'
      _map['r'] = '10111'
      _map['s'] = '11000'
      _map['t'] = '11001'
      _map['u'] = '11010'
      _map['v'] = '11011'
      _map['w'] = '11100'
      _map['x'] = '11101'
      _map['y'] = '11110'
      _map['z'] = '11111'


local function _toBin(coord, min, max)
    local mid = 0.0
    local x   = 0.0
    local y   = 0.0
    local p   = 5 * 6
    local result = ''
    for i = 1, p do
        if coord <= max and coord >= mid then
            result = result .. '1'
            x = mid
            y = max
        else
            result = result .. '0'
            x = min
            y = mid
        end
        min = x
        mid = x + ((y - x) / 2)
        max = y
    end
    return result
end

local function _combine(latbin, lonbin)
    local res = ''
    for i = 1, #latbin do
        res = res .. lonbin:sub(i, i)  .. latbin:sub(i, i)
    end
    return res
end

local function _swap(tbl)
    local table = {}
    for key, val in pairs(tbl) do
        table[val] = key
    end
    return table
end

local function _transform(bstr)
    local hash = ''
    local t = _swap(_map)
    for i = 1, #bstr, 5 do
        hash = hash .. t[bstr:sub(i, i + 4)]
    end
    sr.pv.sets("$var(ghash)", hash)
    -- sr.pv.sets("$avp(ghash)", hash)
    -- sr.log("crit", "Wrong geohash")
    return hash
end

function GeoHash(lat, lon)
    local tmpLat = _toBin(tonumber(lat), -90.0, 90.0)
    local tmpLon = _toBin(tonumber(lon), -180.0, 180.0)
    return _transform(_combine(tmpLat, tmpLon))
end  
