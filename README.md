# heplify

### Usage of ./heplify:

```bash
  -b int
        Interface buffer size (MB) (default 128)
  -d string
        Enable certain debug selectors
  -df string
        Dump to file
  -dh
        Use Hep (default true)
  -e    Log to stderr and disable syslog/file output
  -f string
        BPF filter (default "greater 300 and portrange 5060-5090")
  -hf string
        Filter like REGISTER, OPTIONS
  -hs string
        HepServer address (default "127.0.0.1:9060")
  -i string
        Listen on interface
  -k int
        Keep the number of log files (default 4)
  -l string
        Logging level (default "info")
  -lp int
        Loop
  -n string
        Log filename (default "heplify.log")
  -o    Read packet for packet
  -p string
        Log path
  -r uint
        The size (KB) of each log file (default 51200)
  -rf string
        Read packets from file
  -s int
        Snap length (default 65535)
  -t string
        Capture type are pcap or af_packet (default "af_packet")
  -ts
        Topspeed (default true)
  -v    Log at INFO level
  -wl
        With vlans
  
################################################################
./heplify -i eth0 -hf REGISTER


The last command will send HEP messages to localhost Homer. Messages will be captured from eth0.
It will filter out REGISTER and the default BPF Filter is greater 300 and portrange 5060-5090.
```