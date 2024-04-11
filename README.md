<a href="https://sipcapture.org"><img src="https://user-images.githubusercontent.com/1423657/55069501-8348c400-5084-11e9-9931-fefe0f9874a7.png" width=200/></a>

<img src="https://github.com/sipcapture/heplify/assets/1423657/7a36896d-0bd3-4cf3-9525-0513e67aee46">

This is a fork of [heplify](https://github.com/sipcapture/heplify) - captagents little brother, optimized for speed and simplicity. It's a single binary which you can run
on Linux, ARM, MIPS, Windows to capture IPv4 or IPv6 packets and send them to Homer. Heplify is able to send
SIP, correlated RTCP, RTCPXR, DNS, Logs into homer.
It's able to handle fragmented and duplicate packets out of the box.  
  
This fork adds MTLS support.

## Usage

### Linux

None if you use the binary from the releases

### Windows

[WinPcap](https://www.winpcap.org/install/default.htm)

## Installation

### Linux

Download [heplify](TBD) and execute 'chmod +x heplify'

### Windows

Download [heplify.exe](TBD)

## Building

You should install LUA Jit, libpcap-devel, libpcap1:  
`sudo zypper in libpcap-devel libpcap1 luajit-devel`  

For macOS, see [heplify](https://github.com/sipcapture/heplify) Github page

If you have Go 1.18+ installed, build the latest heplify binary by running `make`.
 

## Usage

```bash
 -help
 -hs  
...TBC  

```
### Made by Humans

This Open-Source project is made possible by actual Humans without corporate sponsors, angels or patreons. Please see links below to support the original developers of this tool.

If you use this software in production, please consider supporting its development with contributions or [donations](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=donation%40sipcapture%2eorg&lc=US&item_name=SIPCAPTURE&no_note=0&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHostedGuest)
