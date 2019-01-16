package sniffer

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/gopacket/pcap"

	"github.com/negbie/logp"
)

var deviceAnySupported = runtime.GOOS == "linux"

// ListDeviceNames returns the list of adapters available for sniffing on
// this computer. If the withDescription parameter is set to true, a human
// readable version of the adapter name is added. If the withIP parameter
// is set to true, IP address of the adapter is added.
func ListDeviceNames(withDescription bool, withIP bool) ([]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return []string{}, err
	}

	ret := []string{}
	for _, dev := range devices {
		r := dev.Name

		if withDescription {
			desc := "No description available"
			if len(dev.Description) > 0 {
				desc = dev.Description
			}
			r += fmt.Sprintf(" (%s)", desc)
		}

		if withIP {
			ips := "Not assigned ip address"
			if len(dev.Addresses) > 0 {
				ips = ""

				for i, address := range []pcap.InterfaceAddress(dev.Addresses) {
					// Add a space between the IP address.
					if i > 0 {
						ips += " "
					}

					ips += address.IP.String()
				}
			}
			r += fmt.Sprintf(" (%s)", ips)

		}
		ret = append(ret, r)
	}
	filterDeviceName(ret)
	return ret, nil
}

func resolveDeviceName(name string) (string, error) {
	if name == "" {
		return "any", nil
	}

	if index, err := strconv.Atoi(name); err == nil { // Device is numeric id
		devices, err := ListDeviceNames(false, false)
		if err != nil {
			return "", fmt.Errorf("error getting devices list: %v", err)
		}

		name, err = deviceNameFromIndex(index, devices)
		if err != nil {
			return "", fmt.Errorf("couldn't understand device index %d: %v", index, err)
		}

		logp.Info("Resolved device index %d to device: %s", index, name)
	}

	return name, nil
}

func deviceNameFromIndex(index int, devices []string) (string, error) {
	if index >= len(devices) {
		return "", fmt.Errorf("looking for device index %d, but there are only %d devices",
			index, len(devices))
	}

	return devices[index], nil
}

func filterDeviceName(name []string) {
	for _, d := range name {
		if strings.HasPrefix(d, "bluetooth") || strings.HasPrefix(d, "dbus") || strings.HasPrefix(d, "nf") || strings.HasPrefix(d, "usb") {
			continue
		}
		fmt.Printf("-i %s\n", d)
	}
}
