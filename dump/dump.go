package dump

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/negbie/logp"
	"github.com/sipcapture/heplify/config"
)

type pcapWriter interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
	Close() error
}

type defaultPcapWriter struct {
	io.WriteCloser
	*Writer
}

type gzipPcapWriter struct {
	w io.WriteCloser
	z *gzip.Writer
	*Writer
}

type Packet struct {
	Ci   gopacket.CaptureInfo
	Data []byte
}

func (wrapper *gzipPcapWriter) Close() error {
	gzerr := wrapper.z.Close()
	ferr := wrapper.w.Close()

	if gzerr != nil {
		return gzerr
	}
	if ferr != nil {
		return ferr
	}
	return nil
}

func createPcap(baseFilename string, lt layers.LinkType) (pcapWriter, error) {
	if config.Cfg.Zip {
		baseFilename = baseFilename + ".gz"
	}
	logp.Info("opening new pcap file %s", baseFilename)
	f, err := os.Create(baseFilename)
	if err != nil {
		return nil, err
	}
	if config.Cfg.Zip {
		o := gzip.NewWriter(f)
		w := NewWriter(o)
		w.WriteFileHeader(uint32(config.Cfg.Iface.Snaplen), lt)
		return &gzipPcapWriter{f, o, w}, nil
	}

	w := NewWriter(f)
	// It's a new file, so we need to create a new writer
	w.WriteFileHeader(uint32(config.Cfg.Iface.Snaplen), lt)
	return &defaultPcapWriter{f, w}, nil

}

func movePcap(tempName, outputPath string) error {
	dateString := time.Now().Format("2006/01/02/02.01.2006T15-04-05") + "_node" + strconv.Itoa(int(config.Cfg.HepNodeID)) + ".pcap"
	if config.Cfg.Zip {
		dateString = dateString + ".gz"
		tempName = tempName + ".gz"
	}

	newName := filepath.Join(outputPath, dateString)
	// Make sure that the directory exists
	if err := os.MkdirAll(filepath.Dir(newName), 0777); err != nil {
		return err
	}
	err := os.Rename(tempName, newName)

	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		logp.Info("moved %s to %s", tempName, newName)
	}
	return nil
}

func Save(dc chan *Packet, lt layers.LinkType) {
	outPath := config.Cfg.Iface.WriteFile
	tmpName := fmt.Sprintf("%s_interface.pcap.tmp", config.Cfg.Iface.Device)
	tmpName = strings.ReplaceAll(tmpName, "\\", "")

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(time.Duration(config.Cfg.Iface.RotationTime) * time.Minute)

	// Move and rename any leftover pcap files from a previous run
	movePcap(tmpName, outPath)

	w, err := createPcap(tmpName, lt)
	if err != nil {
		logp.Err("Error opening pcap: %v", err)
	}

	for {
		select {
		case packet := <-dc:
			err := w.WritePacket(packet.Ci, packet.Data)
			if err != nil {
				w.Close()
				logp.Err("Error writing output pcap: %v", err)
			}

		case <-ticker.C:
			err = w.Close()
			if err != nil {
				logp.Err("Error closing pcap: %v", err)
			}
			err = movePcap(tmpName, outPath)
			if err != nil {
				logp.Err("Error renaming pcap: %v", err)
			}
			w, err = createPcap(tmpName, lt)
			if err != nil {
				logp.Err("Error opening pcap: %v", err)
			}

		case <-signals:
			logp.Info("Received stop signal")
			err = w.Close()
			if err != nil {
				logp.Err("Error Closing: %v", err)
			}
			err = movePcap(tmpName, outPath)
			if err != nil {
				logp.Err("Error renaming pcap: %v", err)
			}
			os.Exit(0)
		}
	}
}
