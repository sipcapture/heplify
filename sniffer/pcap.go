package sniffer

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/negbie/heplify/config"
	"github.com/negbie/heplify/logp"
)

type pcapWriter interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
	Close() error
}

type defaultPcapWriter struct {
	io.WriteCloser
	*pcapgo.Writer
}

type gzipPcapWriter struct {
	w io.WriteCloser
	z *gzip.Writer
	*pcapgo.Writer
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

func (sniffer *SnifferSetup) createPcap(baseFilename string) (pcapWriter, error) {
	if config.Cfg.Gzip {
		baseFilename = baseFilename + ".gz"
	}
	logp.Info("opening new pcap file %s", baseFilename)
	f, err := os.Create(baseFilename)
	if err != nil {
		return nil, err
	}
	if config.Cfg.Gzip {
		o := gzip.NewWriter(f)
		w := pcapgo.NewWriter(o)
		w.WriteFileHeader(uint32(sniffer.config.Snaplen), sniffer.Datalink())
		return &gzipPcapWriter{f, o, w}, nil
	}

	w := pcapgo.NewWriter(f)
	// It's a new file, so we need to create a new writer
	w.WriteFileHeader(uint32(sniffer.config.Snaplen), sniffer.Datalink())
	return &defaultPcapWriter{f, w}, nil

}

func (sniffer *SnifferSetup) movePcap(tempName, outputPath string) error {
	dateString := time.Now().Format("2006/01/02/02.01.2006T15-04-05") + "_node" + strconv.Itoa(int(config.Cfg.HepNodeID)) + ".pcap"
	if config.Cfg.Gzip {
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

func (sniffer *SnifferSetup) dumpPcap() {
	outPath := sniffer.config.WriteFile
	tmpName := fmt.Sprintf("%s_interface.pcap.tmp", sniffer.config.Device)

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(time.Duration(sniffer.config.RotationTime) * time.Minute)

	// Move and rename any leftover pcap files from a previous run
	sniffer.movePcap(tmpName, outPath)

	w, err := sniffer.createPcap(tmpName)
	if err != nil {
		logp.Err("Error opening pcap: %v", err)
	}

	for {
		select {
		case packet := <-sniffer.dumpChan:
			err := w.WritePacket(packet.ci, packet.data)
			if err != nil {
				w.Close()
				logp.Err("Error writing output pcap: %v", err)
			}

		case <-ticker.C:
			err = w.Close()
			if err != nil {
				logp.Err("Error closing pcap: %v", err)
			}
			err = sniffer.movePcap(tmpName, outPath)
			if err != nil {
				logp.Err("Error renaming pcap: %v", err)
			}
			w, err = sniffer.createPcap(tmpName)
			if err != nil {
				logp.Err("Error opening pcap: %v", err)
			}

		case <-signals:
			logp.Info("Received stop signal")
			err = w.Close()
			if err != nil {
				logp.Err("Error Closing: %v", err)
			}
			err = sniffer.movePcap(tmpName, outPath)
			if err != nil {
				logp.Err("Error renaming pcap: %v", err)
			}
			os.Exit(0)
		}
	}
}
