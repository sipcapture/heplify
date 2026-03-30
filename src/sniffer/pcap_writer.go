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
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/rs/zerolog/log"
)

// dumpPacket holds raw packet data destined for pcap writing.
type dumpPacket struct {
	ci   gopacket.CaptureInfo
	data []byte
}

// pcapWriter is a write-closer that accepts gopacket capture data.
type pcapWriter interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
	Close() error
}

type defaultPcapWriter struct {
	io.WriteCloser
	*pcapgo.Writer
}

type gzipPcapWriter struct {
	f io.WriteCloser
	z *gzip.Writer
	*pcapgo.Writer
}

func (g *gzipPcapWriter) Close() error {
	ge := g.z.Close()
	fe := g.f.Close()
	if ge != nil {
		return ge
	}
	return fe
}

// createPcap opens a new pcap (or pcap.gz) file and writes the file header.
func (s *Sniffer) createPcap(baseFilename string, snaplen int, lt layers.LinkType) (pcapWriter, error) {
	if s.cfg.PcapSettings.Compress {
		baseFilename += ".gz"
	}
	log.Info().Str("file", baseFilename).Msg("Opening pcap file")
	f, err := os.Create(baseFilename)
	if err != nil {
		return nil, err
	}
	if s.cfg.PcapSettings.Compress {
		z := gzip.NewWriter(f)
		w := pcapgo.NewWriter(z)
		if err := w.WriteFileHeader(uint32(snaplen), lt); err != nil {
			f.Close()
			return nil, err
		}
		return &gzipPcapWriter{f, z, w}, nil
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(uint32(snaplen), lt); err != nil {
		f.Close()
		return nil, err
	}
	return &defaultPcapWriter{f, w}, nil
}

// movePcap renames tmpName to a date-stamped path under outDir.
// Final path: outDir/YYYY/MM/DD/DD.MM.YYYYTHH-MM-SS_nodeNN.pcap[.gz]
func (s *Sniffer) movePcap(tmpName, outDir string) error {
	dateStr := time.Now().Format("2006/01/02/02.01.2006T15-04-05") +
		"_node" + strconv.Itoa(int(s.cfg.SystemSettings.NodeID)) + ".pcap"
	if s.cfg.PcapSettings.Compress {
		dateStr += ".gz"
		tmpName += ".gz"
	}
	newName := filepath.Join(outDir, dateStr)
	if err := os.MkdirAll(filepath.Dir(newName), 0o777); err != nil {
		return err
	}
	err := os.Rename(tmpName, newName)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		log.Info().Str("from", tmpName).Str("to", newName).Msg("Rotated pcap file")
	}
	return nil
}

// dumpPcap reads from ch and writes packets to a pcap file, rotating on a
// time ticker or on process termination.
func (s *Sniffer) dumpPcap(ch <-chan dumpPacket, device string, lt layers.LinkType) {
	outDir := s.cfg.PcapSettings.WriteFile
	rotateMin := s.cfg.PcapSettings.RotateMinutes
	if rotateMin <= 0 {
		rotateMin = 60
	}

	snaplen := 65535
	tmpName := fmt.Sprintf("%s_interface.pcap.tmp", device)

	// Attempt to move any leftover tmp file from a previous run.
	if err := s.movePcap(tmpName, outDir); err != nil {
		log.Warn().Err(err).Msg("Could not move leftover pcap file")
	}

	w, err := s.createPcap(tmpName, snaplen, lt)
	if err != nil {
		log.Error().Err(err).Msg("Failed to open pcap file, pcap writing disabled")
		return
	}

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(time.Duration(rotateMin) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				// channel closed — flush and exit
				if err := w.Close(); err != nil {
					log.Error().Err(err).Msg("Error closing pcap on shutdown")
				}
				_ = s.movePcap(tmpName, outDir)
				return
			}
			if err := w.WritePacket(pkt.ci, pkt.data); err != nil {
				log.Error().Err(err).Msg("Error writing pcap packet")
			}

		case <-ticker.C:
			if err := w.Close(); err != nil {
				log.Error().Err(err).Msg("Error closing pcap before rotation")
			}
			if err := s.movePcap(tmpName, outDir); err != nil {
				log.Error().Err(err).Msg("Error rotating pcap file")
			}
			w, err = s.createPcap(tmpName, snaplen, lt)
			if err != nil {
				log.Error().Err(err).Msg("Failed to open new pcap file after rotation")
				return
			}

		case <-signals:
			log.Info().Msg("pcap writer received stop signal")
			if err := w.Close(); err != nil {
				log.Error().Err(err).Msg("Error closing pcap on signal")
			}
			_ = s.movePcap(tmpName, outDir)
			os.Exit(0)
		}
	}
}
