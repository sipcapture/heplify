package sniffer

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/fsutil"
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
	f, err := fsutil.Create(baseFilename)
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
var movePcapMu sync.Mutex

// uniquePath returns path, or path with _2, _3, ... before its extension when
// path already exists.
func uniquePath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	base, ext := path, ""
	for _, e := range []string{".pcap.gz", ".pcap"} {
		if strings.HasSuffix(path, e) {
			base, ext = strings.TrimSuffix(path, e), e
			break
		}
	}
	for i := 2; ; i++ {
		p := fmt.Sprintf("%s_%d%s", base, i, ext)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p
		}
	}
}

func (s *Sniffer) movePcap(tmpName, outDir string) error {
	dateStr := time.Now().Format("2006/01/02/02.01.2006T15-04-05") +
		"_node" + strconv.Itoa(int(s.cfg.SystemSettings.NodeID)) + ".pcap"
	if s.cfg.PcapSettings.Compress {
		dateStr += ".gz"
		tmpName += ".gz"
	}
	newName := filepath.Join(outDir, dateStr)
	if err := os.MkdirAll(filepath.Dir(newName), fsutil.DirMode); err != nil {
		return err
	}
	if _, err := os.Stat(tmpName); os.IsNotExist(err) {
		return nil
	}
	// Fanout workers rotate in the same second: never overwrite another
	// worker's file, pick name_2.pcap, name_3.pcap, ... instead.
	movePcapMu.Lock()
	defer movePcapMu.Unlock()
	newName = uniquePath(newName)
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
	// Keep the in-progress file in outDir (not the working directory) so the
	// final rename stays on one filesystem.
	if err := os.MkdirAll(outDir, fsutil.DirMode); err != nil {
		log.Error().Err(err).Str("dir", outDir).Msg("Failed to create pcap directory, pcap writing disabled")
		return
	}
	tmpName := filepath.Join(outDir, fmt.Sprintf("%s_interface.pcap.tmp", filepath.Base(device)))

	// Attempt to move any leftover tmp file from a previous run.
	if err := s.movePcap(tmpName, outDir); err != nil {
		log.Warn().Err(err).Msg("Could not move leftover pcap file")
	}

	w, err := s.createPcap(tmpName, snaplen, lt)
	if err != nil {
		log.Error().Err(err).Msg("Failed to open pcap file, pcap writing disabled")
		return
	}

	ticker := time.NewTicker(time.Duration(rotateMin) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				// channel closed — flush and exit
				err = w.Close()
				if err != nil {
					log.Error().Err(err).Msg("Error closing pcap on shutdown")
				}
				_ = s.movePcap(tmpName, outDir)
				return
			}
			err = w.WritePacket(pkt.ci, pkt.data)
			if err != nil {
				log.Error().Err(err).Msg("Error writing pcap packet")
			}

		case <-ticker.C:
			err = w.Close()
			if err != nil {
				log.Error().Err(err).Msg("Error closing pcap before rotation")
			}
			err = s.movePcap(tmpName, outDir)
			if err != nil {
				log.Error().Err(err).Msg("Error rotating pcap file")
			}
			w, err = s.createPcap(tmpName, snaplen, lt)
			if err != nil {
				log.Error().Err(err).Msg("Failed to open new pcap file after rotation")
				return
			}

		}
	}
}
