package dump

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

// Rotator manages PCAP file rotation
type Rotator struct {
	path          string
	rotateMinutes int
	compress      bool
	snaplen       uint32
	linktype      layers.LinkType

	mu         sync.Mutex
	file       *os.File
	writer     *Writer
	gzWriter   *gzip.Writer
	rotateTime time.Time
	closed     bool
}

// NewRotator creates a new PCAP rotator
func NewRotator(path string, rotateMinutes int, compress bool, snaplen uint32, linktype layers.LinkType) *Rotator {
	r := &Rotator{
		path:          path,
		rotateMinutes: rotateMinutes,
		compress:      compress,
		snaplen:       snaplen,
		linktype:      linktype,
	}

	if r.rotateMinutes <= 0 {
		r.rotateMinutes = 60
	}

	if r.snaplen == 0 {
		r.snaplen = 65535
	}

	return r
}

// Start opens the first PCAP file
func (r *Rotator) Start() error {
	return r.rotate()
}

// WritePacket writes a packet to the current PCAP file, rotating if necessary
func (r *Rotator) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("rotator is closed")
	}

	// Check if we need to rotate
	if time.Now().After(r.rotateTime) {
		if err := r.rotateUnlocked(); err != nil {
			return err
		}
	}

	return r.writer.WritePacket(ci, data)
}

func (r *Rotator) rotate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rotateUnlocked()
}

func (r *Rotator) rotateUnlocked() error {
	// Close existing file if any
	if r.file != nil {
		if r.gzWriter != nil {
			r.gzWriter.Close()
			r.gzWriter = nil
		}
		r.file.Close()
		r.file = nil
	}

	// Generate filename with timestamp
	now := time.Now()
	filename := fmt.Sprintf("%s_%s.pcap", r.path, now.Format("20060102_150405"))
	if r.compress {
		filename += ".gz"
	}

	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Open new file
	var err error
	r.file, err = os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create pcap file: %v", err)
	}

	// Set up writer (with or without compression)
	var w io.Writer = r.file
	if r.compress {
		r.gzWriter = gzip.NewWriter(r.file)
		w = r.gzWriter
	}

	r.writer = NewWriter(w)

	// Write file header
	if err := r.writer.WriteFileHeader(r.snaplen, r.linktype); err != nil {
		r.file.Close()
		return fmt.Errorf("failed to write pcap header: %v", err)
	}

	// Set next rotation time
	r.rotateTime = now.Add(time.Duration(r.rotateMinutes) * time.Minute)

	log.Info().Str("file", filename).Time("next_rotate", r.rotateTime).Msg("Opened new PCAP file")

	return nil
}

// Close closes the rotator and underlying file
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.closed = true

	if r.gzWriter != nil {
		r.gzWriter.Close()
		r.gzWriter = nil
	}

	if r.file != nil {
		err := r.file.Close()
		r.file = nil
		return err
	}

	return nil
}

// GetCurrentFilename returns the current PCAP filename
func (r *Rotator) GetCurrentFilename() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file != nil {
		return r.file.Name()
	}
	return ""
}
