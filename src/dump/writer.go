package dump

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PCAP file format constants
const (
	magicMicroseconds = 0xA1B2C3D4
	versionMajor      = 2
	versionMinor      = 4
)

// Writer wraps an io.Writer to write packet data in PCAP format
type Writer struct {
	w   io.Writer
	buf [16]byte
}

// NewWriter creates a new PCAP writer
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// WriteFileHeader writes the PCAP file header
// This must be called exactly once per output file
func (w *Writer) WriteFileHeader(snaplen uint32, linktype layers.LinkType) error {
	var buf [24]byte
	binary.LittleEndian.PutUint32(buf[0:4], magicMicroseconds)
	binary.LittleEndian.PutUint16(buf[4:6], versionMajor)
	binary.LittleEndian.PutUint16(buf[6:8], versionMinor)
	// bytes 8:12 stay 0 (timezone = UTC)
	// bytes 12:16 stay 0 (sigfigs is always set to zero)
	binary.LittleEndian.PutUint32(buf[16:20], snaplen)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(linktype))
	_, err := w.w.Write(buf[:])
	return err
}

// WritePacket writes a packet to the PCAP file
func (w *Writer) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	if ci.CaptureLength != len(data) {
		ci.CaptureLength = len(data)
	}
	if ci.CaptureLength > ci.Length {
		ci.Length = ci.CaptureLength
	}

	if err := w.writePacketHeader(ci); err != nil {
		return err
	}
	_, err := w.w.Write(data)
	return err
}

func (w *Writer) writePacketHeader(ci gopacket.CaptureInfo) error {
	t := ci.Timestamp
	if t.IsZero() {
		t = time.Now()
	}

	secs := t.Unix()
	usecs := t.Nanosecond() / 1000

	binary.LittleEndian.PutUint32(w.buf[0:4], uint32(secs))
	binary.LittleEndian.PutUint32(w.buf[4:8], uint32(usecs))
	binary.LittleEndian.PutUint32(w.buf[8:12], uint32(ci.CaptureLength))
	binary.LittleEndian.PutUint32(w.buf[12:16], uint32(ci.Length))

	_, err := w.w.Write(w.buf[:])
	return err
}
