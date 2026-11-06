package transport

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/sipcapture/heplify/src/config"
)

// appendingConn simulates bufferToFile running while drainBuffer sends: every
// write appends a new message to the buffer file.
type appendingConn struct {
	stubConn
	sender *Sender
	extra  []byte
	done   bool
}

func (c *appendingConn) Write(b []byte) (int, error) {
	if !c.done {
		c.done = true
		c.sender.bufferToFile(c.extra)
	}
	return len(b), nil
}

func framed(msgs ...[]byte) []byte {
	var out []byte
	for _, m := range msgs {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(m)))
		out = append(out, l[:]...)
		out = append(out, m...)
	}
	return out
}

func TestDrainBufferKeepsMessagesBufferedDuringDrain(t *testing.T) {
	bufferFile := filepath.Join(t.TempDir(), "hep-buffer.dump")
	cfg := &config.Config{}
	cfg.BufferSettings.Enable = true
	cfg.BufferSettings.File = bufferFile
	sender := New(cfg)
	defer sender.Close()

	if err := os.WriteFile(bufferFile, framed([]byte("old")), 0o600); err != nil {
		t.Fatal(err)
	}
	conn := &appendingConn{sender: sender, extra: []byte("new")}
	client := &HEPClient{addr: "127.0.0.1:0", proto: "tcp", conn: conn, state: stateConnected, reconnecting: true}

	sender.drainBuffer(client)

	got, err := os.ReadFile(bufferFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := framed([]byte("new")); string(got) != string(want) {
		t.Fatalf("buffer after drain = %q, want only the message appended during the drain %q", got, want)
	}
}
