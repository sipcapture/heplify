package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/flight"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/rs/zerolog/log"
	"github.com/sipcapture/heplify/src/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// PacketRecord holds structured packet data for Arrow Flight delivery.
// It avoids re-serialising through HEP when the destination is an Arrow server.
type PacketRecord struct {
	TimestampUs uint64 // Unix microseconds
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	IPProtocol  uint8 // 6=TCP, 17=UDP
	ProtoType   uint8 // 1=SIP, 5=RTCP, 53=DNS …
	Payload     []byte
	CID         []byte // Call-ID
	NodeID      uint32
	NodeName    string
	MOS         uint16 // MOS × 100, e.g. 450 = MOS 4.50; 0 = not available
}

// hepPacketSchema is the fixed Arrow schema used in all HEP packet batches.
var hepPacketSchema = arrow.NewSchema([]arrow.Field{
	{Name: "timestamp_us", Type: arrow.PrimitiveTypes.Uint64},
	{Name: "src_ip", Type: arrow.BinaryTypes.String},
	{Name: "dst_ip", Type: arrow.BinaryTypes.String},
	{Name: "src_port", Type: arrow.PrimitiveTypes.Uint16},
	{Name: "dst_port", Type: arrow.PrimitiveTypes.Uint16},
	{Name: "ip_protocol", Type: arrow.PrimitiveTypes.Uint8},
	{Name: "proto_type", Type: arrow.PrimitiveTypes.Uint8},
	{Name: "payload", Type: arrow.BinaryTypes.LargeString},
	{Name: "cid", Type: arrow.BinaryTypes.String},
	{Name: "node_id", Type: arrow.PrimitiveTypes.Uint32},
	{Name: "node_name", Type: arrow.BinaryTypes.String},
	{Name: "mos", Type: arrow.PrimitiveTypes.Float32},
}, nil)

// ArrowFlightClient sends PacketRecords to an Arrow Flight server via DoPut.
type ArrowFlightClient struct {
	cfg    config.TransportSettings
	client flight.Client
	mem    memory.Allocator

	mu      sync.Mutex
	buf     []PacketRecord
	flushCh chan struct{}
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// newArrowFlightClient creates and starts a new Arrow Flight client.
func newArrowFlightClient(cfg config.TransportSettings) (*ArrowFlightClient, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	var dialOpts []grpc.DialOption
	if cfg.TLSEnabled {
		if cfg.SkipVerify {
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			})))
		} else {
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				MinVersion: tls.VersionTLS12,
			})))
		}
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	client, err := flight.NewClientWithMiddleware(addr, nil, nil, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("arrow flight dial %s: %w", addr, err)
	}

	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}
	flushMs := cfg.FlushIntervalMs
	if flushMs <= 0 {
		flushMs = 1000
	}

	c := &ArrowFlightClient{
		cfg:     cfg,
		client:  client,
		mem:     memory.NewGoAllocator(),
		buf:     make([]PacketRecord, 0, batchSize),
		flushCh: make(chan struct{}, 1),
		stopCh:  make(chan struct{}),
	}

	c.wg.Add(1)
	go c.flusher(batchSize, time.Duration(flushMs)*time.Millisecond)

	log.Info().
		Str("component", "arrow-flight").
		Str("addr", addr).
		Str("stream", cfg.StreamName).
		Int("batch_size", batchSize).
		Int("flush_ms", flushMs).
		Msg("Arrow Flight client started")

	return c, nil
}

// AddRecord buffers a PacketRecord for the next Arrow Flight batch flush.
func (c *ArrowFlightClient) AddRecord(r PacketRecord) {
	batchSize := c.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}

	c.mu.Lock()
	c.buf = append(c.buf, r)
	full := len(c.buf) >= batchSize
	c.mu.Unlock()

	if full {
		select {
		case c.flushCh <- struct{}{}:
		default:
		}
	}
}

// flusher runs in its own goroutine and flushes on timer or batch-full signal.
func (c *ArrowFlightClient) flusher(_ int, interval time.Duration) {
	defer c.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			c.doFlush() // final flush before exit
			return
		case <-ticker.C:
			c.doFlush()
		case <-c.flushCh:
			c.doFlush()
		}
	}
}

// doFlush drains the internal buffer and sends one Arrow RecordBatch via DoPut.
func (c *ArrowFlightClient) doFlush() {
	c.mu.Lock()
	if len(c.buf) == 0 {
		c.mu.Unlock()
		return
	}
	records := c.buf
	batchSize := c.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}
	c.buf = make([]PacketRecord, 0, batchSize)
	c.mu.Unlock()

	streamName := c.cfg.StreamName
	if streamName == "" {
		streamName = "heplify"
	}

	rec := buildArrowRecord(c.mem, records)
	defer rec.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := c.client.DoPut(ctx)
	if err != nil {
		log.Error().
			Str("component", "arrow-flight").
			Err(err).
			Msg("Arrow Flight DoPut stream open failed")
		return
	}

	desc := &flight.FlightDescriptor{
		Type: flight.DescriptorPATH,
		Path: []string{streamName},
	}

	writer := flight.NewRecordWriter(stream, ipc.WithSchema(rec.Schema()))
	writer.SetFlightDescriptor(desc)

	if err := writer.Write(rec); err != nil {
		log.Error().
			Str("component", "arrow-flight").
			Err(err).
			Msg("Arrow record write failed")
		_ = stream.CloseSend()
		return
	}

	if err := writer.Close(); err != nil {
		log.Error().
			Str("component", "arrow-flight").
			Err(err).
			Msg("Arrow writer close failed")
	}

	if err := stream.CloseSend(); err != nil {
		log.Debug().
			Str("component", "arrow-flight").
			Err(err).
			Msg("Arrow stream CloseSend")
	}

	log.Debug().
		Str("component", "arrow-flight").
		Int64("rows", rec.NumRows()).
		Str("stream", streamName).
		Msg("Arrow batch flushed")
}

// buildArrowRecord constructs an Arrow RecordBatch from a slice of PacketRecords.
func buildArrowRecord(mem memory.Allocator, records []PacketRecord) arrow.RecordBatch {
	b := array.NewRecordBuilder(mem, hepPacketSchema)
	defer b.Release()

	tsB := b.Field(0).(*array.Uint64Builder)
	srcIPB := b.Field(1).(*array.StringBuilder)
	dstIPB := b.Field(2).(*array.StringBuilder)
	srcPortB := b.Field(3).(*array.Uint16Builder)
	dstPortB := b.Field(4).(*array.Uint16Builder)
	ipProtoB := b.Field(5).(*array.Uint8Builder)
	protoTypeB := b.Field(6).(*array.Uint8Builder)
	payloadB := b.Field(7).(*array.LargeStringBuilder)
	cidB := b.Field(8).(*array.StringBuilder)
	nodeIDB := b.Field(9).(*array.Uint32Builder)
	nodeNameB := b.Field(10).(*array.StringBuilder)
	mosB := b.Field(11).(*array.Float32Builder)

	for _, r := range records {
		tsB.Append(r.TimestampUs)
		srcIPB.Append(netIPStr(r.SrcIP))
		dstIPB.Append(netIPStr(r.DstIP))
		srcPortB.Append(r.SrcPort)
		dstPortB.Append(r.DstPort)
		ipProtoB.Append(r.IPProtocol)
		protoTypeB.Append(r.ProtoType)
		payloadB.Append(string(r.Payload))
		cidB.Append(string(r.CID))
		nodeIDB.Append(r.NodeID)
		nodeNameB.Append(r.NodeName)
		if r.MOS > 0 {
			mosB.Append(float32(r.MOS) / 100.0)
		} else {
			mosB.AppendNull()
		}
	}

	return b.NewRecordBatch()
}

func netIPStr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// Close stops the flusher goroutine (with a final flush) and closes the gRPC connection.
func (c *ArrowFlightClient) Close() {
	close(c.stopCh)
	c.wg.Wait()
	if err := c.client.Close(); err != nil {
		log.Debug().Str("component", "arrow-flight").Err(err).Msg("Arrow Flight client close")
	}
}
