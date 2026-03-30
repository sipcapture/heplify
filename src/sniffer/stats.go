package sniffer

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	StatSIP = iota
	StatRTCP
	StatRTCPFail
	StatRTP
	StatDNS
	StatLog
	StatHEPSent
	StatDuplicates
	StatUnknown
	statCount
)

// StatsSnapshot holds a point-in-time read of all cumulative counters.
// Total = SIP + RTCP + RTCPFail + RTP + DNS + Log + Duplicates + Unknown.
type StatsSnapshot struct {
	UptimeSeconds int64
	Total         int64
	SIP           int64
	RTCP          int64
	RTCPFail      int64
	RTP           int64
	DNS           int64
	Log           int64
	HEPSent       int64
	Duplicates    int64
	Unknown       int64
}

// Stats holds per-minute packet counters (reset each minute) and
// cumulative totals (never reset) for the web stats endpoint.
type Stats struct {
	counters  [statCount]atomic.Int64
	totals    [statCount]atomic.Int64
	startTime time.Time
}

func NewStats() *Stats {
	return &Stats{startTime: time.Now()}
}

func (s *Stats) Inc(idx int) {
	if idx >= 0 && idx < statCount {
		s.counters[idx].Add(1)
		s.totals[idx].Add(1)
	}
}

// Snapshot returns cumulative counters since start without resetting them.
// Total is the sum of all protocol counters — unknown packets are included via StatUnknown.
func (s *Stats) Snapshot() StatsSnapshot {
	sip := s.totals[StatSIP].Load()
	rtcp := s.totals[StatRTCP].Load()
	rtcpFail := s.totals[StatRTCPFail].Load()
	rtp := s.totals[StatRTP].Load()
	dns := s.totals[StatDNS].Load()
	logPkts := s.totals[StatLog].Load()
	hepSent := s.totals[StatHEPSent].Load()
	dups := s.totals[StatDuplicates].Load()
	unknown := s.totals[StatUnknown].Load()
	return StatsSnapshot{
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
		Total:         sip + rtcp + rtcpFail + rtp + dns + logPkts + dups + unknown,
		SIP:           sip,
		RTCP:          rtcp,
		RTCPFail:      rtcpFail,
		RTP:           rtp,
		DNS:           dns,
		Log:           logPkts,
		HEPSent:       hepSent,
		Duplicates:    dups,
		Unknown:       unknown,
	}
}

// FormatUptime formats seconds into a human-readable string like "2h 5m 30s".
func FormatUptime(secs int64) string {
	h := secs / 3600
	m := (secs % 3600) / 60
	s := secs % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// RunLogger logs per-minute delta stats and resets the per-minute counters.
func (s *Stats) RunLogger() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sip := s.counters[StatSIP].Swap(0)
		rtcp := s.counters[StatRTCP].Swap(0)
		rtcpFail := s.counters[StatRTCPFail].Swap(0)
		rtp := s.counters[StatRTP].Swap(0)
		dns := s.counters[StatDNS].Swap(0)
		logPkts := s.counters[StatLog].Swap(0)
		hepSent := s.counters[StatHEPSent].Swap(0)
		dups := s.counters[StatDuplicates].Swap(0)
		unknown := s.counters[StatUnknown].Swap(0)
		total := sip + rtcp + rtcpFail + rtp + dns + logPkts + dups + unknown

		log.Info().
			Int64("total", total).
			Int64("sip", sip).
			Int64("rtcp", rtcp).
			Int64("rtcp_fail", rtcpFail).
			Int64("rtp", rtp).
			Int64("dns", dns).
			Int64("log", logPkts).
			Int64("hep_sent", hepSent).
			Int64("duplicates", dups).
			Int64("unknown", unknown).
			Msg("per-minute packet stats")
	}
}
