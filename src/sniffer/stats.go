package sniffer

import (
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	StatTotal = iota
	StatSIP
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

// Stats holds per-minute packet counters.
type Stats struct {
	counters [statCount]atomic.Int64
}

func NewStats() *Stats {
	return &Stats{}
}

func (s *Stats) Inc(idx int) {
	if idx >= 0 && idx < statCount {
		s.counters[idx].Add(1)
	}
}

// RunLogger logs stats every minute and resets counters.
func (s *Stats) RunLogger() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		total := s.counters[StatTotal].Swap(0)
		sip := s.counters[StatSIP].Swap(0)
		rtcp := s.counters[StatRTCP].Swap(0)
		rtcpFail := s.counters[StatRTCPFail].Swap(0)
		rtp := s.counters[StatRTP].Swap(0)
		dns := s.counters[StatDNS].Swap(0)
		logPkts := s.counters[StatLog].Swap(0)
		hepSent := s.counters[StatHEPSent].Swap(0)
		dups := s.counters[StatDuplicates].Swap(0)
		unknown := s.counters[StatUnknown].Swap(0)

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
