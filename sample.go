package main

import (
	"fmt"
	"sync"
	"sync/atomic"
)

type Sample struct {
	src_as uint32
	dst_as uint32

	in_bytes uint64
	in_packets uint64

	vlan uint32
	proto uint32
	ip_version uint8

}

func (s *Sample) String() string {
	return fmt.Sprintf("VLAN: %6d\tPROTO: %2d\tIP: %d\tSRC_AS: %6d\tDST_AS: %6d\tIN_PACKETS: %6d\tIN_BYTES: %6d\n",
		s.vlan, s.proto, s.ip_version, s.src_as, s.dst_as, s.in_packets, s.in_bytes,
	)
}

type StoreKey struct {
	src_asn uint32
	dst_asn uint32
	vlan uint32
	proto uint32
	ip_version uint8

}

type SampleStore struct {
	lock sync.RWMutex
	flows map[StoreKey]*Sample
}

func (s *SampleStore) Add(sample Sample) {
	// insert by src_as <<32 dst_as
	key := StoreKey{ src_asn: sample.src_as, dst_asn: sample.dst_as, vlan: sample.vlan, proto: sample.proto}

	s.lock.RLock()
	samp, ok := s.flows[key]
	if !ok {
		s.lock.RUnlock()
		s.lock.Lock()
		defer s.lock.Unlock()

		if samp, ok = s.flows[key]; !ok {
			samp = &Sample{
				ip_version: sample.ip_version,
				proto: sample.proto,
				src_as: sample.src_as,
				dst_as: sample.dst_as,
				vlan: sample.vlan,
				in_bytes: 0,
				in_packets:0 ,

			}
			s.flows[key] = samp
		}

	} else {
		defer s.lock.RUnlock()
	}
	atomic.AddUint64(&samp.in_bytes, sample.in_bytes)
	atomic.AddUint64(&samp.in_packets, sample.in_packets)
}