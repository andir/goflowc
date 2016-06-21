package main

import (
	"fmt"
	"os"
	"net"
	"github.com/fln/nf9packet"
)

const SRC_AS_ID = 16
const DST_AS_ID = 17
const IN_PKTS_ID = 2
const IN_BYTES_ID = 1
const PROTO_ID = 4
const VLAN_ID = 58
const IP_PROTOCOL_VERSION_ID = 60


func processNetFlowPacket(store *SampleStore, pdu PDU) {
	p := pdu.packet
	templateList := p.TemplateRecords()

	TemplateCacheLock.Lock()
	for _, t := range templateList {
		templateKey := fmt.Sprintf("%s|%b|%v", pdu.source, p.SourceId, t.TemplateId)
		TemplateCache[templateKey] = t

	}
	TemplateCacheLock.Unlock()
	TemplateCacheLock.RLock()
	defer TemplateCacheLock.RUnlock()

	for _, flowSet := range p.DataFlowSets() {
		templateKey := fmt.Sprintf("%s|%b|%v", pdu.source, p.SourceId, flowSet.Id)
		template, ok := TemplateCache[templateKey]
		if !ok {
			fmt.Fprintln(os.Stderr, "Missing template ", templateKey)
			continue
		}

		records := template.DecodeFlowSet(&flowSet)
		if records == nil {
			continue
		}

		for _, r := range records {

			var sample Sample
			var c uint64

			for i := range r.Values {
				field := template.Fields[i]
				fieldType := field.Type

				switch {
				case fieldType == DST_AS_ID:
					sample.dst_as = uint32(field.DataToUint64(r.Values[i]))
					c += DST_AS_ID

				case fieldType == SRC_AS_ID:
					sample.src_as = uint32(field.DataToUint64(r.Values[i]))
					c += SRC_AS_ID

				case fieldType == IN_BYTES_ID:
					sample.in_bytes = field.DataToUint64(r.Values[i])
					c += IN_BYTES_ID
				case fieldType == IN_PKTS_ID:
					sample.in_packets = field.DataToUint64(r.Values[i])
					c += IN_PKTS_ID
				case fieldType == VLAN_ID:
					sample.vlan = uint32(field.DataToUint64(r.Values[i]))
					c += VLAN_ID
				case fieldType == PROTO_ID:
					sample.proto = uint32(field.DataToUint64(r.Values[i]))
					c += PROTO_ID
				case fieldType == IP_PROTOCOL_VERSION_ID:
					sample.ip_version = uint8(field.DataToUint64(r.Values[i]))
					c += IP_PROTOCOL_VERSION_ID
				}

				if c == DST_AS_ID + SRC_AS_ID + IN_BYTES_ID + IN_PKTS_ID + VLAN_ID + PROTO_ID + IP_PROTOCOL_VERSION_ID {
					break
				}

			}
			if c == DST_AS_ID + SRC_AS_ID + IN_BYTES_ID + IN_PKTS_ID + VLAN_ID  + PROTO_ID + IP_PROTOCOL_VERSION_ID {
				store.Add(sample)
			} else {
				fmt.Println("Missing fileds for flow.")
			}
		}

	}
}


func parseNetFlowPacket(c chan PDU, remote net.Addr, data []byte) {
	p, err := nf9packet.Decode(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	c <- PDU {
		packet: p,
		source: remote,
	}
}