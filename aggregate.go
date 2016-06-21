package main


func aggregateData(store *SampleStore, graphiteServer *string) {
	store.lock.Lock()

	var l []StoreKey
	var v []*Sample
	for key, val := range store.flows {
		if val.in_bytes + val.in_packets == 0 {
			l = append(l, key)
		} else {
			var sample *Sample = new(Sample)
			*sample = *val
			v = append(v, sample)
			val.in_packets, val.in_bytes = 0, 0
		}
	}
	for _, k := range l {
		delete(store.flows, k)
	}
	store.lock.Unlock()

	storeSamples(v, graphiteServer)
}