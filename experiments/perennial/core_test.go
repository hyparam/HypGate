package gateway

import "testing"

func valid(s Stream) bool {
	return s.Sent <= s.Received && s.Durable <= s.Received &&
		s.Received-s.Sent <= s.Capacity && (!s.Strict || s.Sent <= s.Durable) &&
		(!s.Strict || !s.LogFailed || s.Closed)
}

// Exhaustive reachable-state exploration within a six-byte lifetime cap.
// This is a bounded test, not a proof for arbitrary traces or concurrency.
func TestReachableStates(t *testing.T) {
	for _, strict := range []bool{false, true} {
		start := New(2, strict)
		seen := map[Stream]bool{start: true}
		queue := []Stream{start}
		for len(queue) > 0 {
			s := queue[0]
			queue = queue[1:]
			next := []Stream{}
			for n := uint64(0); n <= 7; n++ {
				a := s
				a.Receive(n)
				if a.Received <= 6 {
					next = append(next, a)
				}
				a = s
				a.Acknowledge(n)
				next = append(next, a)
				a = s
				a.Send(n)
				next = append(next, a)
			}
			a := s
			a.FailLog()
			next = append(next, a)
			a = s
			a.Cancel()
			next = append(next, a)
			for _, a := range next {
				if !valid(a) {
					t.Fatalf("invariant failed: %+v -> %+v", s, a)
				}
				if a.Strict != s.Strict || a.Capacity != s.Capacity {
					t.Fatal("configuration changed")
				}
				if s.Closed && (a.Sent != s.Sent || a.Received != s.Received) {
					t.Fatal("I/O after close")
				}
				if !seen[a] {
					seen[a] = true
					queue = append(queue, a)
				}
			}
		}
		t.Logf("strict=%v: %d reachable states", strict, len(seen))
	}
}

func TestAvailabilityAndOverflow(t *testing.T) {
	s := New(2, false)
	if !s.Receive(2) {
		t.Fatal("receive")
	}
	s.FailLog()
	if !s.Send(2) || !s.Receive(2) {
		t.Fatal("logger failure blocked forwarding")
	}
	s = Stream{Received: ^uint64(0), Sent: ^uint64(0), Capacity: 2}
	if s.Receive(1) {
		t.Fatal("offset overflow accepted")
	}
}
