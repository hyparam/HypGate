// Package gateway is a candidate input to Goose, not a Perennial-verified program.
// It has no I/O: durable acknowledgments are supplied by a trusted caller.
package gateway

type Stream struct {
	Received, Durable, Sent, Capacity uint64
	Strict, LogFailed, Closed         bool
}

func New(capacity uint64, strict bool) Stream {
	return Stream{Capacity: capacity, Strict: strict}
}

func (s *Stream) Receive(count uint64) bool {
	if s.Closed || count > ^uint64(0)-s.Received || count > s.Capacity-(s.Received-s.Sent) {
		return false
	}
	s.Received += count
	return true
}

func (s *Stream) Acknowledge(offset uint64) bool {
	if s.Closed || s.LogFailed || offset < s.Durable || offset > s.Received {
		return false
	}
	s.Durable = offset
	return true
}

func (s *Stream) Send(count uint64) bool {
	if s.Closed || count > s.Received-s.Sent {
		return false
	}
	if s.Strict && count > s.Durable-s.Sent {
		return false
	}
	s.Sent += count
	return true
}

func (s *Stream) FailLog() {
	s.LogFailed = true
	if s.Strict {
		s.Closed = true
	}
}

func (s *Stream) Cancel() { s.Closed = true }
