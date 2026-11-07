package pia

import "testing"

func TestReliableRoundTrip(t *testing.T) {
	in := ReliableMsg{Flags: RelData | RelLast, Seq: ReliableFirstSeq, Ack: ReliableFirstSeq, Payload: []byte{0, 1}}
	out, err := ParseReliable(in.Marshal())
	if err != nil || !out.IsData() || out.Seq != 0xFFFFF82F || string(out.Payload) != "\x00\x01" {
		t.Fatalf("%v %+v", err, out)
	}
	if _, err := ParseReliable(in.Marshal()[:25]); err == nil {
		t.Fatal("a short message must be refused (len must equal size + 24)")
	}
}
