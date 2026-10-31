package dnsmsg

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

// testReplyPrototype builds a representative DNS response for the mutation
// tests: one question, an A record in the answer section, an NS record in
// the authority section (whose RDATA is a domain name and so cannot be bit
// flipped), and a raw record of an uninterpreted type in the additional
// section.
//
// Every call returns a message with its own domain names, so a test may
// modify what it returns without affecting any other message.
func testReplyPrototype(t *testing.T) Message {
	qname := testDomainName(t, "example.com.")
	var msg Message
	msg.ID = 0x4f3d
	msg.QR = QRResponse
	msg.RD = 1
	msg.RA = 1
	msg.QDCOUNT = 1
	msg.ANCOUNT = 1
	msg.NSCOUNT = 1
	msg.ARCOUNT = 1
	msg.QuestionSection = []QuestionSectionEntry{
		{QName: qname, Class: CLASS_IN, Type: TYPE_A},
	}
	msg.AnswerSection = []ResourceRecord{
		{Name: qname, Class: CLASS_IN, Type: TYPE_A, TTL: 60, RData: NewRecordA([4]byte{192, 0, 2, 1})},
	}
	msg.AuthoritySection = []ResourceRecord{
		{Name: qname, Class: CLASS_IN, Type: TYPE_NS, TTL: 300, RData: NewRecordNS(testDomainName(t, "ns.example.com."))},
	}
	msg.AdditionalSection = []ResourceRecord{
		{
			Name:  qname,
			Class: CLASS_IN,
			Type:  65535,
			TTL:   10,
			RData: NewRecordRaw(65535, []byte{0xde, 0xad, 0xbe, 0xef}),
		},
	}
	return msg
}

func writeAndParse(t *testing.T, msg Message) Message {
	t.Helper()
	w := WireFormat{}
	size := w.WriteWireFormat(msg)
	if size == 0 {
		t.Fatalf("WriteWireFormat wrote nothing for a message with %d bytes of records", countRecords(&msg))
	}
	got, err := ParseWireFormat(w)
	if err != nil {
		t.Fatalf("ParseWireFormat() of the message this package wrote: %v", err)
	}
	return got
}

func TestRecords(t *testing.T) {
	msg := testReplyPrototype(t)
	records := msg.Records()
	if len(records) != 3 {
		t.Fatalf("Records() returned %d records, want 3", len(records))
	}
	want := []struct {
		section string
		typ     ResourceType
	}{
		{"answer", TYPE_A},
		{"authority", TYPE_NS},
		{"additional", 65535},
	}
	for i, w := range want {
		if records[i].Type != w.typ {
			t.Errorf("Records()[%d].Type = %d, want the %s record %d", i, records[i].Type, w.section, w.typ)
		}
	}
	// Records returns the records of msg, not copies of them.
	records[0].TTL = 99
	if msg.AnswerSection[0].TTL != 99 {
		t.Errorf("the answer record TTL is %d after writing 99 through Records(), want 99", msg.AnswerSection[0].TTL)
	}
}

// TestFlippableRecords checks that the records FlippableRecords reports are
// entries of Records, so that one target index selects the same record for
// both the record mutations.
func TestFlippableRecords(t *testing.T) {
	msg := testReplyPrototype(t)
	records := msg.Records()
	flippable := msg.FlippableRecords()
	if len(flippable) != 2 {
		t.Fatalf("FlippableRecords() returned %d records, want the A record and the raw record", len(flippable))
	}
	if flippable[0] != records[0] {
		t.Errorf("FlippableRecords()[0] is the %s record, want the answer A record", flippable[0].Type)
	}
	if flippable[1] != records[2] {
		t.Errorf("FlippableRecords()[1] is the %s record, want the additional raw record", flippable[1].Type)
	}
	for _, rr := range flippable {
		if !canFlipRDataBit(rr) {
			t.Errorf("FlippableRecords() reports the %s record, which cannot be bit flipped", rr.Type)
		}
		if len(rr.RData.CanonicalWireFormat()) > 0 {
			continue
		}
		t.Errorf("FlippableRecords() reports a record with no RDATA octets")
	}
	for _, rr := range records {
		if containsRecord(flippable, rr) {
			continue
		}
		if canFlipRDataBit(rr) {
			t.Errorf("FlippableRecords() omits the %s record, which can be bit flipped", rr.Type)
		}
	}

	// A record whose RDATA carries no octets has no bit to flip.
	msg = testReplyPrototype(t)
	msg.AdditionalSection[0].RData = NewRecordRaw(65535, nil)
	if got := len(msg.FlippableRecords()); got != 1 {
		t.Errorf("FlippableRecords() with an empty raw record returned %d records, want 1", got)
	}
}

func containsRecord(records []*ResourceRecord, rr *ResourceRecord) bool {
	for _, r := range records {
		if r == rr {
			return true
		}
	}
	return false
}

// TestMessageMutationsCatalog checks the parameters every mutation in the
// catalog reports, because a caller picks its parameters from these values.
func TestMessageMutationsCatalog(t *testing.T) {
	if len(MessageMutations) != 7 {
		t.Fatalf("MessageMutations holds %d mutations, want 7", len(MessageMutations))
	}
	msg := testReplyPrototype(t)
	tests := []struct {
		name     string
		can      bool
		targets  int
		maxValue uint64
	}{
		{"flip-header-flag", true, 7, 0},
		{"set-opcode", true, 1, 0x0f},
		{"set-rcode", true, 1, 0x0f},
		{"set-question-type", true, 1, 0xffff},
		{"set-question-class", true, 1, 0xffff},
		{"set-record-ttl", true, 3, math.MaxUint32},
		{"flip-record-rdata-bit", true, 2, 31},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mutationByName(t, tt.name)
			if m.Can(&msg) != tt.can {
				t.Errorf("Can() = %v, want %v", m.Can(&msg), tt.can)
			}
			if got := m.Targets(&msg); got != tt.targets {
				t.Errorf("Targets() = %d, want %d", got, tt.targets)
			}
			for target := 0; target < tt.targets; target++ {
				if got := m.MaxValue(&msg, target); got != tt.maxValue {
					t.Errorf("MaxValue(target=%d) = %d, want %d", target, got, tt.maxValue)
				}
			}
			if m.Name != "flip-record-rdata-bit" {
				return
			}
			// This one limit depends on the record the target selects.
			if got := m.MaxValue(&msg, tt.targets); got != 0 {
				t.Errorf("MaxValue(target=%d) = %d, want 0 for a target outside the message", tt.targets, got)
			}
		})
	}

	// A message with no question and no records limits what can be applied.
	var empty Message
	if got := mutationByName(t, "set-question-type").Targets(&empty); got != 0 {
		t.Errorf("Targets() on a message without questions = %d, want 0", got)
	}
	if mutationByName(t, "set-question-type").Can(&empty) {
		t.Error("Can() accepted a message without questions")
	}
	if mutationByName(t, "set-record-ttl").Can(&empty) {
		t.Error("Can() accepted a message without records")
	}
	if mutationByName(t, "flip-record-rdata-bit").Can(&empty) {
		t.Error("Can() accepted a message without records")
	}
	// Every message has header flags.
	if !mutationByName(t, "flip-header-flag").Can(&empty) {
		t.Error("Can() rejected a message without questions or records")
	}
}

func TestMutationFlipHeaderFlag(t *testing.T) {
	m := mutationByName(t, "flip-header-flag")

	msg := testReplyPrototype(t)
	desc, ok := m.Apply(&msg, 2, 0)
	if !ok {
		t.Fatalf("Apply(target=2) declined: %s", desc)
	}
	if msg.RD != 0 || msg.RA != 1 {
		t.Errorf("after Apply: RD = %d RA = %d, want RD = 0 RA = 1", msg.RD, msg.RA)
	}
	if want := "flipped the RD header flag: 1 to 0"; desc != want {
		t.Errorf("Apply returned %q, want %q", desc, want)
	}

	// Applying the same mutation to the same target applies it again.
	desc, ok = m.Apply(&msg, 2, 0)
	if !ok {
		t.Fatalf("Apply(target=2) declined the second time: %s", desc)
	}
	if msg.RD != 1 {
		t.Errorf("RD = %d after flipping it twice, want 1", msg.RD)
	}
	if want := "flipped the RD header flag: 0 to 1"; desc != want {
		t.Errorf("Apply returned %q, want %q", desc, want)
	}

	// Every flag of the header is reachable by its index.
	flags := map[int]*uint8{0: &msg.AA, 1: &msg.TC, 3: &msg.RA, 4: &msg.Z, 5: &msg.AD, 6: &msg.CD}
	for target, flag := range flags {
		before := *flag
		desc, ok := m.Apply(&msg, target, 0)
		if !ok {
			t.Errorf("Apply(target=%d) declined", target)
			continue
		}
		if *flag != before^1 {
			t.Errorf("flag at target %d is %d after flipping it, want %d", target, *flag, before^1)
		}
		want := fmt.Sprintf("flipped the %s header flag: %d to %d", headerFlagNames[target], before, *flag)
		if desc != want {
			t.Errorf("Apply(target=%d) returned %q, want %q", target, desc, want)
		}
	}

	// A target outside the flags, and any value, is declined without
	// changing the message.
	before := msg
	desc, ok = m.Apply(&msg, 7, 0)
	if ok || desc != "" {
		t.Errorf("Apply(target=7) = (%q, %v), want an empty decline", desc, ok)
	}
	if _, ok := m.Apply(&msg, 0, 1); ok {
		t.Error("Apply(value=1) was accepted, want declined: the mutation needs no value")
	}
	if !reflect.DeepEqual(before, msg) {
		t.Error("a declined Apply changed the message")
	}
}

func TestMutationSetOpcode(t *testing.T) {
	m := mutationByName(t, "set-opcode")

	msg := testReplyPrototype(t)
	desc, ok := m.Apply(&msg, 0, 4)
	if !ok {
		t.Fatalf("Apply declined: %s", desc)
	}
	if msg.OPCODE != 4 {
		t.Errorf("OPCODE = %d, want 4", msg.OPCODE)
	}
	if want := "set OPCODE from 0 to 4"; desc != want {
		t.Errorf("Apply returned %q, want %q", desc, want)
	}

	if _, ok := m.Apply(&msg, 0, 16); ok {
		t.Error("Apply(value=16) was accepted, want declined")
	}
	if msg.OPCODE != 4 {
		t.Errorf("a declined Apply changed OPCODE to %d", msg.OPCODE)
	}
	if _, ok := m.Apply(&msg, 1, 4); ok {
		t.Error("Apply(target=1) was accepted, want declined: an opcode has no index")
	}
}

func TestMutationSetRcode(t *testing.T) {
	m := mutationByName(t, "set-rcode")

	msg := testReplyPrototype(t)
	desc, ok := m.Apply(&msg, 0, 3)
	if !ok {
		t.Fatalf("Apply declined: %s", desc)
	}
	if msg.RCODE != 3 {
		t.Errorf("RCODE = %d, want 3", msg.RCODE)
	}
	if want := "set RCODE from 0 to 3"; desc != want {
		t.Errorf("Apply returned %q, want %q", desc, want)
	}

	if _, ok := m.Apply(&msg, 0, 16); ok {
		t.Error("Apply(value=16) was accepted, want declined")
	}
	if _, ok := m.Apply(&msg, 1, 3); ok {
		t.Error("Apply(target=1) was accepted, want declined")
	}
	if got := m.MaxValue(&msg, 0); got != 15 {
		t.Errorf("MaxValue() = %d, want 15", got)
	}
}

func TestMutationSetQuestionType(t *testing.T) {
	m := mutationByName(t, "set-question-type")

	msg := testReplyPrototype(t)
	msg.QDCOUNT = 2
	msg.QuestionSection = append(msg.QuestionSection, QuestionSectionEntry{
		QName: testDomainName(t, "sub.example.com."), Class: CLASS_IN, Type: 65535,
	})

	desc, ok := m.Apply(&msg, 1, uint64(TYPE_PTR))
	if !ok {
		t.Fatalf("Apply(target=1) declined: %s", desc)
	}
	if got := msg.QuestionSection[1].Type; got != TYPE_PTR {
		t.Errorf("QuestionSection[1].Type = %d, want %d", got, TYPE_PTR)
	}
	if got := msg.QuestionSection[0].Type; got != TYPE_A {
		t.Errorf("Apply changed question 0 type to %d", got)
	}
	if msg.QDCOUNT != 2 {
		t.Errorf("QDCOUNT = %d, want 2", msg.QDCOUNT)
	}
	want := "changed the QTYPE of question 2 from TYPE65535 to PTR"
	if desc != want {
		t.Errorf("Apply returned %q, want %q", desc, want)
	}

	if _, ok := m.Apply(&msg, 2, uint64(TYPE_PTR)); ok {
		t.Error("Apply(target=2) was accepted, want declined: there is no question 3")
	}
	if _, ok := m.Apply(&msg, 0, 65536); ok {
		t.Error("Apply(value=65536) was accepted, want declined")
	}
}

func TestMutationSetQuestionClass(t *testing.T) {
	m := mutationByName(t, "set-question-class")

	msg := testReplyPrototype(t)
	desc, ok := m.Apply(&msg, 0, uint64(CLASS_CHAOS))
	if !ok {
		t.Fatalf("Apply declined: %s", desc)
	}
	if got := msg.QuestionSection[0].Class; got != CLASS_CHAOS {
		t.Errorf("QuestionSection[0].Class = %d, want %d", got, CLASS_CHAOS)
	}
	if got := msg.QuestionSection[0].Type; got != TYPE_A {
		t.Errorf("Apply changed the question type to %d", got)
	}
	want := "changed the QCLASS of question 1 from IN to CH"
	if desc != want {
		t.Errorf("Apply returned %q, want %q", desc, want)
	}

	if _, ok := m.Apply(&msg, 1, uint64(CLASS_CHAOS)); ok {
		t.Error("Apply(target=1) was accepted, want declined")
	}
	if _, ok := m.Apply(&msg, 0, 65536); ok {
		t.Error("Apply(value=65536) was accepted, want declined")
	}
}

func TestMutationSetRecordTTL(t *testing.T) {
	m := mutationByName(t, "set-record-ttl")

	msg := testReplyPrototype(t)
	// The target indexes Records(), which lists the sections in order.
	desc, ok := m.Apply(&msg, 1, 42)
	if !ok {
		t.Fatalf("Apply(target=1) declined: %s", desc)
	}
	if got := msg.AuthoritySection[0].TTL; got != 42 {
		t.Errorf("authority record TTL = %d, want 42", got)
	}
	if got := msg.AnswerSection[0].TTL; got != 60 {
		t.Errorf("Apply changed the answer record TTL to %d", got)
	}
	want := "authority record 1 (example.com. NS): set TTL from 300 to 42"
	if desc != want {
		t.Errorf("Apply returned %q, want %q", desc, want)
	}

	desc, ok = m.Apply(&msg, 2, 0)
	if !ok {
		t.Fatalf("Apply(target=2) declined: %s", desc)
	}
	if got := msg.AdditionalSection[0].TTL; got != 0 {
		t.Errorf("additional record TTL = %d, want 0", got)
	}

	if _, ok := m.Apply(&msg, 3, 7); ok {
		t.Error("Apply(target=3) was accepted, want declined: the message has three records")
	}
	if _, ok := m.Apply(&msg, 0, uint64(math.MaxUint32)+1); ok {
		t.Error("Apply(value=4294967296) was accepted, want declined: a TTL is 32 bits")
	}

	// Every record of the message is a target, whichever section holds it.
	msg = testReplyPrototype(t)
	if got := m.Targets(&msg); got != 3 {
		t.Errorf("Targets() = %d, want 3", got)
	}
}

func TestMutationFlipRecordRDataBit(t *testing.T) {
	m := mutationByName(t, "flip-record-rdata-bit")

	msg := testReplyPrototype(t)
	// The target indexes FlippableRecords, so target 1 is the raw record:
	// the authority NS record is not a target.
	desc, ok := m.Apply(&msg, 0, 1)
	if !ok {
		t.Fatalf("Apply(target=0) declined: %s", desc)
	}
	if got := msg.AnswerSection[0].RData.String(); got != "194.0.2.1" {
		t.Errorf("answer record RDATA = %s, want 194.0.2.1", got)
	}
	want := "answer record 1 (example.com. A): flipped bit 1 of the A RDATA: 192.0.2.1 to 194.0.2.1"
	if desc != want {
		t.Errorf("Apply returned %q, want %q", desc, want)
	}

	desc, ok = m.Apply(&msg, 1, 7)
	if !ok {
		t.Fatalf("Apply(target=1) declined: %s", desc)
	}
	if got := msg.AdditionalSection[0].RData.CanonicalWireFormat(); !reflect.DeepEqual(got, []byte{0xde ^ 0x80, 0xad, 0xbe, 0xef}) {
		t.Errorf("additional record RDATA = %v, want the first octet with bit 7 flipped", got)
	}
	if !strings.HasPrefix(desc, "additional record 1 (example.com. TYPE65535): flipped bit 7 of the raw RDATA: deadbeef to") {
		t.Errorf("Apply returned %q, want a description of the raw record it changed", desc)
	}

	// Flipping every bit of an octet inverts it, and flipping them again
	// returns the original RDATA.
	msg = testReplyPrototype(t)
	for bit := uint64(0); bit < 8; bit++ {
		m.Apply(&msg, 0, bit)
	}
	if got := msg.AnswerSection[0].RData.CanonicalWireFormat(); got[0] != 0xc0^0xff {
		t.Errorf("answer record RDATA first octet = %02x, want %02x", got[0], 0xc0^0xff)
	}
	for bit := uint64(0); bit < 8; bit++ {
		m.Apply(&msg, 0, bit)
	}
	if got := msg.AnswerSection[0].RData.CanonicalWireFormat(); !reflect.DeepEqual(got, []byte{0xc0, 0, 2, 1}) {
		t.Errorf("answer record RDATA = %v after flipping every bit twice, want c0000201", got)
	}

	// A bit index beyond the RDATA is declined, and the RDATA keeps its size.
	if _, ok := m.Apply(&msg, 0, 32); ok {
		t.Error("Apply(value=32) was accepted, want declined: an A RDATA holds 32 bits")
	}
	if _, ok := m.Apply(&msg, 2, 0); ok {
		t.Error("Apply(target=2) was accepted, want declined: the message has two flippable records")
	}
	if got := len(msg.AnswerSection[0].RData.CanonicalWireFormat()); got != 4 {
		t.Errorf("answer record RDATA holds %d octets, want 4", got)
	}

	// No target selects the authority NS record, so applying the mutation to
	// every target of a message leaves that record as it was.
	msg = testReplyPrototype(t)
	before := msg.AuthoritySection[0].RData.CanonicalWireFormat()
	targets := msg.FlippableRecords()
	for target := range targets {
		if _, ok := m.Apply(&msg, target, 0); !ok {
			t.Errorf("Apply(target=%d) declined", target)
		}
	}
	if got := msg.AuthoritySection[0].RData.CanonicalWireFormat(); !reflect.DeepEqual(got, before) {
		t.Errorf("applying the mutation to all %d targets changed the authority record RDATA to %v", len(targets), got)
	}
}

// TestRecordMutations applies the record mutations directly to a record.
func TestRecordMutations(t *testing.T) {
	if len(RecordMutations) != 2 {
		t.Fatalf("RecordMutations holds %d mutations, want 2", len(RecordMutations))
	}
	msg := testReplyPrototype(t)

	setTTL := recordMutationByName(t, "set-ttl")
	rr := &msg.AnswerSection[0]
	if !setTTL.Can(rr) {
		t.Error("set-ttl.Can() = false, want true")
	}
	if got := setTTL.MaxValue(rr); got != math.MaxUint32 {
		t.Errorf("set-ttl.MaxValue() = %d, want %d", got, uint64(math.MaxUint32))
	}
	desc, ok := setTTL.Apply(rr, 42)
	if !ok {
		t.Fatalf("set-ttl.Apply declined: %s", desc)
	}
	if rr.TTL != 42 {
		t.Errorf("record TTL = %d, want 42", rr.TTL)
	}
	if want := "set TTL from 60 to 42"; desc != want {
		t.Errorf("set-ttl.Apply returned %q, want %q", desc, want)
	}
	if _, ok := setTTL.Apply(rr, uint64(math.MaxUint32)+1); ok {
		t.Error("set-ttl.Apply accepted a 33 bit value, want declined")
	}

	flip := recordMutationByName(t, "flip-rdata-bit")
	rr = &msg.AuthoritySection[0]
	if flip.Can(rr) {
		t.Error("flip-rdata-bit.Can() accepted an NS record, want false")
	}
	if _, ok := flip.Apply(rr, 0); ok {
		t.Error("flip-rdata-bit.Apply accepted an NS record, want declined")
	}
	if got := flip.MaxValue(rr); got != 0 {
		t.Errorf("flip-rdata-bit.MaxValue() on an NS record = %d, want 0", got)
	}

	rr = &msg.AdditionalSection[0]
	if !flip.Can(rr) {
		t.Error("flip-rdata-bit.Can() = false for a raw record, want true")
	}
	if got := flip.MaxValue(rr); got != 31 {
		t.Errorf("flip-rdata-bit.MaxValue() = %d, want 31 bits of RDATA", got)
	}
	desc, ok = flip.Apply(rr, 31)
	if !ok {
		t.Fatalf("flip-rdata-bit.Apply declined: %s", desc)
	}
	if got := rr.RData.CanonicalWireFormat(); !reflect.DeepEqual(got, []byte{0xde, 0xad, 0xbe, 0xef ^ 0x80}) {
		t.Errorf("raw RDATA = %v, want the last bit flipped", got)
	}
	if _, ok := flip.Apply(rr, 32); ok {
		t.Error("flip-rdata-bit.Apply accepted bit 32, want declined")
	}

	// An AAAA record is flippable like an A record.
	msg = testReplyPrototype(t)
	msg.AnswerSection[0].Type = TYPE_AAAA
	msg.AnswerSection[0].RData = NewRecordAAAA([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	rr = &msg.AnswerSection[0]
	if !flip.Can(rr) {
		t.Fatal("flip-rdata-bit.Can() = false for an AAAA record, want true")
	}
	if got := flip.MaxValue(rr); got != 127 {
		t.Errorf("flip-rdata-bit.MaxValue() = %d, want 127 bits of RDATA", got)
	}
	if _, ok := flip.Apply(rr, 127); !ok {
		t.Error("flip-rdata-bit.Apply declined an AAAA record")
	}
	if got := rr.RData.CanonicalWireFormat(); got[15] != 0x81 {
		t.Errorf("AAAA RDATA last octet = %02x, want 81 (bit 127 flipped)", got[15])
	}
}

func mutationByName(t *testing.T, name string) Mutation {
	t.Helper()
	for _, m := range MessageMutations {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("MessageMutations has no mutation named %q", name)
	return Mutation{}
}

func recordMutationByName(t *testing.T, name string) RecordMutation {
	t.Helper()
	for _, m := range RecordMutations {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("RecordMutations has no mutation named %q", name)
	return RecordMutation{}
}

// TestAppliedMutationsKeepTheMessageWellFormed applies one mutation at a
// time and checks that the message still serializes, still parses, and
// still holds what this package promises never to change.
func TestAppliedMutationsKeepTheMessageWellFormed(t *testing.T) {
	messages := []struct {
		name  string
		build func(*testing.T) Message
	}{
		{"response with three records", testReplyPrototype},
		{"request", func(t *testing.T) Message {
			msg := testReplyPrototype(t)
			msg.QR = QRQuery
			msg.RA = 0
			return msg
		}},
		{"no records", func(t *testing.T) Message {
			msg := testReplyPrototype(t)
			msg.ANCOUNT, msg.NSCOUNT, msg.ARCOUNT = 0, 0, 0
			msg.AnswerSection, msg.AuthoritySection = nil, nil
			msg.AdditionalSection = nil
			return msg
		}},
		{"two questions", func(t *testing.T) Message {
			msg := testReplyPrototype(t)
			msg.QDCOUNT = 2
			msg.QuestionSection = append(msg.QuestionSection, QuestionSectionEntry{
				QName: testDomainName(t, "sub.example.com."), Class: CLASS_IN, Type: 65535,
			})
			return msg
		}},
	}

	for _, tc := range messages {
		for _, m := range MessageMutations {
			t.Run(tc.name+"/"+m.Name, func(t *testing.T) {
				before := tc.build(t)
				if !m.Can(&before) {
					t.Skipf("%s does not apply to this message", m.Name)
				}
				// Pick parameters inside what the mutation reports.
				targets := m.Targets(&before)
				if targets == 0 {
					t.Skipf("%s has no target in this message", m.Name)
				}
				target := targets - 1
				value := m.MaxValue(&before, target)
				if m.Name == "set-rcode" {
					value = 2
				}

				msg := tc.build(t)
				desc, ok := m.Apply(&msg, target, value)
				if !ok {
					t.Fatalf("Apply(target=%d, value=%d) declined: %s", target, value, desc)
				}

				got := writeAndParse(t, msg)
				if got.ID != before.ID {
					t.Errorf("ID changed from %04x to %04x", before.ID, got.ID)
				}
				if got.QR != before.QR {
					t.Errorf("QR changed from %d to %d", before.QR, got.QR)
				}
				for _, c := range []struct {
					name      string
					got, want uint16
				}{
					{"QDCOUNT", got.QDCOUNT, before.QDCOUNT},
					{"ANCOUNT", got.ANCOUNT, before.ANCOUNT},
					{"NSCOUNT", got.NSCOUNT, before.NSCOUNT},
					{"ARCOUNT", got.ARCOUNT, before.ARCOUNT},
				} {
					if c.got != c.want {
						t.Errorf("%s changed from %d to %d", c.name, c.want, c.got)
					}
				}
				if len(got.Records()) != len(before.Records()) {
					t.Fatalf("the message holds %d records, want %d", len(got.Records()), len(before.Records()))
				}
				for i := range got.Records() {
					new, old := got.Records()[i], before.Records()[i]
					if new.Name.String() != old.Name.String() {
						t.Errorf("record %d name changed to %s", i, new.Name)
					}
					if new.Type != old.Type {
						t.Errorf("record %d type changed from %d to %d", i, old.Type, new.Type)
					}
					if new.Class != old.Class {
						t.Errorf("record %d class changed from %d to %d", i, old.Class, new.Class)
					}
					if len(new.RData.CanonicalWireFormat()) != len(old.RData.CanonicalWireFormat()) {
						t.Errorf("record %d RDATA changed from %d to %d octets", i, len(old.RData.CanonicalWireFormat()), len(new.RData.CanonicalWireFormat()))
					}
				}
				if m.Name != "set-opcode" && got.OPCODE != before.OPCODE {
					t.Errorf("OPCODE changed from %d to %d", before.OPCODE, got.OPCODE)
				}
				if m.Name != "set-rcode" && got.RCODE != before.RCODE {
					t.Errorf("RCODE changed from %d to %d", before.RCODE, got.RCODE)
				}
				switch m.Name {
				case "set-opcode":
					if got.OPCODE != uint8(value) {
						t.Errorf("OPCODE = %d, want %d", got.OPCODE, value)
					}
				case "set-rcode":
					if got.RCODE != uint8(value) {
						t.Errorf("RCODE = %d, want %d", got.RCODE, value)
					}
				case "set-question-type":
					if got.QuestionSection[target].Type != ResourceType(value) {
						t.Errorf("question %d type = %d, want %d", target, got.QuestionSection[target].Type, value)
					}
				case "set-question-class":
					if got.QuestionSection[target].Class != ResourceClass(value) {
						t.Errorf("question %d class = %d, want %d", target, got.QuestionSection[target].Class, value)
					}
				case "set-record-ttl":
					if got.Records()[target].TTL != uint32(value) {
						t.Errorf("record %d TTL = %d, want %d", target, got.Records()[target].TTL, value)
					}
				}
			})
		}
	}
}

// TestAppliedMutationsAreReproduced checks that the same parameters applied
// to the same message always produce the same change, which is what lets a
// caller repeat a sequence of mutations it recorded.
func TestAppliedMutationsAreReproduced(t *testing.T) {
	for _, m := range MessageMutations {
		t.Run(m.Name, func(t *testing.T) {
			msg, other := testReplyPrototype(t), testReplyPrototype(t)
			if !m.Can(&msg) {
				t.Skipf("%s does not apply to this message", m.Name)
			}
			target, value := 0, uint64(0)
			if targets := m.Targets(&msg); targets > 0 {
				target = 0
				value = m.MaxValue(&msg, 0)
			}

			first, ok := m.Apply(&msg, target, value)
			second, ok2 := m.Apply(&other, target, value)
			if ok != ok2 {
				t.Fatal("Apply accepted the parameters once and declined them once")
			}
			if !ok {
				if first != second {
					t.Errorf("the two declines differ: %q, %q", first, second)
				}
				return
			}
			if first != second {
				t.Errorf("Apply described the change differently:\n%s\n%s", first, second)
			}
			if !reflect.DeepEqual(msg, other) {
				t.Error("the message after one Apply differs from the message after applying it again")
			}
		})
	}
}
