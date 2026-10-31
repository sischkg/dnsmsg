// Message and resource record modification.
//
// The API in this file applies one named modification to a Message or to
// one of its resource records. Every parameter a modification needs is an
// argument of the applied function: this file contains no random number
// generator and makes no choice of its own, so a program decides which
// modification to apply, which entry of the message it applies it to, and
// what value to pass with it, and the same arguments always produce the
// same change.
//
// Every modification here leaves the message serializable to wire format
// and parsable from it: it never changes a Message's ID or QR bit, never
// changes the section counts or the number of entries in any section, and
// never changes a record's name, class, type, or RDATA size. An applied
// modification returns a description of the change in a form a program
// can log.

package dnsmsg

import (
	"encoding/hex"
	"fmt"
	"math"
)

// A Mutation is one named, parameterized, in-place modification of a
// Message. All parameters the modification needs are arguments of Apply:
// target selects the entry of msg the modification acts on, and value is
// the value it sets or uses; a mutation that needs no value accepts only
// value 0. Can reports whether the modification applies to msg, Targets
// counts its valid target indices, and MaxValue reports the largest value
// valid for a target. A target or value outside them makes Apply decline
// by returning ok false. The built-in mutations are listed in
// MessageMutations.
type Mutation struct {
	Name     string
	Can      func(msg *Message) bool
	Targets  func(msg *Message) int
	MaxValue func(msg *Message, target int) uint64
	Apply    func(msg *Message, target int, value uint64) (desc string, ok bool)
}

// MessageMutations are the built-in Message modifications, with the
// parameters each one takes:
//
//	flip-header-flag      target: index into AA, TC, RD, RA, Z, AD, CD; value: 0
//	set-opcode            target: 0;                          value: new OPCODE, 0 to 15
//	set-rcode             target: 0;                          value: new RCODE, 0 to 15
//	set-question-type     target: index into QuestionSection; value: new QTYPE
//	set-question-class    target: index into QuestionSection; value: new QCLASS
//	set-record-ttl        target: index into Records();       value: new TTL
//	flip-record-rdata-bit target: index into FlippableRecords(); value: bit index in the record's canonical RDATA
//
// flip-record-rdata-bit applies only to records whose RDATA is a plain
// byte string that stays well-formed when one of its bits is flipped;
// FlippableRecords counts them.
var MessageMutations = []Mutation{
	{
		Name:     "flip-header-flag",
		Can:      func(*Message) bool { return true },
		Targets:  func(*Message) int { return len(headerFlagNames) },
		MaxValue: maxValues(0),
		Apply:    applyFlipHeaderFlag,
	},
	{
		Name:     "set-opcode",
		Can:      func(*Message) bool { return true },
		Targets:  func(*Message) int { return 1 },
		MaxValue: maxValues(0x0f),
		Apply:    applySetOpcode,
	},
	{
		Name:     "set-rcode",
		Can:      func(*Message) bool { return true },
		Targets:  func(*Message) int { return 1 },
		MaxValue: maxValues(0x0f),
		Apply:    applySetRcode,
	},
	{
		Name:     "set-question-type",
		Can:      func(msg *Message) bool { return len(msg.QuestionSection) > 0 },
		Targets:  func(msg *Message) int { return len(msg.QuestionSection) },
		MaxValue: maxValues(0xffff),
		Apply:    applySetQuestionType,
	},
	{
		Name:     "set-question-class",
		Can:      func(msg *Message) bool { return len(msg.QuestionSection) > 0 },
		Targets:  func(msg *Message) int { return len(msg.QuestionSection) },
		MaxValue: maxValues(0xffff),
		Apply:    applySetQuestionClass,
	},
	{
		Name:     "set-record-ttl",
		Can:      func(msg *Message) bool { return countRecords(msg) > 0 },
		Targets:  countRecords,
		MaxValue: maxValues(math.MaxUint32),
		Apply:    applySetRecordTTL,
	},
	{
		Name:    "flip-record-rdata-bit",
		Can:     func(msg *Message) bool { return msg.FlippableRecords() != nil },
		Targets: func(msg *Message) int { return len(msg.FlippableRecords()) },
		MaxValue: func(msg *Message, target int) uint64 {
			records := msg.FlippableRecords()
			if target < 0 || target >= len(records) {
				return 0
			}
			return maxRDataBitValue(records[target])
		},
		Apply: applyFlipRecordRDataBit,
	},
}

// A RecordMutation is one named, parameterized, in-place modification of
// a single ResourceRecord, following the same rules as a Mutation. The
// record modifications of MessageMutations apply one of these to the
// record their target selects.
type RecordMutation struct {
	Name     string
	Can      func(rr *ResourceRecord) bool
	MaxValue func(rr *ResourceRecord) uint64
	Apply    func(rr *ResourceRecord, value uint64) (desc string, ok bool)
}

// RecordMutations are the built-in resource record modifications, with
// the parameters each one takes:
//
//	set-ttl         value: new TTL
//	flip-rdata-bit  value: index of the bit to flip in the record's canonical RDATA
//
// flip-rdata-bit applies only to the records FlippableRecords counts.
var RecordMutations = []RecordMutation{
	{
		Name:     "set-ttl",
		Can:      func(*ResourceRecord) bool { return true },
		MaxValue: func(*ResourceRecord) uint64 { return math.MaxUint32 },
		Apply:    applyRecordTTL,
	},
	{
		Name:     "flip-rdata-bit",
		Can:      canFlipRDataBit,
		MaxValue: maxRDataBitValue,
		Apply:    applyFlipRDataBit,
	},
}

// Records returns pointers to msg's resource records, in the order of the
// answer, authority, and additional sections. The target of the record
// mutations in MessageMutations indexes this list.
func (msg *Message) Records() []*ResourceRecord {
	records := make([]*ResourceRecord, 0, countRecords(msg))
	for _, section := range []*[]ResourceRecord{&msg.AnswerSection, &msg.AuthoritySection, &msg.AdditionalSection} {
		for i := range *section {
			records = append(records, &(*section)[i])
		}
	}
	return records
}

// FlippableRecords returns pointers to the records of Records whose RDATA
// can be bit-flipped in place with the flip-rdata-bit mutation: the
// addresses of A and AAAA records and the octets of a RecordRaw, which
// carries the RDATA of record types this library does not interpret. The
// target of flip-record-rdata-bit indexes this list.
func (msg *Message) FlippableRecords() []*ResourceRecord {
	var records []*ResourceRecord
	for _, rr := range msg.Records() {
		if canFlipRDataBit(rr) {
			records = append(records, rr)
		}
	}
	return records
}

// headerFlagNames are the Message header flags the flip-header-flag
// mutation targets, in the order of its target indexes.
var headerFlagNames = []string{"AA", "TC", "RD", "RA", "Z", "AD", "CD"}

// maxValues returns a Mutation.MaxValue reporting the fixed value limit v.
func maxValues(v uint64) func(msg *Message, target int) uint64 {
	return func(*Message, int) uint64 { return v }
}

// recordAt returns a pointer to the target-th record of msg's answer,
// authority, and additional sections in that order, with the name of its
// section and its 1-based number within that section, or a nil record
// when target is out of range. When filter is not nil, only the records
// filter accepts are counted.
func recordAt(msg *Message, target int, filter func(rr *ResourceRecord) bool) (*ResourceRecord, string, int) {
	sections := []struct {
		name    string
		records []ResourceRecord
	}{
		{"answer", msg.AnswerSection},
		{"authority", msg.AuthoritySection},
		{"additional", msg.AdditionalSection},
	}
	for _, section := range sections {
		for i := range section.records {
			rr := &section.records[i]
			if filter != nil && !filter(rr) {
				continue
			}
			if target == 0 {
				return rr, section.name, i + 1
			}
			target--
		}
	}
	return nil, "", 0
}

func countRecords(msg *Message) int {
	return len(msg.AnswerSection) + len(msg.AuthoritySection) + len(msg.AdditionalSection)
}

// recordDesc formats the prefix naming the record a record modification
// was applied to, so that a Message-level description carries the same
// reference the target selected.
func recordDesc(section string, ordinal int, rr *ResourceRecord, desc string) string {
	return fmt.Sprintf("%s record %d (%s %s): %s", section, ordinal, rr.Name, rr.Type, desc)
}

// headerFlag returns a pointer to the flag at target index in
// headerFlagNames, or nil when target is out of range.
func headerFlag(msg *Message, target int) *uint8 {
	switch target {
	case 0:
		return &msg.AA
	case 1:
		return &msg.TC
	case 2:
		return &msg.RD
	case 3:
		return &msg.RA
	case 4:
		return &msg.Z
	case 5:
		return &msg.AD
	case 6:
		return &msg.CD
	}
	return nil
}

func applyFlipHeaderFlag(msg *Message, target int, value uint64) (string, bool) {
	if value != 0 {
		return "", false
	}
	flag := headerFlag(msg, target)
	if flag == nil {
		return "", false
	}
	old := *flag
	*flag ^= 1
	return fmt.Sprintf("flipped the %s header flag: %d to %d", headerFlagNames[target], old, *flag), true
}

func applySetOpcode(msg *Message, target int, value uint64) (string, bool) {
	if target != 0 || value > 0x0f {
		return "", false
	}
	old := msg.OPCODE
	msg.OPCODE = uint8(value)
	return fmt.Sprintf("set OPCODE from %d to %d", old, msg.OPCODE), true
}

func applySetRcode(msg *Message, target int, value uint64) (string, bool) {
	if target != 0 || value > 0x0f {
		return "", false
	}
	old := msg.RCODE
	msg.RCODE = uint8(value)
	return fmt.Sprintf("set RCODE from %d to %d", old, msg.RCODE), true
}

func questionAt(msg *Message, target int) *QuestionSectionEntry {
	if target < 0 || target >= len(msg.QuestionSection) {
		return nil
	}
	return &msg.QuestionSection[target]
}

func applySetQuestionType(msg *Message, target int, value uint64) (string, bool) {
	if value > 0xffff {
		return "", false
	}
	q := questionAt(msg, target)
	if q == nil {
		return "", false
	}
	old := q.Type
	q.Type = ResourceType(value)
	return fmt.Sprintf("changed the QTYPE of question %d from %s to %s", target+1, old, q.Type), true
}

func applySetQuestionClass(msg *Message, target int, value uint64) (string, bool) {
	if value > 0xffff {
		return "", false
	}
	q := questionAt(msg, target)
	if q == nil {
		return "", false
	}
	old := q.Class
	q.Class = ResourceClass(value)
	return fmt.Sprintf("changed the QCLASS of question %d from %s to %s", target+1, old, q.Class), true
}

func applySetRecordTTL(msg *Message, target int, value uint64) (string, bool) {
	rr, section, ordinal := recordAt(msg, target, nil)
	if rr == nil {
		return "", false
	}
	desc, ok := applyRecordTTL(rr, value)
	if !ok {
		return "", false
	}
	return recordDesc(section, ordinal, rr, desc), true
}

func applyFlipRecordRDataBit(msg *Message, target int, value uint64) (string, bool) {
	rr, section, ordinal := recordAt(msg, target, canFlipRDataBit)
	if rr == nil {
		return "", false
	}
	desc, ok := applyFlipRDataBit(rr, value)
	if !ok {
		return "", false
	}
	return recordDesc(section, ordinal, rr, desc), true
}

func applyRecordTTL(rr *ResourceRecord, value uint64) (string, bool) {
	if value > math.MaxUint32 {
		return "", false
	}
	old := rr.TTL
	rr.TTL = uint32(value)
	return fmt.Sprintf("set TTL from %d to %d", old, rr.TTL), true
}

// canFlipRDataBit reports whether rr's RDATA is a plain byte string that
// stays well-formed when one of its bits is flipped.
func canFlipRDataBit(rr *ResourceRecord) bool {
	switch rdata := rr.RData.(type) {
	case RecordA, RecordAAAA:
		return true
	case RecordRaw:
		return len(rdata.Data) > 0
	}
	return false
}

// rdataBitCount counts the bits of the canonical RDATA of a record for
// which canFlipRDataBit holds.
func rdataBitCount(rr *ResourceRecord) int {
	return 8 * len(rr.RData.CanonicalWireFormat())
}

func maxRDataBitValue(rr *ResourceRecord) uint64 {
	if !canFlipRDataBit(rr) {
		return 0
	}
	return uint64(rdataBitCount(rr)) - 1
}

func applyFlipRDataBit(rr *ResourceRecord, value uint64) (string, bool) {
	if !canFlipRDataBit(rr) || value >= uint64(rdataBitCount(rr)) {
		return "", false
	}
	bit := int(value)
	octet, shift := bit/8, bit%8
	switch rdata := rr.RData.(type) {
	case RecordA:
		next := rdata
		next.address[octet] ^= 1 << shift
		rr.RData = next
		return fmt.Sprintf("flipped bit %d of the A RDATA: %s to %s", bit, rdata, next), true
	case RecordAAAA:
		next := rdata
		next.address[octet] ^= 1 << shift
		rr.RData = next
		return fmt.Sprintf("flipped bit %d of the AAAA RDATA: %s to %s", bit, rdata, next), true
	case RecordRaw:
		data := make([]byte, len(rdata.Data))
		copy(data, rdata.Data)
		data[octet] ^= 1 << shift
		next := NewRecordRaw(rdata.rtype, data)
		rr.RData = next
		return fmt.Sprintf("flipped bit %d of the raw RDATA: %s to %s", bit, hex.EncodeToString(rdata.Data), hex.EncodeToString(data)), true
	}
	return "", false
}
