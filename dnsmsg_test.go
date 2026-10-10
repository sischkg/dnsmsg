package dnsmsg

import (
	"reflect"
	"testing"
)

// roundTripWire serializes msg to wire format for testing.
func roundTripWire(t *testing.T, msg Message) WireFormat {
	t.Helper()
	var w WireFormat
	w.WriteWireFormat(msg)
	return w
}

// craftedErrorWire builds a minimal single-question, single-answer message
// whose answer record has the given TYPE and RDLENGTH, followed by the raw
// RDATA bytes (which may be shorter than RDLENGTH or terminate in the
// middle of a field).  RDATA always begins at offset 36.
func craftedErrorWire(rtype ResourceType, rdlen uint16, rdata ...byte) WireFormat {
	var w WireFormat
	w.AppendUInt16(0x1234) // ID
	w.AppendUInt8(0x00)    // flags
	w.AppendUInt8(0x00)
	w.AppendUInt16(1) // QDCOUNT
	w.AppendUInt16(1) // ANCOUNT
	w.AppendUInt16(0) // NSCOUNT
	w.AppendUInt16(0) // ARCOUNT
	// Question: e.x IN A
	w.AppendBytes([]byte{0x01, 'e', 0x01, 'x', 0x00})
	w.AppendUInt16(uint16(TYPE_A))
	w.AppendUInt16(uint16(CLASS_IN))
	// Answer: e.x <rtype> IN 3600 <rdlen> <rdata...>
	w.AppendBytes([]byte{0x01, 'e', 0x01, 'x', 0x00})
	w.AppendUInt16(uint16(rtype))
	w.AppendUInt16(uint16(CLASS_IN))
	w.AppendUInt32(3600)
	w.AppendUInt16(rdlen)
	w.AppendBytes(rdata)
	return w
}

func TestParseWireFormat(t *testing.T) {
	example := testDomainName(t, "example.com.")

	aReply := Message{
		ID:      0x2345,
		QR:      1,
		RD:      1,
		RA:      1,
		QDCOUNT: 1,
		ANCOUNT: 1,
		QuestionSection: []QuestionSectionEntry{
			{QName: example, Class: CLASS_IN, Type: TYPE_A},
		},
		AnswerSection: []ResourceRecord{
			{
				Name: example, Class: CLASS_IN, Type: TYPE_A, TTL: 3600,
				RData: NewRecordA([4]byte{192, 0, 2, 53}),
			},
		},
	}

	soaReply := Message{
		ID:      0x0ABC,
		QR:      1,
		RD:      1,
		RA:      1,
		QDCOUNT: 1,
		ANCOUNT: 1,
		NSCOUNT: 1,
		QuestionSection: []QuestionSectionEntry{
			{QName: testDomainName(t, "example.net."), Class: CLASS_IN, Type: TYPE_SOA},
		},
		AnswerSection: []ResourceRecord{
			{
				Name: testDomainName(t, "example.net."), Class: CLASS_IN, Type: TYPE_SOA, TTL: 3600,
				RData: NewRecordSOA(
					testDomainName(t, "ns1.example.net."),
					testDomainName(t, "admin.example.net."),
					2026010101, 3600, 900, 1209600, 300,
				),
			},
		},
		AuthoritySection: []ResourceRecord{
			{
				Name: testDomainName(t, "example.net."), Class: CLASS_IN, Type: TYPE_NS, TTL: 3600,
				RData: NewRecordNS(testDomainName(t, "ns2.example.net.")),
			},
		},
	}

	aaaa, err := NewRecordAAAAFromString("2001:db8::53")
	if err != nil {
		t.Fatalf("NewRecordAAAAFromString() error = %v", err)
	}
	aaaaReply := Message{
		ID:      0x7777,
		QR:      1,
		RD:      1,
		RA:      1,
		QDCOUNT: 1,
		ANCOUNT: 2,
		QuestionSection: []QuestionSectionEntry{
			{QName: testDomainName(t, "host.example.org."), Class: CLASS_IN, Type: TYPE_AAAA},
		},
		AnswerSection: []ResourceRecord{
			{
				Name: testDomainName(t, "host.example.org."), Class: CLASS_IN, Type: TYPE_AAAA, TTL: 300,
				RData: aaaa,
			},
			{
				Name: testDomainName(t, "host.example.org."), Class: CLASS_IN, Type: TYPE_MX, TTL: 300,
				RData: NewRecordMX(10, testDomainName(t, "mail.example.org.")),
			},
		},
	}

	keyTag := uint16(0x3F1A)
	dnssecReply := Message{
		ID:      0x5555,
		QR:      1,
		RD:      1,
		AD:      1,
		QDCOUNT: 1,
		NSCOUNT: 1,
		ARCOUNT: 2,
		QuestionSection: []QuestionSectionEntry{
			{QName: example, Class: CLASS_IN, Type: TYPE_DNSKEY},
		},
		AuthoritySection: []ResourceRecord{
			{
				Name: example, Class: CLASS_IN, Type: TYPE_DNSKEY, TTL: 3600,
				RData: NewRecordDNSKEY(257, 3, 13, []byte{0x03, 0x2B, 0x8B, 0x9F, 0x44, 0x1C, 0x77, 0xD2}),
			},
		},
		AdditionalSection: []ResourceRecord{
			{
				Name: example, Class: CLASS_IN, Type: TYPE_RRSIG, TTL: 300,
				RData: NewRecordRRSIG(uint16(TYPE_DNSKEY), 13, 3, 3600, 0x7858A9B4, 0x78580000, keyTag, example,
					[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}),
			},
			{
				Name: example, Class: CLASS_IN, Type: TYPE_DS, TTL: 3600,
				RData: NewRecordDS(keyTag, 13, 2, []byte{
					0x8C, 0x5A, 0x2A, 0x4B, 0x11, 0x22, 0x33, 0x44,
					0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
				}),
			},
		},
	}

	rawData := []byte{0xAB, 0xCD, 0xEF}
	rawReply := Message{
		ID:      0x9999,
		QR:      1,
		RD:      1,
		RA:      1,
		QDCOUNT: 1,
		ANCOUNT: 1,
		QuestionSection: []QuestionSectionEntry{
			{QName: testDomainName(t, "raw.example."), Class: CLASS_IN, Type: ResourceType(16)},
		},
		AnswerSection: []ResourceRecord{
			{
				Name: testDomainName(t, "raw.example."), Class: CLASS_IN, Type: ResourceType(16), TTL: 3600,
				RData: NewRecordRaw(ResourceType(16), rawData),
			},
		},
	}

	tests := []struct {
		name    string
		input   WireFormat
		want    Message
		wantErr bool
	}{
		{
			name:  "A record reply",
			input: roundTripWire(t, aReply),
			want:  aReply,
		},
		{
			name:  "SOA reply with NS authority",
			input: roundTripWire(t, soaReply),
			want:  soaReply,
		},
		{
			name:  "AAAA and MX reply",
			input: roundTripWire(t, aaaaReply),
			want:  aaaaReply,
		},
		{
			name:  "DNSKEY reply with RRSIG and DS additional",
			input: roundTripWire(t, dnssecReply),
			want:  dnssecReply,
		},
		{
			name:  "header-only message",
			input: WireFormat{0x23, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			want:  Message{ID: 0x2345},
		},
		{
			name:  "trailing bytes after last section are ignored",
			input: append(roundTripWire(t, aReply), 0xDE),
			want:  aReply,
		},
		{
			name:  "unknown record type is parsed as raw record",
			input: roundTripWire(t, rawReply),
			want:  rawReply,
		},
		{
			name:    "empty wire",
			input:   WireFormat{},
			wantErr: true,
		},
		{
			name:    "message smaller than header and question",
			input:   WireFormat{0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0},
			wantErr: true,
		},
		{
			name: "unterminated question name",
			input: WireFormat{
				0, 0, 0, 0, // ID, flags
				0, 1, // QDCOUNT = 1
				0, 0, // ANCOUNT
				0, 0, // NSCOUNT
				0, 0, // ARCOUNT
				0x02, 'e', 'x', // QNAME: label of two characters, never terminated
			},
			wantErr: true,
		},
		{
			name: "compression pointer must point backwards",
			input: WireFormat{
				0, 0, 0, 0, // ID, flags
				0, 1, // QDCOUNT = 1
				0, 0, // ANCOUNT
				0, 0, // NSCOUNT
				0, 0, // ARCOUNT
				0xC0, 0x0C, // QNAME: pointer to the name's own position
			},
			wantErr: true,
		},
		{
			name: "answer record header truncated",
			input: WireFormat{
				0, 0, 0, 0, // ID, flags
				0, 1, // QDCOUNT = 1
				0, 1, // ANCOUNT = 1
				0, 0, // NSCOUNT
				0, 0, // ARCOUNT
				0x01, 'e', 0x01, 'x', 0, // question name: e.x
				0, 1, // QTYPE A
				0, 1, // QCLASS IN
				0x01, 'e', 0x01, 'x', 0, // answer name: e.x
				0, 1, // TYPE A
				0, 1, // CLASS IN (TTL and RDATA missing)
			},
			wantErr: true,
		},
		{
			name:    "A record RDATA truncated",
			input:   craftedErrorWire(TYPE_A, 4, 0xC0),
			wantErr: true,
		},
		{
			name:    "AAAA record RDATA truncated",
			input:   craftedErrorWire(TYPE_AAAA, 16, 0x20, 0x01),
			wantErr: true,
		},
		{
			name:    "DS record RDATA extends beyond message",
			input:   craftedErrorWire(TYPE_DS, 10, 0x3F, 0x1A, 13, 2, 0xAA),
			wantErr: true,
		},
		{
			name:    "DS record with empty digest",
			input:   craftedErrorWire(TYPE_DS, 4, 0x3F, 0x1A, 13, 2),
			wantErr: true,
		},
		{
			name:    "DNSKEY record RDATA extends beyond message",
			input:   craftedErrorWire(TYPE_DNSKEY, 8, 0x01, 0x01, 3, 13, 0x03),
			wantErr: true,
		},
		{
			name:    "DNSKEY record with empty public key",
			input:   craftedErrorWire(TYPE_DNSKEY, 4, 0x01, 0x01, 3, 13),
			wantErr: true,
		},
		{
			name: "RRSIG record with empty signature",
			input: craftedErrorWire(TYPE_RRSIG, 22,
				0x00, 0x30, // type covered: DNSKEY
				13,               // algorithm
				3,                // labels
				0, 0, 0x0E, 0x10, // original TTL
				0, 0, 1, 0, // expiration
				0, 0, 0, 0, // inception
				0, 1, // key tag
				2, 'n', 's', 0, // signers name: ns.
			),
			wantErr: true,
		},
		{
			name: "RRSIG record RDATA extends beyond message",
			input: craftedErrorWire(TYPE_RRSIG, 40,
				0x00, 0x30, // type covered: DNSKEY
				13,               // algorithm
				3,                // labels
				0, 0, 0x0E, 0x10, // original TTL
				0, 0, 1, 0, // expiration
				0, 0, 0, 0, // inception
				0, 1, // key tag
				2, 'n', 's', 0, // signers name: ns.
				0xAA, 0xBB, 0xCC, 0xDD, // signature bytes
			),
			wantErr: true,
		},
		{
			name:    "unknown record type RDATA extends beyond message",
			input:   craftedErrorWire(ResourceType(16), 10, 0xAB, 0xCD),
			wantErr: true,
		},
		{
			name:    "NS record with unterminated name",
			input:   craftedErrorWire(TYPE_NS, 3, 2, 'n', 's'),
			wantErr: true,
		},
		{
			name: "MX record exchange name crosses end of message",
			input: craftedErrorWire(TYPE_MX, 4,
				0x00, 0x0A, // preference 10
				0x02, 'n', // label of two characters with only one present
			),
			wantErr: true,
		},
		{
			name: "SOA record truncated before timers",
			input: craftedErrorWire(TYPE_SOA, 19,
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // mname: example
				0x03, 'c', 'o', 'm', // mname: example.com
				0x00,           // root label
				0x02, 'a', 'd', // rname: ad
				0x00,       // root label
				0x00, 0x01, // only two of the twenty timer bytes
			),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseWireFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseWireFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseWireFormat() got =\n%#v\n\nwant =\n%#v", got, tt.want)
			}
		})
	}
}

func TestWriteWireFormat(t *testing.T) {
	example := testDomainName(t, "example.com.")

	aReply := Message{
		ID:      0x2345,
		QR:      1,
		RD:      1,
		RA:      1,
		QDCOUNT: 1,
		ANCOUNT: 1,
		QuestionSection: []QuestionSectionEntry{
			{QName: example, Class: CLASS_IN, Type: TYPE_A},
		},
		AnswerSection: []ResourceRecord{
			{
				Name: example, Class: CLASS_IN, Type: TYPE_A, TTL: 3600,
				RData: NewRecordA([4]byte{192, 0, 2, 53}),
			},
		},
	}

	mxReply := Message{
		ID:      0x4321,
		QR:      1,
		RD:      1,
		RA:      1,
		QDCOUNT: 1,
		ANCOUNT: 2,
		ARCOUNT: 2,
		QuestionSection: []QuestionSectionEntry{
			{QName: example, Class: CLASS_IN, Type: TYPE_MX},
		},
		AnswerSection: []ResourceRecord{
			{
				Name: example, Class: CLASS_IN, Type: TYPE_MX, TTL: 3600,
				RData: NewRecordMX(10, testDomainName(t, "mx01.example.com.")),
			},
			{
				Name: example, Class: CLASS_IN, Type: TYPE_MX, TTL: 3600,
				RData: NewRecordMX(20, testDomainName(t, "mx02.example.com.")),
			},
		},
		AdditionalSection: []ResourceRecord{
			{
				Name: testDomainName(t, "mx01.example.com."), Class: CLASS_IN, Type: TYPE_A, TTL: 3600,
				RData: NewRecordA([4]byte{192, 0, 2, 1}),
			},
			{
				Name: testDomainName(t, "mx02.example.com."), Class: CLASS_IN, Type: TYPE_A, TTL: 3600,
				RData: NewRecordA([4]byte{192, 0, 2, 2}),
			},
		},
	}

	tests := []struct {
		name      string
		seed      WireFormat // content pre-existing in the wire
		msg       Message
		want      WireFormat
		roundTrip bool // parse the result back and compare with msg
	}{
		{
			name: "empty message writes the 12-byte header only",
			msg:  Message{ID: 0x1234},
			want: WireFormat{
				0x12, 0x34, // ID
				0x00,       // flags1
				0x00,       // flags2
				0x00, 0x00, // QDCOUNT
				0x00, 0x00, // ANCOUNT
				0x00, 0x00, // NSCOUNT
				0x00, 0x00, // ARCOUNT
			},
		},
		{
			name: "header flags occupy their RFC 1035 bit positions",
			msg: Message{
				ID: 0x1234,
				QR: 1, OPCODE: 3, AA: 1, TC: 1, RD: 1,
				RA: 1, Z: 1, AD: 1, CD: 1, RCODE: 3,
			},
			want: WireFormat{
				0x12, 0x34, // ID
				0x9F,       // flags1: QR|OPCODE(3)<<3|AA<<2|TC<<1|RD
				0xF3,       // flags2: RA<<7|Z<<6|AD<<5|CD<<4|RCODE(3)
				0x00, 0x00, // QDCOUNT
				0x00, 0x00, // ANCOUNT
				0x00, 0x00, // NSCOUNT
				0x00, 0x00, // ARCOUNT
			},
		},
		{
			name: "section counts are written verbatim",
			msg:  Message{QDCOUNT: 3, ANCOUNT: 4, NSCOUNT: 5, ARCOUNT: 6},
			want: WireFormat{
				0x00, 0x00, // ID
				0x00,       // flags1
				0x00,       // flags2
				0x00, 0x03, // QDCOUNT
				0x00, 0x04, // ANCOUNT
				0x00, 0x05, // NSCOUNT
				0x00, 0x06, // ARCOUNT
			},
		},
		{
			name: "answer name is emitted as a compression pointer to the question name",
			msg:  aReply,
			want: WireFormat{
				0x23, 0x45, // ID
				0x81,       // flags1: QR|RD
				0x80,       // flags2: RA
				0x00, 0x01, // QDCOUNT
				0x00, 0x01, // ANCOUNT
				0x00, 0x00, // NSCOUNT
				0x00, 0x00, // ARCOUNT
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // question name: example
				0x03, 'c', 'o', 'm', // example.com
				0x00,       // root label
				0x00, 0x01, // QTYPE: A
				0x00, 0x01, // QCLASS: IN
				0xC0, 0x0C, // answer name: pointer to offset 12
				0x00, 0x01, // TYPE: A
				0x00, 0x01, // CLASS: IN
				0x00, 0x00, 0x0E, 0x10, // TTL: 3600
				0x00, 0x04, // RDLENGTH
				192, 0, 2, 53, // RDATA: 192.0.2.53
			},
			roundTrip: true,
		},
		{
			name: "appends after pre-existing content and rebases the compression pointer",
			seed: WireFormat{0xFF},
			msg:  aReply,
			want: WireFormat{
				0xFF,       // pre-existing content
				0x23, 0x45, // ID
				0x81,       // flags1: QR|RD
				0x80,       // flags2: RA
				0x00, 0x01, // QDCOUNT
				0x00, 0x01, // ANCOUNT
				0x00, 0x00, // NSCOUNT
				0x00, 0x00, // ARCOUNT
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // question name: example
				0x03, 'c', 'o', 'm', // example.com
				0x00,       // root label
				0x00, 0x01, // QTYPE: A
				0x00, 0x01, // QCLASS: IN
				0xC0, 0x0D, // answer name: pointer to offset 13
				0x00, 0x01, // TYPE: A
				0x00, 0x01, // CLASS: IN
				0x00, 0x00, 0x0E, 0x10, // TTL: 3600
				0x00, 0x04, // RDLENGTH
				192, 0, 2, 53, // RDATA: 192.0.2.53
			},
		},
		{
			name: "MX response: two MX answers with A glue in the additional section",
			msg:  mxReply,
			want: WireFormat{
				0x43, 0x21, // ID
				0x81,       // flags1: QR|RD
				0x80,       // flags2: RA
				0x00, 0x01, // QDCOUNT
				0x00, 0x02, // ANCOUNT
				0x00, 0x00, // NSCOUNT
				0x00, 0x02, // ARCOUNT
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // question name: example
				0x03, 'c', 'o', 'm', // example.com
				0x00,       // root label
				0x00, 0x0F, // QTYPE: MX
				0x00, 0x01, // QCLASS: IN
				0xC0, 0x0C, // answer 1 name: pointer to offset 12 (example.com.)
				0x00, 0x0F, // TYPE: MX
				0x00, 0x01, // CLASS: IN
				0x00, 0x00, 0x0E, 0x10, // TTL: 3600
				0x00, 0x09, // RDLENGTH
				0x00, 0x0A, // preference: 10
				0x04, 'm', 'x', '0', '1', // exchange: mx01
				0xC0, 0x0C, // ...example.com (pointer to offset 12)
				0xC0, 0x0C, // answer 2 name: pointer to offset 12 (example.com.)
				0x00, 0x0F, // TYPE: MX
				0x00, 0x01, // CLASS: IN
				0x00, 0x00, 0x0E, 0x10, // TTL: 3600
				0x00, 0x09, // RDLENGTH
				0x00, 0x14, // preference: 20
				0x04, 'm', 'x', '0', '2', // exchange: mx02
				0xC0, 0x0C, // ...example.com (pointer to offset 12)
				0xC0, 0x2B, // additional 1 name: pointer to offset 43 (mx01.example.com.)
				0x00, 0x01, // TYPE: A
				0x00, 0x01, // CLASS: IN
				0x00, 0x00, 0x0E, 0x10, // TTL: 3600
				0x00, 0x04, // RDLENGTH
				192, 0, 2, 1, // RDATA: 192.0.2.1
				0xC0, 0x40, // additional 2 name: pointer to offset 64 (mx02.example.com.)
				0x00, 0x01, // TYPE: A
				0x00, 0x01, // CLASS: IN
				0x00, 0x00, 0x0E, 0x10, // TTL: 3600
				0x00, 0x04, // RDLENGTH
				192, 0, 2, 2, // RDATA: 192.0.2.2
			},
			roundTrip: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := append(WireFormat{}, tt.seed...)
			before := w.Size()
			size := w.WriteWireFormat(tt.msg)
			if size != w.Size()-before {
				t.Errorf("WriteWireFormat() = %d bytes appended, want %d", size, w.Size()-before)
			}
			if !reflect.DeepEqual(w, tt.want) {
				t.Errorf("WriteWireFormat() =\n%v\n\nwant =\n%v", w, tt.want)
			}
			if !tt.roundTrip {
				return
			}
			got, err := ParseWireFormat(w)
			if err != nil {
				t.Fatalf("ParseWireFormat() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.msg) {
				t.Errorf("ParseWireFormat(WriteWireFormat(m)) =\n%#v\n\nwant =\n%#v", got, tt.msg)
			}
		})
	}
}

func TestWriteWireFormatNilWire(t *testing.T) {
	var w *WireFormat
	size := w.WriteWireFormat(Message{ID: 0x1234})
	if size != 0 || w != nil {
		t.Errorf("WriteWireFormat() on nil WireFormat = size %d, w %v; want 0, nil", size, w)
	}
}
