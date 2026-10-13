package dnsmsg

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestDomainNameMarshalJSON tests that a domain name is exported as its
// presentation-format string.
func TestDomainNameMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: ".",
			want: `"."`,
		},
		{
			name: "example.com",
			want: `"example.com."`,
		},
		{
			name: "a.b.c",
			want: `"a.b.c."`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := testDomainName(t, tt.name)
			got, err := json.Marshal(d)
			if err != nil {
				t.Errorf("json.Marshal() error = %v", err)
				return
			}
			if string(got) != tt.want {
				t.Errorf("json.Marshal() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

// TestRecordMarshalJSON tests that resource records are exported as JSON
// objects that keep the presentation-format strings of their fields.
func TestRecordMarshalJSON(t *testing.T) {
	tests := []struct {
		name  string
		rdata RDATA
		want  string
	}{
		{
			name:  "A record",
			rdata: NewRecordA([4]byte{192, 134, 1, 21}),
			want:  `{"address":"192.134.1.21"}`,
		},
		{
			name:  "NS record",
			rdata: NewRecordNS(testDomainName(t, "ns1.example.com")),
			want:  `{"nsname":"ns1.example.com."}`,
		},
		{
			name:  "SOA record",
			rdata: NewRecordSOA(testDomainName(t, "a.root-sns.net"), testDomainName(t, "a.root-sns.net"), 20240817, 0, 0, 0, 0),
			want:  `{"expire":0,"minimum":0,"mname":"a.root-sns.net.","refresh":0,"retry":0,"rname":"a.root-sns.net.","serial":20240817}`,
		},
		{
			name:  "MX record",
			rdata: NewRecordMX(3600, testDomainName(t, "mail.example.com")),
			want:  `{"Exchange":"mail.example.com.","Preference":3600}`,
		},
		{
			name:  "AAAA record",
			rdata: NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
			want:  `{"address":"::1"}`,
		},
		{
			name:  "DS record",
			rdata: NewRecordDS(1000, 5, 1, []byte{0x00, 0x01}),
			want:  `{"Algorithm":5,"Digest":"0001","DigestType":1,"KeyTag":1000}`,
		},
		{
			name:  "OPT record",
			rdata: NewRecordOPT(0, 0x8000, EDNSOptionDNSSEC{}, EDNSOptionNSID{ID: "ednsx"}, NewEDNSOptionEDE(6, "bogus"), EDNSOptionRaw{OptionCode: 8, OptionData: []byte{0x00, 0x00, 0x01, 0x18, 0x01, 0xc6, 0x33, 0x64}}),
			want:  `{"Flags":32768,"Options":[{"Code":1},{"Code":3,"ID":"ednsx"},{"Code":15,"ErrorCode":6,"ExtraText":"bogus"},{"Code":8,"OptionData":"0000011801c63364"}],"Version":0}`,
		},
		{
			name:  "RRSIG record",
			rdata: NewRecordRRSIG(1, 1, 1, 3600, 1457745740, 1457659200, 9526, testDomainName(t, "example.com"), []byte("key")),
			want:  `{"Algorithm":1,"Expiration":1457745740,"Inception":1457659200,"KeyTag":9526,"Labels":1,"OrigTTL":3600,"Signature":"a2V5","SignersName":"example.com.","TypeCovered":"A"}`,
		},
		{
			name:  "DNSKEY record",
			rdata: NewRecordDNSKEY(256, 3, 1, []byte{0x01, 0x02}),
			want:  `{"Algorithm":1,"Flags":256,"Protocol":3,"PublicKey":"AQI"}`,
		},
		{
			name:  "unknown type record",
			rdata: RecordRaw{rtype: 100, Data: []byte{0x66, 0x66}},
			want:  `{"Data":"ZmY","rtype":"TYPE100"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.rdata)
			if err != nil {
				t.Errorf("json.Marshal() error = %v", err)
				return
			}
			if string(got) != tt.want {
				t.Errorf("json.Marshal() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

// TestResourceRecordMarshalJSON tests that a resource record is exported as
// a JSON object with its name, class, type, TTL, and RDATA.
func TestResourceRecordMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		rr   ResourceRecord
		want string
	}{
		{
			name: "A record",
			rr: ResourceRecord{
				Name:  testDomainName(t, "example.com"),
				Class: CLASS_IN,
				Type:  TYPE_A,
				TTL:   300,
				RData: NewRecordA([4]byte{192, 134, 1, 21}),
			},
			want: `{"Class":"IN","Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300,"Type":"A"}`,
		},
		{
			name: "unknown type record",
			rr: ResourceRecord{
				Name:  testDomainName(t, "example.com"),
				Class: CLASS_IN,
				Type:  100,
				TTL:   0,
				RData: RecordRaw{rtype: 100, Data: []byte{0x66, 0x66}},
			},
			want: `{"Class":"IN","Name":"example.com.","RData":{"Data":"ZmY","rtype":"TYPE100"},"TTL":0,"Type":"TYPE100"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.rr)
			if err != nil {
				t.Errorf("json.Marshal() error = %v", err)
				return
			}
			if string(got) != tt.want {
				t.Errorf("json.Marshal() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

// TestMessageMarshalJSON tests that a message is exported as a JSON object
// with its header fields and all four question/answer/authority/additional
// sections.  The count fields are exported as stored, not derived from the
// section lengths, and a section that is not present is exported as null.
func TestMessageMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want string
	}{
		{
			name: "empty message",
			msg: Message{
				ID:      1,
				QR:      1,
				OPCODE:  0,
				AA:      0,
				TC:      0,
				RD:      0,
				RA:      0,
				Z:       0,
				AD:      0,
				CD:      0,
				RCODE:   0,
				QDCOUNT: 0,
				ANCOUNT: 0,
				NSCOUNT: 0,
				ARCOUNT: 0,
			},
			want: `{"AA":0,"AD":0,"ANCOUNT":0,"ARCOUNT":0,"AdditionalSection":null,"AnswerSection":null,"AuthoritySection":null,"CD":0,"ID":1,"NSCOUNT":0,"OPCODE":0,"QDCOUNT":0,"QR":1,"QuestionSection":null,"RA":0,"RCODE":0,"RD":0,"TC":0,"Z":0}`,
		},
		{
			name: "query with an answer",
			msg: Message{
				ID:      1,
				QR:      1,
				QDCOUNT: 1,
				ANCOUNT: 1,
				QuestionSection: []QuestionSectionEntry{
					QuestionSectionEntry{
						QName: testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_A,
					},
				},
				AnswerSection: []ResourceRecord{
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_A,
						TTL:   300,
						RData: NewRecordA([4]byte{192, 134, 1, 21}),
					},
				},
			},
			want: `{"AA":0,"AD":0,"ANCOUNT":1,"ARCOUNT":0,"AdditionalSection":null,"AnswerSection":[{"Class":"IN","Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300,"Type":"A"}],"AuthoritySection":null,"CD":0,"ID":1,"NSCOUNT":0,"OPCODE":0,"QDCOUNT":1,"QR":1,"QuestionSection":[{"Class":"IN","QName":"example.com.","Type":"A"}],"RA":0,"RCODE":0,"RD":0,"TC":0,"Z":0}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.msg)
			if err != nil {
				t.Errorf("json.Marshal() error = %v", err)
				return
			}
			if string(got) != tt.want {
				t.Errorf("json.Marshal() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

// TestDomainNameUnmarshalJSON tests that a domain name is imported from its
// presentation-format string.
func TestDomainNameUnmarshalJSON(t *testing.T) {
	tests := []struct {
		json string
		want string
	}{
		{
			json: `"."`,
			want: ".",
		},
		{
			json: `""`,
			want: ".",
		},
		{
			json: `"example.com."`,
			want: "example.com.",
		},
		{
			json: `"example.com"`,
			want: "example.com.",
		},
		{
			json: `"a.b.c."`,
			want: "a.b.c.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.json, func(t *testing.T) {
			var d DomainName
			if err := json.Unmarshal([]byte(tt.json), &d); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}
			if got := d.String(); got != tt.want {
				t.Errorf("json.Unmarshal(%s) = %q, want %q", tt.json, got, tt.want)
			}
		})
	}
}

// TestDomainNameUnmarshalJSONErrors tests that a domain name that is not a
// string, or a string that is not a valid domain name, is rejected.
func TestDomainNameUnmarshalJSONErrors(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "not a string",
			json: `123`,
		},
		{
			name: "empty label",
			json: `"a..b."`,
		},
		{
			name: "label too long",
			json: `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example."`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d DomainName
			if err := json.Unmarshal([]byte(tt.json), &d); err == nil {
				t.Errorf("json.Unmarshal(%s) error = nil, want an error", tt.json)
			}
		})
	}
}

// newRDATA returns a pointer to a new zero value of the same concrete type as
// rdata, so that json.Unmarshal decodes through that type's UnmarshalJSON.
func newRDATA(rdata RDATA) any {
	return reflect.New(reflect.TypeOf(rdata)).Interface()
}

// copyRDATA returns a pointer to a copy of rdata.  json.Unmarshal decodes a
// record into a pointer, and reflect.DeepEqual follows pointers, so comparing
// the decoded value with a copy of the expected record compares the records.
func copyRDATA(rdata RDATA) any {
	p := reflect.New(reflect.TypeOf(rdata))
	p.Elem().Set(reflect.ValueOf(rdata))
	return p.Interface()
}

// TestRecordUnmarshalJSON tests that resource records are imported from the
// JSON objects MarshalJSON produces.
func TestRecordUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want RDATA
	}{
		{
			name: "A record",
			json: `{"address":"192.134.1.21"}`,
			want: NewRecordA([4]byte{192, 134, 1, 21}),
		},
		{
			name: "AAAA record",
			json: `{"address":"::1"}`,
			want: NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		},
		{
			name: "NS record",
			json: `{"nsname":"ns1.example.com."}`,
			want: NewRecordNS(testDomainName(t, "ns1.example.com")),
		},
		{
			name: "SOA record",
			json: `{"expire":0,"minimum":0,"mname":"a.root-sns.net.","refresh":0,"retry":0,"rname":"a.root-sns.net.","serial":20240817}`,
			want: NewRecordSOA(testDomainName(t, "a.root-sns.net"), testDomainName(t, "a.root-sns.net"), 20240817, 0, 0, 0, 0),
		},
		{
			name: "MX record",
			json: `{"Exchange":"mail.example.com.","Preference":3600}`,
			want: NewRecordMX(3600, testDomainName(t, "mail.example.com")),
		},
		{
			name: "DS record",
			json: `{"Algorithm":5,"Digest":"0001","DigestType":1,"KeyTag":1000}`,
			want: NewRecordDS(1000, 5, 1, []byte{0x00, 0x01}),
		},
		{
			name: "RRSIG record",
			json: `{"Algorithm":1,"Expiration":1457745740,"Inception":1457659200,"KeyTag":9526,"Labels":1,"OrigTTL":3600,"Signature":"a2V5","SignersName":"example.com.","TypeCovered":"A"}`,
			want: NewRecordRRSIG(1, 1, 1, 3600, 1457745740, 1457659200, 9526, testDomainName(t, "example.com"), []byte("key")),
		},
		{
			name: "DNSKEY record",
			json: `{"Algorithm":1,"Flags":256,"Protocol":3,"PublicKey":"AQI"}`,
			want: NewRecordDNSKEY(256, 3, 1, []byte{0x01, 0x02}),
		},
		{
			name: "unknown type record",
			json: `{"Data":"ZmY","rtype":"TYPE100"}`,
			want: RecordRaw{rtype: 100, Data: []byte{0x66, 0x66}},
		},
		{
			name: "OPT record",
			json: `{"Flags":32768,"Options":[{"Code":1},{"Code":3,"ID":"ednsx"},{"Code":15,"ErrorCode":6,"ExtraText":"bogus"},{"Code":8,"OptionData":"0000011801c63364"}],"Version":0}`,
			want: NewRecordOPT(0, 0x8000, &EDNSOptionDNSSEC{}, &EDNSOptionNSID{ID: "ednsx"}, &EDNSOptionEDE{ErrorCode: 6, ExtraText: "bogus"}, &EDNSOptionRaw{OptionCode: 8, OptionData: []byte{0x00, 0x00, 0x01, 0x18, 0x01, 0xc6, 0x33, 0x64}}),
		},
		{
			name: "OPT record without options",
			json: `{"Flags":32768,"Options":null,"Version":0}`,
			want: NewRecordOPT(0, 0x8000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newRDATA(tt.want)
			if err := json.Unmarshal([]byte(tt.json), got); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}
			want := copyRDATA(tt.want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("json.Unmarshal(%s) = %+v, want %+v", tt.json, got, want)
			}
		})
	}
}

// TestRecordUnmarshalJSONErrors tests that malformed RDATA is rejected.
func TestRecordUnmarshalJSONErrors(t *testing.T) {
	tests := []struct {
		name  string
		json  string
		rdata RDATA
	}{
		{
			name:  "A record with an address that is not IPv4",
			json:  `{"address":"::1"}`,
			rdata: RecordA{},
		},
		{
			name:  "A record with a malformed address",
			json:  `{"address":"10.0.0.256"}`,
			rdata: RecordA{},
		},
		{
			name:  "NS record with a malformed domain name",
			json:  `{"nsname":"a..b."}`,
			rdata: RecordNS{},
		},
		{
			name:  "DS record with a malformed digest",
			json:  `{"Algorithm":5,"Digest":"zz","DigestType":1,"KeyTag":1000}`,
			rdata: RecordDS{},
		},
		{
			name:  "raw record with malformed base64",
			json:  `{"Data":"!!!"}`,
			rdata: RecordRaw{},
		},
		{
			name:  "raw record with an unknown type name",
			json:  `{"Data":"aGVsbG8","rtype":"XX"}`,
			rdata: RecordRaw{},
		},
		{
			name:  "OPT record with an option that has no code",
			json:  `{"Flags":0,"Options":[{"Code":"x"}],"Version":0}`,
			rdata: RecordOPT{},
		},
		{
			name:  "OPT record with a malformed EDE option",
			json:  `{"Flags":0,"Options":[{"Code":15,"ExtraText":5}],"Version":0}`,
			rdata: RecordOPT{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newRDATA(tt.rdata)
			if err := json.Unmarshal([]byte(tt.json), got); err == nil {
				t.Errorf("json.Unmarshal(%s) error = nil, want an error", tt.json)
			}
		})
	}
}

// TestResourceRecordUnmarshalJSON tests that a resource record is imported from
// the JSON object MarshalJSON produces.  The class and the type are accepted
// either as the name strings MarshalJSON produces or as their numeric codes,
// and a record of a type the library does not interpret is imported as a raw
// record.
func TestResourceRecordUnmarshalJSON(t *testing.T) {
	aRecord := NewRecordA([4]byte{192, 134, 1, 21})
	nsRecord := NewRecordNS(testDomainName(t, "ns1.example.com"))
	rawRecord := RecordRaw{rtype: 100, Data: []byte{0x66, 0x66}}

	tests := []struct {
		name string
		json string
		want ResourceRecord
	}{
		{
			name: "A record",
			json: `{"Class":"IN","Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300,"Type":"A"}`,
			want: ResourceRecord{
				Name:  testDomainName(t, "example.com"),
				Class: CLASS_IN,
				Type:  TYPE_A,
				TTL:   300,
				RData: &aRecord,
			},
		},
		{
			name: "NS record",
			json: `{"Class":"IN","Name":"example.com.","RData":{"nsname":"ns1.example.com."},"TTL":300,"Type":"NS"}`,
			want: ResourceRecord{
				Name:  testDomainName(t, "example.com"),
				Class: CLASS_IN,
				Type:  TYPE_NS,
				TTL:   300,
				RData: &nsRecord,
			},
		},
		{
			name: "class and type given as numbers",
			json: `{"Class":1,"Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300,"Type":1}`,
			want: ResourceRecord{
				Name:  testDomainName(t, "example.com"),
				Class: CLASS_IN,
				Type:  TYPE_A,
				TTL:   300,
				RData: &aRecord,
			},
		},
		{
			name: "class and type given as CLASS and TYPE names",
			json: `{"Class":"CLASS3","Name":"example.com.","RData":{"nsname":"ns1.example.com."},"TTL":300,"Type":"TYPE2"}`,
			want: ResourceRecord{
				Name:  testDomainName(t, "example.com"),
				Class: CLASS_CHAOS,
				Type:  TYPE_NS,
				TTL:   300,
				RData: &nsRecord,
			},
		},
		{
			name: "unknown type is imported as a raw record",
			json: `{"Class":"IN","Name":"example.com.","RData":{"Data":"ZmY","rtype":"TYPE100"},"TTL":0,"Type":"TYPE100"}`,
			want: ResourceRecord{
				Name:  testDomainName(t, "example.com"),
				Class: CLASS_IN,
				Type:  100,
				TTL:   0,
				RData: &rawRecord,
			},
		},
		{
			name: "raw RDATA without its own type",
			json: `{"Class":"IN","Name":"example.com.","RData":{"Data":"ZmY"},"TTL":0,"Type":"TYPE100"}`,
			want: ResourceRecord{
				Name:  testDomainName(t, "example.com"),
				Class: CLASS_IN,
				Type:  100,
				TTL:   0,
				RData: &rawRecord,
			},
		},
		{
			name: "record without RDATA",
			json: `{"Class":"IN","Name":"example.com.","TTL":300,"Type":"A"}`,
			want: ResourceRecord{
				Name:  testDomainName(t, "example.com"),
				Class: CLASS_IN,
				Type:  TYPE_A,
				TTL:   300,
			},
		},
		{
			name: "record with null RDATA",
			json: `{"Class":"IN","Name":"example.com.","RData":null,"TTL":300,"Type":"A"}`,
			want: ResourceRecord{
				Name:  testDomainName(t, "example.com"),
				Class: CLASS_IN,
				Type:  TYPE_A,
				TTL:   300,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ResourceRecord
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("json.Unmarshal(%s) = %+v, want %+v", tt.json, got, tt.want)
			}
		})
	}
}

// TestResourceRecordUnmarshalJSONErrors tests that a resource record without a
// class or a type, or with a class or a type the library does not know, is
// rejected.
func TestResourceRecordUnmarshalJSONErrors(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "missing class",
			json: `{"Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300,"Type":"A"}`,
		},
		{
			name: "missing type",
			json: `{"Class":"IN","Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300}`,
		},
		{
			name: "unknown class name",
			json: `{"Class":"XX","Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300,"Type":"A"}`,
		},
		{
			name: "unknown type name",
			json: `{"Class":"IN","Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300,"Type":"XX"}`,
		},
		{
			name: "malformed RDATA",
			json: `{"Class":"IN","Name":"example.com.","RData":{"address":"10.0.0.256"},"TTL":300,"Type":"A"}`,
		},
		{
			name: "truncated JSON",
			json: `{"Class":"IN"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ResourceRecord
			if err := json.Unmarshal([]byte(tt.json), &got); err == nil {
				t.Errorf("json.Unmarshal(%s) error = nil, want an error", tt.json)
			}
		})
	}
}

// TestMessageUnmarshalJSON tests that a message is imported from the JSON
// object MarshalJSON produces, including its header fields and its four
// sections.  A section exported as null is imported as a section that is not
// present.
func TestMessageUnmarshalJSON(t *testing.T) {
	aRecord := NewRecordA([4]byte{192, 134, 1, 21})

	tests := []struct {
		name string
		json string
		want Message
	}{
		{
			name: "empty message",
			json: `{"AA":0,"AD":0,"ANCOUNT":0,"ARCOUNT":0,"AdditionalSection":null,"AnswerSection":null,"AuthoritySection":null,"CD":0,"ID":1,"NSCOUNT":0,"OPCODE":0,"QDCOUNT":0,"QR":1,"QuestionSection":null,"RA":0,"RCODE":0,"RD":0,"TC":0,"Z":0}`,
			want: Message{
				ID:      1,
				QR:      1,
				OPCODE:  0,
				AA:      0,
				TC:      0,
				RD:      0,
				RA:      0,
				Z:       0,
				AD:      0,
				CD:      0,
				RCODE:   0,
				QDCOUNT: 0,
				ANCOUNT: 0,
				NSCOUNT: 0,
				ARCOUNT: 0,
			},
		},
		{
			name: "query with an answer",
			json: `{"AA":0,"AD":0,"ANCOUNT":1,"ARCOUNT":0,"AdditionalSection":null,"AnswerSection":[{"Class":"IN","Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300,"Type":"A"}],"AuthoritySection":null,"CD":0,"ID":1,"NSCOUNT":0,"OPCODE":0,"QDCOUNT":1,"QR":1,"QuestionSection":[{"Class":"IN","QName":"example.com.","Type":"A"}],"RA":0,"RCODE":0,"RD":0,"TC":0,"Z":0}`,
			want: Message{
				ID:      1,
				QR:      1,
				QDCOUNT: 1,
				ANCOUNT: 1,
				QuestionSection: []QuestionSectionEntry{
					QuestionSectionEntry{
						QName: testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_A,
					},
				},
				AnswerSection: []ResourceRecord{
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_A,
						TTL:   300,
						RData: &aRecord,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Message
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("json.Unmarshal(%s) = %+v, want %+v", tt.json, got, tt.want)
			}
		})
	}
}

// TestMessageUnmarshalJSONErrors tests that a message whose header fields or
// whose sections are malformed is rejected.
func TestMessageUnmarshalJSONErrors(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "header field of the wrong type",
			json: `{"ID":"one"}`,
		},
		{
			name: "section of the wrong type",
			json: `{"AnswerSection":{"Class":"IN"}}`,
		},
		{
			name: "malformed section entry",
			json: `{"AnswerSection":[{"Class":"IN","Name":"example.com.","TTL":300}]}`,
		},
		{
			name: "truncated JSON",
			json: `{"ID":1,"QuestionSection":`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Message
			if err := json.Unmarshal([]byte(tt.json), &got); err == nil {
				t.Errorf("json.Unmarshal(%s) error = nil, want an error", tt.json)
			}
		})
	}
}

// hasSections reports whether a message has any question, answer, authority, or
// additional entry.  A message without entries is the length of its header,
// which the wire-format parser rejects as a truncated message.
func hasSections(msg *Message) bool {
	return len(msg.QuestionSection)+len(msg.AnswerSection)+len(msg.AuthoritySection)+len(msg.AdditionalSection) > 0
}

// TestMessageJSONRoundTrip tests that a message survives a round trip through
// JSON: marshalling a message, unmarshalling the JSON, and marshalling the
// result produces the same JSON.  A message that has entries is also written
// to the wire format and parsed back from it, and the parsed message must
// produce the same JSON as the original one.
func TestMessageJSONRoundTrip(t *testing.T) {
	aRecord := NewRecordA([4]byte{192, 134, 1, 21})
	aaaaRecord := NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	nsRecord := NewRecordNS(testDomainName(t, "ns1.example.com"))
	soaRecord := NewRecordSOA(testDomainName(t, "a.root-sns.net"), testDomainName(t, "a.root-sns.net"), 20240817, 0, 0, 0, 0)
	mxRecord := NewRecordMX(3600, testDomainName(t, "mail.example.com"))
	dsRecord := NewRecordDS(1000, 5, 1, []byte{0x00, 0x01})
	rrsigRecord := NewRecordRRSIG(1, 1, 1, 3600, 1457745740, 1457659200, 9526, testDomainName(t, "example.com"), []byte("key"))
	dnskeyRecord := NewRecordDNSKEY(256, 3, 1, []byte{0x01, 0x02})
	rawRecord := RecordRaw{rtype: 100, Data: []byte{0x66, 0x66}}
	optRecord := NewRecordOPT(0, 0x8000, &EDNSOptionDNSSEC{}, &EDNSOptionNSID{ID: "ednsx"}, &EDNSOptionEDE{ErrorCode: 6, ExtraText: "bogus"}, &EDNSOptionRaw{OptionCode: 8, OptionData: []byte{0x00, 0x00, 0x01, 0x18, 0x01, 0xc6, 0x33, 0x64}})

	tests := []struct {
		name string
		msg  Message
	}{
		{
			name: "empty message",
			msg: Message{
				ID: 1,
				QR: 1,
			},
		},
		{
			name: "query with an answer",
			msg: Message{
				ID:      1,
				QR:      1,
				RD:      1,
				QDCOUNT: 1,
				ANCOUNT: 1,
				QuestionSection: []QuestionSectionEntry{
					QuestionSectionEntry{
						QName: testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_A,
					},
				},
				AnswerSection: []ResourceRecord{
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_A,
						TTL:   300,
						RData: &aRecord,
					},
				},
			},
		},
		{
			name: "response with every record type",
			msg: Message{
				ID:      0x1234,
				QR:      1,
				AA:      1,
				RD:      1,
				RA:      1,
				ANCOUNT: 9,
				ARCOUNT: 1,
				AnswerSection: []ResourceRecord{
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_A,
						TTL:   300,
						RData: &aRecord,
					},
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_AAAA,
						TTL:   300,
						RData: &aaaaRecord,
					},
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_NS,
						TTL:   300,
						RData: &nsRecord,
					},
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_SOA,
						TTL:   300,
						RData: &soaRecord,
					},
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_MX,
						TTL:   300,
						RData: &mxRecord,
					},
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_DS,
						TTL:   300,
						RData: &dsRecord,
					},
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_RRSIG,
						TTL:   300,
						RData: &rrsigRecord,
					},
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  TYPE_DNSKEY,
						TTL:   300,
						RData: &dnskeyRecord,
					},
					ResourceRecord{
						Name:  testDomainName(t, "example.com"),
						Class: CLASS_IN,
						Type:  100,
						TTL:   300,
						RData: &rawRecord,
					},
				},
				AdditionalSection: []ResourceRecord{
					ResourceRecord{
						Name:  testDomainName(t, "."),
						Class: CLASS_IN,
						Type:  TYPE_OPT,
						TTL:   0,
						RData: &optRecord,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := json.Marshal(tt.msg)
			if err != nil {
				t.Errorf("json.Marshal() error = %v", err)
				return
			}

			var got Message
			if err := json.Unmarshal(want, &got); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Errorf("json.Marshal() error = %v", err)
				return
			}
			if string(gotJSON) != string(want) {
				t.Errorf("json round trip = %s, want %s", gotJSON, want)
			}

			if !hasSections(&tt.msg) {
				return
			}
			w := new(WireFormat)
			w.WriteWireFormat(got)
			parsed, err := ParseWireFormat(*w)
			if err != nil {
				t.Errorf("ParseWireFormat() error = %v", err)
				return
			}
			parsedJSON, err := json.Marshal(parsed)
			if err != nil {
				t.Errorf("json.Marshal() error = %v", err)
				return
			}
			if string(parsedJSON) != string(want) {
				t.Errorf("wire format round trip = %s, want %s", parsedJSON, want)
			}
		})
	}
}
