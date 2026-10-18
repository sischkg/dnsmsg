package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
)

const UDP_BUFFER_SIZE = 1 << 12
const TCP_BUFFER_SIZE = 1 << 15

// EDNS0DefaultPayloadSize is the default recommended EDNS(0) UDP payload
// size advertised in the OPT record's TTL field (RFC 6891 Section 6.1.1,
// the recommended value of 1232 bytes).
const EDNS0DefaultPayloadSize uint32 = 1232

const DOMAINNAME_MAX_LENGTH uint32 = 255

const (
	QRQuery uint8 = iota
	QRResponse
)

const (
	QpcodeQuery uint8 = iota
	OpcodeIQuery
	OpcodeStatus
)

const (
	RCodeNoError uint8 = iota
	RCodeFormatError
	RCodeServerFailure
	RCodeNameError
	RCodeNotImplemented
	RCodeRefused
)

const (
	DNSoverUDP = "udp"
	DNSoverTCP = "tcp"
)

type ResourceType uint16

const (
	TYPE_A      ResourceType = 1
	TYPE_NS     ResourceType = 2
	TYPE_SOA    ResourceType = 6
	TYPE_MX     ResourceType = 15
	TYPE_AAAA   ResourceType = 28
	TYPE_DS     ResourceType = 43
	TYPE_OPT    ResourceType = 41
	TYPE_RRSIG  ResourceType = 46
	TYPE_DNSKEY ResourceType = 48
	TYPE_TSIG   ResourceType = 250
	TYPE_NSEC   ResourceType = 32
	TYPE_NSEC3  ResourceType = 50
)

func (t ResourceType) String() string {
	switch t {
	case TYPE_A:
		return "A"
	case TYPE_NS:
		return "NS"
	case TYPE_SOA:
		return "SOA"
	case TYPE_MX:
		return "MX"
	case TYPE_AAAA:
		return "AAAA"
	case TYPE_DS:
		return "DS"
	case TYPE_OPT:
		return "OPT"
	case TYPE_RRSIG:
		return "RRSIG"
	case TYPE_DNSKEY:
		return "DNSKEY"
	case TYPE_TSIG:
		return "TSIG"
	case TYPE_NSEC:
		return "NSEC"
	case TYPE_NSEC3:
		return "NSEC3"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func NewType(s string) (ResourceType, error) {
	pattern := regexp.MustCompile(`TYPE(\d+)`)
	matched := pattern.FindStringSubmatch(s)
	if len(matched) > 0 {
		t, _ := strconv.ParseUint(matched[1], 10, 16)
		return ResourceType(t), nil
	}
	switch s {
	case "A":
		return TYPE_A, nil
	case "NS":
		return TYPE_NS, nil
	case "SOA":
		return TYPE_SOA, nil
	case "MX":
		return TYPE_MX, nil
	case "AAAA":
		return TYPE_AAAA, nil
	case "DS":
		return TYPE_DS, nil
	case "OPT":
		return TYPE_OPT, nil
	case "RRSIG":
		return TYPE_RRSIG, nil
	case "DNSKEY":
		return TYPE_DNSKEY, nil
	case "TSIG":
		return TYPE_TSIG, nil
	case "NSEC":
		return TYPE_NSEC, nil
	case "NSEC3":
		return TYPE_NSEC3, nil
	default:
		return 0, fmt.Errorf(`unknown resource type "%s"`, s)
	}
}

type ResourceClass uint16

const (
	CLASS_IN     ResourceClass = 1
	CLASS_CHAOS  ResourceClass = 3
	CLASS_HESIOD ResourceClass = 4
	CLASS_ANY    ResourceClass = 255
)

func (c ResourceClass) String() string {
	switch c {
	case CLASS_IN:
		return "IN"
	case CLASS_CHAOS:
		return "CH"
	case CLASS_HESIOD:
		return "HS"
	case CLASS_ANY:
		return "ANY"
	default:
		return fmt.Sprintf("CLASS%d", c)
	}
}

func NewClass(s string) (ResourceClass, error) {
	pattern := regexp.MustCompile(`CLASS(\d+)`)
	matched := pattern.FindStringSubmatch(s)
	if len(matched) > 0 {
		t, _ := strconv.ParseUint(matched[1], 10, 16)
		return ResourceClass(t), nil
	}
	switch s {
	case "IN":
		return CLASS_IN, nil
	case "CH":
		return CLASS_CHAOS, nil
	case "HS":
		return CLASS_HESIOD, nil
	case "ANY":
		return CLASS_ANY, nil
	default:
		return 0, fmt.Errorf(`unknown resource class "%s"`, s)
	}
}

type QuestionSectionEntry struct {
	QName DomainName
	Class ResourceClass
	Type  ResourceType
}

func (q QuestionSectionEntry) String() string {
	return fmt.Sprintf("%s %s %s", q.QName.String(), q.Class.String(), q.Type.String())
}

// MarshalJSON encodes the question section entry as a JSON object.  Domain
// names, resource classes, and resource types are encoded as their
// presentation-format strings.
func (q QuestionSectionEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"QName": q.QName,
		"Class": q.Class.String(),
		"Type":  q.Type.String(),
	})
}

// UnmarshalJSON decodes a question section entry from the JSON object
// MarshalJSON produces.  The class and type also accept their numeric codes.
func (q *QuestionSectionEntry) UnmarshalJSON(data []byte) error {
	var fields struct {
		QName DomainName      `json:"QName"`
		Class json.RawMessage `json:"Class"`
		Type  json.RawMessage `json:"Type"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse question section entry: %w", err)
	}
	class, err := decodeResourceClass(fields.Class)
	if err != nil {
		return err
	}
	rtyp, err := decodeResourceType(fields.Type)
	if err != nil {
		return err
	}
	q.QName = fields.QName
	q.Class = class
	q.Type = rtyp
	return nil
}

// decodeResourceClass decodes a resource class from its name string ("IN",
// "CLASS42") or its numeric code.
func decodeResourceClass(data json.RawMessage) (ResourceClass, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("missing resource class")
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return NewClass(s)
	}
	var n uint16
	if err := json.Unmarshal(data, &n); err != nil {
		return 0, fmt.Errorf("invalid resource class %s", data)
	}
	return ResourceClass(n), nil
}

// decodeResourceType decodes a resource type from its name string ("A",
// "TYPE100") or its numeric code.
func decodeResourceType(data json.RawMessage) (ResourceType, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("missing resource type")
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return NewType(s)
	}
	var n uint16
	if err := json.Unmarshal(data, &n); err != nil {
		return 0, fmt.Errorf("invalid resource type %s", data)
	}
	return ResourceType(n), nil
}

func AppendQuestionSectionEntry(w *WireFormat, q QuestionSectionEntry, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendDomainName(q.QName, db)
	size += w.AppendUInt16(uint16(q.Type))
	size += w.AppendUInt16(uint16(q.Class))
	return size
}

func ParseQuestionSectionEntry(w WireFormat, begin uint32) (q QuestionSectionEntry, end uint32, err error) {
	var p uint32
	q.QName, p, err = NewDomainNameFromCompressedWireFormat(&w, begin)
	if err != nil {
		err = fmt.Errorf("cannot parse QNAME(%s)", err)
		return
	}

	t, err := w.GetUInt16(p)
	q.Type = ResourceType(t)
	if err != nil {
		err = fmt.Errorf("cannot parse QTYPE(%s)", err)
		return
	}
	p += 2

	c, err := w.GetUInt16(p)
	q.Class = ResourceClass(c)
	if err != nil {
		err = fmt.Errorf("cannot parse QCLASS(%s)", err)
		return
	}
	p += 2

	end = p
	return
}

type RDATA interface {
	Type() ResourceType
	String() string
	CanonicalWireFormat() []byte
	AppendWireFormat(*WireFormat, *NameCompressionDB) uint32
	AppendCanonicalWireFormat(*WireFormat) uint32
}

type ResourceRecord struct {
	Name  DomainName
	Class ResourceClass
	Type  ResourceType
	TTL   uint32
	RData RDATA
}

func (rr ResourceRecord) String() string {
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "%s %d %d %d %s", rr.Name.String(), rr.Class, rr.Type, rr.TTL, rr.RData.String())
	return w.String()
}

// MarshalJSON encodes the resource record as a JSON object.  The record
// name is encoded as its presentation-format string, the resource class
// and type as their names, and the RDATA via the concrete record type's
// own MarshalJSON.
func (rr ResourceRecord) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"Name":  rr.Name,
		"Class": rr.Class.String(),
		"Type":  rr.Type.String(),
		"TTL":   rr.TTL,
		"RData": rr.RData,
	})
}

// UnmarshalJSON decodes a resource record from the JSON object MarshalJSON
// produces.  The RDATA is decoded into the concrete record type selected by
// the record type; types the library does not interpret are decoded as
// RecordRaw.  The class and type also accept their numeric codes.
func (rr *ResourceRecord) UnmarshalJSON(data []byte) error {
	var fields struct {
		Name  DomainName      `json:"Name"`
		Class json.RawMessage `json:"Class"`
		Type  json.RawMessage `json:"Type"`
		TTL   uint32          `json:"TTL"`
		RData json.RawMessage `json:"RData"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse resource record: %w", err)
	}
	class, err := decodeResourceClass(fields.Class)
	if err != nil {
		return err
	}
	rtyp, err := decodeResourceType(fields.Type)
	if err != nil {
		return err
	}
	rr.Name = fields.Name
	rr.Class = class
	rr.Type = rtyp
	rr.TTL = fields.TTL
	return rr.unmarshalRData(fields.RData)
}

// unmarshalRData decodes the RDATA of a record whose Type is already set,
// mirroring the dispatch of ParseResourceRecord.  A null or absent RDATA
// leaves RData nil.
func (rr *ResourceRecord) unmarshalRData(data json.RawMessage) error {
	if len(data) == 0 || string(data) == "null" {
		rr.RData = nil
		return nil
	}

	var rdata RDATA
	switch rr.Type {
	case TYPE_A:
		rdata = new(RecordA)
	case TYPE_NS:
		rdata = new(RecordNS)
	case TYPE_MX:
		rdata = new(RecordMX)
	case TYPE_SOA:
		rdata = new(RecordSOA)
	case TYPE_AAAA:
		rdata = new(RecordAAAA)
	case TYPE_DS:
		rdata = new(RecordDS)
	case TYPE_OPT:
		rdata = new(RecordOPT)
	case TYPE_RRSIG:
		rdata = new(RecordRRSIG)
	case TYPE_DNSKEY:
		rdata = new(RecordDNSKEY)
	case TYPE_NSEC:
		rdata = new(RecordNSEC)
	case TYPE_NSEC3:
		rdata = new(RecordNSEC3)
	default:
		raw := new(RecordRaw)
		if err := json.Unmarshal(data, raw); err != nil {
			return fmt.Errorf("cannot parse %s RDATA: %w", rr.Type.String(), err)
		}
		// The record's own type is authoritative over the copy embedded in
		// the raw RDATA.
		raw.rtype = rr.Type
		rr.RData = raw
		return nil
	}

	if err := json.Unmarshal(data, rdata); err != nil {
		return fmt.Errorf("cannot parse %s RDATA: %w", rr.Type.String(), err)
	}
	rr.RData = rdata
	return nil
}

func AppendResourceRecord(w *WireFormat, rr ResourceRecord, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendDomainName(rr.Name, db)
	size += w.AppendUInt16(uint16(rr.Type))
	size += w.AppendUInt16(uint16(rr.Class))
	size += w.AppendUInt32(rr.TTL)
	posRDLen := w.Size()
	size += w.AppendUInt16(0) // dummy data
	rdlen := rr.RData.AppendWireFormat(w, db)
	w.PutUint16(posRDLen, uint16(rdlen))
	size += rdlen
	return size
}

func ParseResourceRecord(w WireFormat, begin uint32) (rr ResourceRecord, end uint32, err error) {
	var p uint32
	rr.Name, p, err = NewDomainNameFromCompressedWireFormat(&w, begin)
	if err != nil {
		err = fmt.Errorf("cannot parse domainname(%s)", err)
		return
	}
	if p+10 > w.Size() {
		err = fmt.Errorf("not enough size for resource record")
		return
	}

	rtype, _ := w.GetUInt16(p)
	rr.Type = ResourceType(rtype)
	p += 2
	class, _ := w.GetUInt16(p)
	rr.Class = ResourceClass(class)
	p += 2
	rr.TTL, _ = w.GetUInt32(p)
	p += 4
	size, _ := w.GetUInt16(p)
	p += 2
	end = p + uint32(size)

	switch rr.Type {
	case TYPE_A:
		rr.RData, _, err = ParseRecordA(w, p)
	case TYPE_NS:
		rr.RData, _, err = ParseRecordNS(w, p)
	case TYPE_MX:
		rr.RData, _, err = ParseRecordMX(w, p)
	case TYPE_SOA:
		rr.RData, _, err = ParseRecordSOA(w, p)
	case TYPE_AAAA:
		rr.RData, _, err = ParseRecordAAAA(w, p)
	case TYPE_DS:
		rr.RData, _, err = ParseRecordDS(w, p, end)
	case TYPE_OPT:
		rr.RData, _, err = ParseRecordOPT(w, p, end)
	case TYPE_RRSIG:
		rr.RData, _, err = ParseRecordRRSIG(w, p, end)
	case TYPE_DNSKEY:
		rr.RData, _, err = ParseRecordDNSKEY(w, p, end)
	case TYPE_TSIG:
		rr.RData, _, err = ParseRecordTSIG(w, p, end)
	case TYPE_NSEC:
		rr.RData, _, err = ParseRecordNSEC(w, p, end)
	case TYPE_NSEC3:
		rr.RData, _, err = ParseRecordNSEC3(w, p, end)
	default:
		rr.RData, _, err = ParseRecordRaw(w, p, end, rr.Type)
	}

	return
}

type Message struct {
	ID     uint16
	QR     uint8
	OPCODE uint8
	AA     uint8
	TC     uint8
	RD     uint8
	RA     uint8
	Z      uint8
	AD     uint8
	CD     uint8
	RCODE  uint8

	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16

	QuestionSection   []QuestionSectionEntry
	AnswerSection     []ResourceRecord
	AuthoritySection  []ResourceRecord
	AdditionalSection []ResourceRecord
}

func (msg Message) String() string {
	var str string
	str += fmt.Sprintf("Header: ID: %d, QR: %d, OPCODE: %d, AA: %d, TC: %d, RD: %d, RA: %d, AD: %d, CD: %d, RCODE: %d\n", msg.ID, msg.QR, msg.OPCODE, msg.AA, msg.TC, msg.RD, msg.RA, msg.AD, msg.CD, msg.RCODE)
	str += fmt.Sprintf("QDCOUNT: %d\n", msg.QDCOUNT)
	str += fmt.Sprintf("ANCOUNT: %d\n", msg.ANCOUNT)
	str += fmt.Sprintf("NSCOUNT: %d\n", msg.NSCOUNT)
	str += fmt.Sprintf("ARCOUNT: %d\n", msg.ARCOUNT)

	for _, q := range msg.QuestionSection {
		str += fmt.Sprintf("%s\n", q.String())
	}
	for _, a := range msg.AnswerSection {
		str += fmt.Sprintf("%s\n", a.String())
	}
	for _, n := range msg.AuthoritySection {
		str += fmt.Sprintf("%s\n", n.String())
	}
	for _, a := range msg.AdditionalSection {
		str += fmt.Sprintf("%s\n", a.String())
	}
	return str
}

// MarshalJSON encodes the message as a JSON object: the header fields and
// all four sections.  The count fields are exported as stored, not derived
// from the section lengths.  A section that is not present (a nil slice) is
// exported as null.
func (msg Message) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"ID":     msg.ID,
		"QR":     msg.QR,
		"OPCODE": msg.OPCODE,
		"AA":     msg.AA,
		"TC":     msg.TC,
		"RD":     msg.RD,
		"RA":     msg.RA,
		"Z":      msg.Z,
		"AD":     msg.AD,
		"CD":     msg.CD,
		"RCODE":  msg.RCODE,

		"QDCOUNT": msg.QDCOUNT,
		"ANCOUNT": msg.ANCOUNT,
		"NSCOUNT": msg.NSCOUNT,
		"ARCOUNT": msg.ARCOUNT,

		"QuestionSection":   msg.QuestionSection,
		"AnswerSection":     msg.AnswerSection,
		"AuthoritySection":  msg.AuthoritySection,
		"AdditionalSection": msg.AdditionalSection,
	})
}

// UnmarshalJSON decodes a message from the JSON object MarshalJSON produces:
// the header fields and all four sections.  The count fields are taken from
// the JSON as given, and a section that is null in the JSON is decoded as a
// nil slice.
func (msg *Message) UnmarshalJSON(data []byte) error {
	var fields struct {
		ID     uint16 `json:"ID"`
		QR     uint8  `json:"QR"`
		OPCODE uint8  `json:"OPCODE"`
		AA     uint8  `json:"AA"`
		TC     uint8  `json:"TC"`
		RD     uint8  `json:"RD"`
		RA     uint8  `json:"RA"`
		Z      uint8  `json:"Z"`
		AD     uint8  `json:"AD"`
		CD     uint8  `json:"CD"`
		RCODE  uint8  `json:"RCODE"`

		QDCOUNT uint16 `json:"QDCOUNT"`
		ANCOUNT uint16 `json:"ANCOUNT"`
		NSCOUNT uint16 `json:"NSCOUNT"`
		ARCOUNT uint16 `json:"ARCOUNT"`

		QuestionSection   []QuestionSectionEntry `json:"QuestionSection"`
		AnswerSection     []ResourceRecord       `json:"AnswerSection"`
		AuthoritySection  []ResourceRecord       `json:"AuthoritySection"`
		AdditionalSection []ResourceRecord       `json:"AdditionalSection"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse message: %w", err)
	}
	*msg = Message{
		ID:     fields.ID,
		QR:     fields.QR,
		OPCODE: fields.OPCODE,
		AA:     fields.AA,
		TC:     fields.TC,
		RD:     fields.RD,
		RA:     fields.RA,
		Z:      fields.Z,
		AD:     fields.AD,
		CD:     fields.CD,
		RCODE:  fields.RCODE,

		QDCOUNT: fields.QDCOUNT,
		ANCOUNT: fields.ANCOUNT,
		NSCOUNT: fields.NSCOUNT,
		ARCOUNT: fields.ARCOUNT,

		QuestionSection:   fields.QuestionSection,
		AnswerSection:     fields.AnswerSection,
		AuthoritySection:  fields.AuthoritySection,
		AdditionalSection: fields.AdditionalSection,
	}
	return nil
}

func (msg *Message) SetQuery(qname string, qclass ResourceClass, qtype ResourceType) error {
	var q QuestionSectionEntry
	d, err := NewDomainNameFromString(qname)
	if err != nil {
		return fmt.Errorf("invalid QNAME %s: %v", qname, err)
	}
	q.QName = d
	q.Class = qclass
	q.Type = qtype

	msg.QuestionSection = []QuestionSectionEntry{q}
	msg.QDCOUNT = 1
	return nil
}

// SetEDNS0 arms an EDNS(0) OPT pseudo-record (RFC 6891) in the additional
// section of msg.  The record's TTL advertises the UDP payload size that
// msg can receive, FLAGS carries the EDNS(0) flags (such as EDNS0FlagDO)
// and options are the requested EDNS(0) options (for example an NSID
// option from NewEDNSOptionNSID).  Any OPT record already present in the
// additional section is replaced, so calling SetEDNS0 repeatedly is
// idempotent with respect to the ARCOUNT.
func (msg *Message) SetEDNS0(payloadSize uint32, flags uint16, options ...EDNSOption) {
	opt := ResourceRecord{
		Name:  NewRootDomainName(),
		Class: CLASS_IN,
		Type:  TYPE_OPT,
		TTL:   payloadSize,
		RData: NewRecordOPT(EDNS0Version, flags, options...),
	}

	hadOPT := false
	kept := make([]ResourceRecord, 0, len(msg.AdditionalSection))
	for _, rr := range msg.AdditionalSection {
		if rr.Type == TYPE_OPT {
			hadOPT = true
			continue
		}
		kept = append(kept, rr)
	}
	msg.AdditionalSection = append(kept, opt)
	if !hadOPT {
		msg.ARCOUNT++
	}
}

func (w *WireFormat) WriteWireFormat(msg Message) uint32 {
	var size uint32 = 0
	db := NewNameCompressionDB()
	size += w.AppendUInt16(msg.ID)

	var flags1 uint8 = 0
	flags1 |= (0x01 & msg.QR) << 7
	flags1 |= (0x0f & msg.OPCODE) << 3
	flags1 |= (0x01 & msg.AA) << 2
	flags1 |= (0x01 & msg.TC) << 1
	flags1 |= (0x01 & msg.RD)

	var flags2 uint8 = 0
	flags2 |= (0x01 & msg.RA) << 7
	flags2 |= (0x01 & msg.Z) << 6
	flags2 |= (0x01 & msg.AD) << 5
	flags2 |= (0x01 & msg.CD) << 4
	flags2 |= (0x0f & msg.RCODE)

	size += w.AppendUInt8(flags1)
	size += w.AppendUInt8(flags2)

	size += w.AppendUInt16(msg.QDCOUNT)
	size += w.AppendUInt16(msg.ANCOUNT)
	size += w.AppendUInt16(msg.NSCOUNT)
	size += w.AppendUInt16(msg.ARCOUNT)

	for _, e := range msg.QuestionSection {
		size += AppendQuestionSectionEntry(w, e, db)
	}
	for _, a := range msg.AnswerSection {
		size += AppendResourceRecord(w, a, db)
	}
	for _, a := range msg.AuthoritySection {
		size += AppendResourceRecord(w, a, db)
	}
	for _, a := range msg.AdditionalSection {
		size += AppendResourceRecord(w, a, db)
	}

	return size
}

const DNS_HEADER_SIZE uint32 = 12

func ParseHeader(w WireFormat, msg *Message) (uint32, error) {
	if w.Size() <= DNS_HEADER_SIZE {
		return w.Size(), fmt.Errorf("too few message size %d( <= DNS Header Size %d )", w.Size(), DNS_HEADER_SIZE)
	}

	var p uint32 = 0
	msg.ID, _ = w.GetUInt16(p)
	p += 2
	flags1, _ := w.GetUInt8(p)
	p += 1
	flags2, _ := w.GetUInt8(p)
	p += 1

	msg.QR = 0x01 & (flags1 >> 7)
	msg.OPCODE = 0x0f & (flags1 >> 3)
	msg.AA = 0x01 & (flags1 >> 2)
	msg.TC = 0x01 & (flags1 >> 1)
	msg.RD = 0x01 & (flags1 >> 0)

	msg.RA = 0x01 & (flags2 >> 7)
	msg.Z = 0x01 & (flags2 >> 6)
	msg.AD = 0x01 & (flags2 >> 5)
	msg.CD = 0x01 & (flags2 >> 4)
	msg.RCODE = 0x0f & (flags2 >> 0)

	msg.QDCOUNT, _ = w.GetUInt16(p)
	p += 2
	msg.ANCOUNT, _ = w.GetUInt16(p)
	p += 2
	msg.NSCOUNT, _ = w.GetUInt16(p)
	p += 2
	msg.ARCOUNT, _ = w.GetUInt16(p)
	p += 2

	return p, nil
}

func ParseWireFormat(w WireFormat) (msg Message, err error) {
	p, err := ParseHeader(w, &msg)
	if err != nil {
		return
	}

	for i := uint32(0); i < uint32(msg.QDCOUNT); i++ {
		var q QuestionSectionEntry
		q, p, err = ParseQuestionSectionEntry(w, p)
		if err != nil {
			return
		}
		msg.QuestionSection = append(msg.QuestionSection, q)
	}

	for i := uint32(0); i < uint32(msg.ANCOUNT); i++ {
		var rr ResourceRecord
		rr, p, err = ParseResourceRecord(w, p)
		if err != nil {
			return
		}
		msg.AnswerSection = append(msg.AnswerSection, rr)
	}

	for i := uint32(0); i < uint32(msg.NSCOUNT); i++ {
		var rr ResourceRecord
		rr, p, err = ParseResourceRecord(w, p)
		if err != nil {
			return
		}
		msg.AuthoritySection = append(msg.AuthoritySection, rr)
	}

	for i := uint32(0); i < uint32(msg.ARCOUNT); i++ {
		var rr ResourceRecord
		rr, p, err = ParseResourceRecord(w, p)
		if err != nil {
			return
		}
		msg.AdditionalSection = append(msg.AdditionalSection, rr)
	}

	return
}

func SendQuery(query Message, target string, port uint16, transport string) (reply Message, err error) {
	var q, r WireFormat
	q.WriteWireFormat(query)

	endpoint := net.JoinHostPort(target, strconv.Itoa(int(port)))
	if transport == DNSoverUDP {
		udp, e := net.Dial("udp", endpoint)
		if e != nil {
			err = fmt.Errorf("cannot send message to %s:%d(%s)", target, port, e)
			return
		}
		_, e = udp.Write([]byte(q))
		if e != nil {
			err = fmt.Errorf("cannot send message to %s:%d(%s)", target, port, e)
			return
		}
		buf := make([]byte, UDP_BUFFER_SIZE)
		_, e = udp.Read(buf)
		if e != nil {
			err = fmt.Errorf("cannot receive message from %s:%d(%s)", target, port, e)
			return
		}
		r = WireFormat(buf)
	} else if transport == DNSoverTCP {
		tcp, e := net.Dial("tcp", endpoint)
		if e != nil {
			err = fmt.Errorf("cannot send message to %s:%d(%s)", target, port, e)
			return
		}

		var sendSize []byte
		sendSize = binary.BigEndian.AppendUint16(sendSize, uint16(q.Size()))
		_, e = tcp.Write(sendSize)
		if e != nil {
			err = fmt.Errorf("cannot send payload size to %s:%d(%s)", target, port, e)
			return
		}
		_, e = tcp.Write([]byte(q))
		if e != nil {
			err = fmt.Errorf("cannot send message to %s:%d(%s)", target, port, e)
			return
		}

		recvSizeBuf := make([]byte, 2)
		_, e = tcp.Read(recvSizeBuf)
		if e != nil {
			err = fmt.Errorf("cannot receive payload size from %s:%d(%s)", target, port, e)
			return
		}
		var recvSize uint16
		binary.Decode(recvSizeBuf, binary.NativeEndian, recvSize)

		buf := make([]byte, recvSize)
		_, e = tcp.Read(buf)
		if e != nil {
			err = fmt.Errorf("cannot receive message from %s:%d(%s)", target, port, e)
			return
		}
		r = WireFormat(buf)
	} else {
		err = fmt.Errorf("unknown transport %s", transport)
		return
	}

	reply, err = ParseWireFormat(r)
	return
}
