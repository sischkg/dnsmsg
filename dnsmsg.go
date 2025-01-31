package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
)

const UDP_BUFFER_SIZE = 1 << 12
const TCP_BUFFER_SIZE = 1 << 15

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
	TYPE_A   ResourceType = 1
	TYPE_NS  ResourceType = 2
	TYPE_SOA ResourceType = 6
)

func (t ResourceType) String() string {
	switch t {
	case TYPE_A:
		return "A"
	case TYPE_NS:
		return "NS"
	case TYPE_SOA:
		return "SOA"
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
	default:
		return 0, fmt.Errorf(`unknown resource type "%s"`, s)
	}
}

type ResourceClass uint16

const (
	CLASS_IN     ResourceClass = 1
	CLASS_CHAOS  ResourceClass = 3
	CLASS_HESIOD ResourceClass = 4
)

func (c ResourceClass) String() string {
	switch c {
	case CLASS_IN:
		return "IN"
	case CLASS_CHAOS:
		return "CH"
	case CLASS_HESIOD:
		return "HS"
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
	default:
		return 0, fmt.Errorf(`unknown resource class "%s"`, s)
	}
}

type QuestionSectionEntry struct {
	QName Domainname
	Class ResourceClass
	Type  ResourceType
}

func (q QuestionSectionEntry) String() string {
	return fmt.Sprintf("%s %s %s", q.QName.String(), q.Class.String(), q.Class.String())
}

func AppendQuestionSectionEntry(w *WireFormat, q QuestionSectionEntry, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendDomainname(q.QName, db)
	size += w.AppendUInt16(uint16(q.Class))
	size += w.AppendUInt16(uint16(q.Type))
	return size
}

func ParseQuestionSectionEntry(w WireFormat, p uint32) (q QuestionSectionEntry, end uint32, err error) {
	q.QName, p, err = NewDomainnameFromWireFormat(w, p)
	if err != nil {
		err = fmt.Errorf("cannot parse QNAME(%s)", err)
		return
	}

	c, err := w.GetUInt16(p)
	q.Class = ResourceClass(c)
	if err != nil {
		err = fmt.Errorf("cannot parse QCLASS(%s)", err)
		return
	}
	p += 2

	t, err := w.GetUInt16(p)
	q.Type = ResourceType(t)
	if err != nil {
		err = fmt.Errorf("cannot parse QTYPE(%s)", err)
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
	Name  Domainname
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

func AppendResourceRecord(w *WireFormat, rr ResourceRecord, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendDomainname(rr.Name, db)
	size += w.AppendUInt16(uint16(rr.Class))
	size += w.AppendUInt16(uint16(rr.Type))
	size += w.AppendUInt32(rr.TTL)
	size += rr.RData.AppendWireFormat(w, db)
	return size
}

func ParseResourceRecord(w WireFormat, begin uint32) (rr ResourceRecord, end uint32, err error) {
	var p uint32
	rr.Name, p, err = NewDomainnameFromWireFormat(w, p)
	if err != nil {
		err = fmt.Errorf("cannot parse domainname(%s)", err)
		return
	}
	if p+10 > w.Size() {
		err = fmt.Errorf("not enough size for resource record")
		return
	}

	class, _ := w.GetUInt16(p)
	rr.Class = ResourceClass(class)
	p += 2
	rtype, _ := w.GetUInt16(p)
	rr.Type = ResourceType(rtype)
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
	case TYPE_SOA:
		rr.RData, _, err = ParseRecordSOA(w, p)
	default:
		rr.RData, _, err = ParseRecordRaw(w, p, end)
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
	str += fmt.Sprintf("Header: ID: %d, QR: %d, OPCODE: %d, AA: %d, TC: %d, RD: %d, RA: %d, CD: %d, RCODE: %d\n", msg.ID, msg.QR, msg.OPCODE, msg.AA, msg.TC, msg.RA, msg.AD, msg.CD, msg.RCODE)
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

func (msg *Message) SetQuery(qname string, qclass ResourceClass, qtype ResourceType) error {
	var q QuestionSectionEntry
	d, err := NewDomainname(qname)
	if err != nil {
		return fmt.Errorf("invalid QNAME %s: %v", qname, err)
	}
	q.QName = d
	q.Class = qclass
	q.Type = qtype

	msg.QuestionSection = []QuestionSectionEntry{q}
	return nil
}

func (w *WireFormat) WriteWireFormat(msg Message) uint32 {
	var size uint32 = 0
	db := NewNameCompressionDB()
	size += w.AppendUInt16(msg.ID)

	var flags1 uint8 = 0
	flags1 |= 0x01 & msg.QR
	flags1 |= (0x0f & msg.OPCODE) << 1
	flags1 |= (0x01 & msg.AA) << 5
	flags1 |= (0x01 & msg.TC) << 6
	flags1 |= (0x01 & msg.RD) << 7

	var flags2 uint8 = 0
	flags2 |= 0x01 & msg.RA
	flags2 |= (0x01 & msg.Z) << 1
	flags2 |= (0x01 & msg.AD) << 2
	flags2 |= (0x01 & msg.CD) << 3
	flags2 |= (0x0f & msg.RCODE) << 4

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
	flags2, _ := w.GetUInt8(p)
	p += 2

	msg.QR = 0x01 & flags1
	msg.OPCODE = 0x0f & (flags1 >> 1)
	msg.AA = 0x01 & (flags1 >> 5)
	msg.TC = 0x01 & (flags1 >> 6)
	msg.RD = 0x01 & (flags1 >> 7)

	msg.RA = 0x01 & flags2
	msg.Z = 0x01 & (flags2 >> 1)
	msg.AD = 0x01 & (flags2 >> 2)
	msg.CD = 0x01 & (flags2 >> 3)
	msg.RCODE = 0x0f & (flags2 >> 4)

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

	if transport == DNSoverUDP {
		udp, e := net.Dial("udp", fmt.Sprintf("%s:%d", target, port))
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
		tcp, e := net.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
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
