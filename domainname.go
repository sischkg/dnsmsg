package dnsmsg

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	domainnameMaxLabelLength = 63
	// A compression pointer has two leading one bits.  The remaining
	// fourteen bits contain the offset from the beginning of the DNS
	// message.
	domainnameCompressionPointerMask  uint8  = 0xc0
	domainnameCompressionPointerValue uint8  = 0xc0
	domainnameCompressionOffsetMask   uint32 = 0x3fff
	domainnameCompressionMaxOffset    uint32 = domainnameCompressionOffsetMask
)

type Label struct {
	data []byte
}

func NewLabelFromString(s string) (Label, error) {
	if len(s) == 0 || len(s) >= 64 {
		return Label{}, fmt.Errorf("invalid label length for %s(len=%d)", s, len(s))
	}
	return Label{data: []byte(s)}, nil
}

func NewLabel(s []byte) (Label, error) {
	if len(s) == 0 || len(s) >= 64 {
		return Label{}, fmt.Errorf("invalid label length for %s(len=%d)", s, len(s))
	}
	return Label{data: s}, nil
}

func NewRootLabel() Label {
	return Label{data: []byte{}}
}

func (l Label) WireFormat() []byte {
	b := []byte{uint8(len(l.data))}
	for _, c := range l.data {
		b = append(b, c)
	}

	return b
}

func (l Label) WriteWireFormat(w *WireFormat) uint32 {
	return w.AppendBytes(l.WireFormat())
}

func (l Label) Size() uint32 {
	return uint32(len(l.data))
}

func toLower(s byte) byte {
	if 'A' <= s && s <= 'Z' {
		return s - byte('A') + byte('a')
	}
	return s
}

func (lhs Label) Equal(rhs Label) bool {
	if lhs.Size() != rhs.Size() {
		return false
	}
	for i, r := range rhs.data {
		if toLower(lhs.data[i]) != toLower(r) {
			return false
		}
	}
	return true
}

func (l Label) CanonicalLabel() Label {
	var dst []byte
	for _, src := range l.data {
		dst = append(dst, toLower(src))
	}
	n, _ := NewLabel(dst)
	return n
}

func (l Label) String() string {
	var buf bytes.Buffer

	for _, c := range l.data {
		switch {
		case c == '.' || c == '\\':
			buf.WriteByte('\\')
			buf.WriteByte(c)
		case c >= 0x21 && c <= 0x7e:
			buf.WriteByte(c)
		default:
			buf.WriteByte('\\')
			buf.WriteByte('0' + c/100)
			buf.WriteByte('0' + (c/10)%10)
			buf.WriteByte('0' + c%10)
		}
	}

	return buf.String()
}

type DomainName struct {
	labels []Label
}

func NewRootDomainName() DomainName {
	return DomainName{labels: []Label{NewRootLabel()}}
}

func NewDomainNameFromString(name string) (DomainName, error) {
	if name == "" || name == "." {
		return NewRootDomainName(), nil
	}

	d := NewRootDomainName()
	var label []byte
	wireSize := uint32(1) // terminating root label

	for pos := 0; pos < len(name); {
		if name[pos] == '.' {
			if len(label) == 0 {
				return DomainName{}, fmt.Errorf("invalid domainname(empty label)")
			}
			increment := uint32(1 + len(label))
			if wireSize > DOMAINNAME_MAX_LENGTH-increment {
				return DomainName{}, fmt.Errorf("domainname %q is too long", name)
			}
			wireSize += increment
			l, err := NewLabel(label)
			if err != nil {
				return DomainName{}, fmt.Errorf("bad label string %v of %s", label, name)
			}
			d.AppendLabel(l)
			label = []byte{}
			pos++
			continue
		}

		octet, next, err := parsePresentationOctet(name, pos)
		if err != nil {
			return DomainName{}, err
		}
		if len(label) >= domainnameMaxLabelLength {
			return DomainName{}, fmt.Errorf("domainname label is too long(length exceeds %d)", domainnameMaxLabelLength)
		}
		label = append(label, octet)
		pos = next
	}

	// Append the final label here only for names that do not end in
	// a dot; such labels were already flushed at their dot in the loop.
	// AppendLabel maintains the terminating root label.  Each append
	// above already bounds wireSize by DOMAINNAME_MAX_LENGTH.
	if len(label) > 0 {
		increment := uint32(1 + len(label))
		if wireSize > DOMAINNAME_MAX_LENGTH-increment {
			return DomainName{}, fmt.Errorf("domainname %q is too long", name)
		}
		wireSize += increment
		l, e := NewLabel(label)
		if e != nil {
			return DomainName{}, fmt.Errorf("bad label string %v of %s", label, name)
		}
		d.AppendLabel(l)
	}

	return d, nil
}

func NewDomainNameFromLabel(ls []Label) (DomainName, error) {
	return DomainName{labels: ls}, nil
}

// NewDomainNameFromWireFormat reads the domain name that begins at index in
// the wire format.  Unlike the message parser shared by
// NewDomainnameFromWireFormat, name compression is not expanded: a
// compression pointer, a missing root label by the end of the wire format, or
// a label type other than a length-prefixed label all produce an error.
func NewDomainNameFromWireFormat(w *WireFormat, index uint32) (DomainName, error) {
	if w == nil {
		return DomainName{}, fmt.Errorf("wireFormat is nil")
	}

	name, _, err := parseDomainname(*w, index, false)
	if err != nil {
		return DomainName{}, err
	}

	d := NewRootDomainName()
	for _, label := range name {
		l, e := NewLabel(label)
		if e != nil {
			return DomainName{}, e
		}
		d.AppendLabel(l)
	}
	return d, nil
}

func (d DomainName) String() string {
	labels := []string{}
	for _, l := range d.labels {
		labels = append(labels, l.String())
	}
	return strings.Join(labels, ".")
}

func (d *DomainName) AppendLabel(l Label) {
	d.labels[len(d.labels)-1] = l
	d.labels = append(d.labels, NewRootLabel())
}

func (d *DomainName) CanonicalDomainName() DomainName {
	labels := []Label{}
	for _, l := range d.labels {
		labels = append(labels, l.CanonicalLabel())
	}
	canonical, _ := NewDomainNameFromLabel(labels)
	return canonical
}

func (lhs DomainName) Equal(rhs DomainName) bool {
	if len(lhs.labels) != len(rhs.labels) {
		return false
	}
	for i, r := range rhs.labels {
		if !r.Equal(lhs.labels[i]) {
			return false
		}
	}
	return true
}

type Domainname [][]byte

type NameCompressionDB struct {
	nameToPointer map[[DOMAINNAME_MAX_LENGTH]byte]uint16
}

// NewCanonicalDomainnameFromBytes parses an uncompressed domain name from
// the beginning of msg.  The terminating zero octet is consumed, but is not
// represented as an empty label in the returned Domainname.
func NewCanonicalDomainnameFromBytes(msg []byte) (Domainname, error) {
	name, _, err := parseDomainname(msg, 0, false)
	if err != nil {
		return name, err
	}
	return name, nil
}

// NewDomainnameFromWireFormat parses the domain name beginning at begin in a
// DNS message.  Compression pointers are expanded, while the returned offset
// is the offset immediately after the encoded name in msg (not after the
// pointer target).  That distinction is important when parsing fields which
// follow a name.
func NewDomainnameFromWireFormat(msg []byte, begin uint32) (Domainname, uint32, error) {
	return parseDomainname(msg, begin, true)
}

// parseDomainname is shared by the canonical (uncompressed) parser and the
// message parser.  A pointer must point to an earlier location in the
// message.  In addition to enforcing that rule, we remember pointer locations
// so malformed messages cannot make us follow a compression cycle.
func parseDomainname(msg []byte, begin uint32, allowCompression bool) (Domainname, uint32, error) {
	var name Domainname

	messageLength := uint64(len(msg))
	if uint64(begin) >= messageLength {
		return nil, begin, fmt.Errorf("out of bound in parsing domainname")
	}

	pos := begin
	// end is the end of the encoded name in the original path.  It is not
	// changed when following a pointer.
	end := begin
	followingPointer := false
	wireSize := uint32(1) // the terminating root label
	var pointers map[uint32]struct{}

	for {
		if uint64(pos) >= messageLength {
			return nil, begin, fmt.Errorf("invalid domainname(not terminated)")
		}

		count := msg[pos]
		kind := count & domainnameCompressionPointerMask

		switch {
		case count == 0:
			if !followingPointer {
				end = pos + 1
			}
			return name, end, nil

		case kind == domainnameCompressionPointerValue:
			pointerOffset := pos
			if uint64(pos)+1 >= messageLength {
				return nil, pointerOffset, fmt.Errorf("out of bound in parsing domainname(cannot read compression pointer)")
			}
			if !allowCompression {
				return nil, pointerOffset, fmt.Errorf("name compression not supported")
			}

			if pointers == nil {
				pointers = make(map[uint32]struct{})
			}
			if _, seen := pointers[pointerOffset]; seen {
				return nil, end, fmt.Errorf("invalid domainname(compression pointer loop)")
			}
			pointers[pointerOffset] = struct{}{}

			// Clear the two marker bits before combining the two octets.
			offset := ((uint32(msg[pos]) << 8) | uint32(msg[pos+1])) & domainnameCompressionOffsetMask
			if !followingPointer {
				end = pos + 2
			}
			if uint64(offset) >= messageLength {
				return nil, end, fmt.Errorf("out of bound in parsing domainname(compression offset: %d)", offset)
			}
			if offset >= pointerOffset {
				return nil, end, fmt.Errorf("invalid domainname(compression pointer must point backwards, pointer: %d, offset: %d)", pointerOffset, offset)
			}
			if _, seen := pointers[offset]; seen {
				return nil, end, fmt.Errorf("invalid domainname(compression pointer loop)")
			}
			pos = offset
			followingPointer = true

		case kind != 0:
			// 01 and 10 are reserved label types in RFC 1035.
			return nil, pos, fmt.Errorf("invalid domainname(reserved label type: 0x%02x)", count)

		default:
			labelLength := uint32(count)
			labelStart := uint64(pos) + 1
			if labelStart+uint64(labelLength) > messageLength {
				return nil, pos, fmt.Errorf("out of bound in parsing domainname(cannot read label)")
			}

			// The length octet is part of the 255-octet name limit.
			if wireSize > DOMAINNAME_MAX_LENGTH-(1+labelLength) {
				return nil, pos, fmt.Errorf("domainname is too long(length exceeds %d)", DOMAINNAME_MAX_LENGTH)
			}
			wireSize += 1 + labelLength

			label := make([]byte, int(labelLength))
			copy(label, msg[labelStart:labelStart+uint64(labelLength)])
			name = append(name, label)
			pos += 1 + labelLength
			if !followingPointer {
				end = pos
			}
		}
	}
}

// NewDomainname converts a presentation-format domain name to the internal
// label representation.  A trailing dot is retained as an explicit empty
// terminal label for compatibility with the original API, but all wire-format
// and string operations treat that label as the DNS root terminator.
func NewDomainname(name string) (Domainname, error) {
	if name == "" || name == "." {
		return Domainname{}, nil
	}

	var d Domainname
	var label []byte
	wireSize := uint32(1) // terminating root label

	for pos := 0; pos < len(name); {
		if name[pos] == '.' {
			if len(label) == 0 {
				return nil, fmt.Errorf("invalid domainname(empty label)")
			}
			increment := uint32(1 + len(label))
			if wireSize > DOMAINNAME_MAX_LENGTH-increment {
				return nil, fmt.Errorf("domainname %q is too long", name)
			}
			wireSize += increment
			d = append(d, label)
			label = []byte{}
			pos++
			continue
		}

		octet, next, err := parsePresentationOctet(name, pos)
		if err != nil {
			return nil, err
		}
		if len(label) >= domainnameMaxLabelLength {
			return nil, fmt.Errorf("domainname label is too long(length exceeds %d)", domainnameMaxLabelLength)
		}
		label = append(label, octet)
		pos = next
	}

	// Preserve a trailing empty label for the old representation.  It is
	// removed by domainnameLabels before encoding or comparing names.
	if len(label) > 0 {
		increment := uint32(1 + len(label))
		if wireSize > DOMAINNAME_MAX_LENGTH-increment {
			return nil, fmt.Errorf("domainname %q is too long", name)
		}
		wireSize += increment
	}
	d = append(d, label)
	if wireSize > DOMAINNAME_MAX_LENGTH {
		return nil, fmt.Errorf("domainname %q is too long", name)
	}
	return d, nil
}

// parsePresentationOctet parses one presentation-format octet.  RFC 4343
// defines a backslash followed by exactly three decimal digits as an octet
// escape; backslash-dot and backslash-backslash are also used for the two
// characters which otherwise have syntactic meaning.  For compatibility with
// common callers, a backslash before another non-decimal character quotes
// that character.
func parsePresentationOctet(name string, pos int) (byte, int, error) {
	if name[pos] != '\\' {
		return name[pos], pos + 1, nil
	}
	if pos+1 >= len(name) {
		return 0, pos, fmt.Errorf("last character of %s is \\", name)
	}

	next := name[pos+1]
	if next >= '0' && next <= '9' {
		if pos+3 < len(name) &&
			name[pos+1] >= '0' && name[pos+1] <= '9' &&
			name[pos+2] >= '0' && name[pos+2] <= '9' &&
			name[pos+3] >= '0' && name[pos+3] <= '9' {
			value := (uint32(next-'0') * 100) +
				(uint32(name[pos+2]-'0') * 10) +
				uint32(name[pos+3]-'0')
			if value > 255 {
				return 0, pos, fmt.Errorf("invalid escaped octet \\%c%c%c in %s", next, name[pos+2], name[pos+3], name)
			}
			return byte(value), pos + 4, nil
		}
	}

	// Quote dot, backslash, and any other single character.  The input is
	// otherwise treated as a byte-oriented DNS label.
	return next, pos + 2, nil
}

func domainnameWireSize(labels [][]byte) (uint32, bool) {
	size := uint32(1) // terminating zero octet
	for _, label := range labels {
		if len(label) == 0 || len(label) > domainnameMaxLabelLength {
			return 0, false
		}
		increment := uint32(1 + len(label))
		if size > DOMAINNAME_MAX_LENGTH-increment {
			return 0, false
		}
		size += increment
	}
	return size, true
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func (name *Domainname) String() string {
	if name == nil {
		return "."
	}

	if len(*name) == 0 || len(*name) == 1 && len((*name)[0]) == 0 {
		return "."
	}

	var buf bytes.Buffer
	for _, label := range *name {
		if len(label) == 0 {
			break
		}
		for _, c := range label {
			switch {
			case c == '.' || c == '\\':
				buf.WriteByte('\\')
				buf.WriteByte(c)
			case c >= 0x21 && c <= 0x7e:
				buf.WriteByte(c)
			default:
				buf.WriteByte('\\')
				buf.WriteByte('0' + c/100)
				buf.WriteByte('0' + (c/10)%10)
				buf.WriteByte('0' + c%10)
			}
		}
		buf.WriteByte('.')
	}
	return buf.String()
}

// CanonicalWireFormat returns the RFC 4034-style lower-case ASCII wire form,
// including the terminating root label.  Domainnames built by NewDomainname
// are validated before reaching this method; an invalid manually-constructed
// value is represented by nil because this legacy method has no error return.
func (name *Domainname) CanonicalWireFormat() []byte {
	if name == nil {
		return []byte{0}
	}

	size, ok := domainnameWireSize(*name)
	if !ok {
		return nil
	}

	msg := make([]byte, 0, int(size))
	for _, label := range *name {
		msg = append(msg, byte(len(label)))
		for _, c := range label {
			msg = append(msg, asciiLower(c))
		}
	}
	msg = append(msg, 0)
	return msg
}

func (name *Domainname) Size() uint32 {
	if name == nil {
		return 1
	}
	size, ok := domainnameWireSize(*name)
	if !ok {
		return 0
	}
	return size
}

func (name *Domainname) DBKey() [DOMAINNAME_MAX_LENGTH]byte {
	var msg [DOMAINNAME_MAX_LENGTH]byte
	if name == nil {
		return msg
	}

	i := 0
	for _, label := range *name {
		if len(label) == 0 || len(label) > domainnameMaxLabelLength || i+1+len(label) >= len(msg) {
			break
		}
		msg[i] = byte(len(label))
		i++
		for _, c := range label {
			msg[i] = asciiLower(c)
			i++
		}
	}
	msg[i] = 0
	return msg
}

func (name *Domainname) Suffixes() (suffixes []Domainname) {
	if name == nil {
		return nil
	}
	for i := range *name {
		suffixes = append(suffixes, (*name)[i:])
	}
	return
}

func (name *Domainname) IsRoot() bool {
	if name == nil {
		return false
	}
	if len(*name) == 0 || len((*name)[0]) == 0 {
		return true
	}
	return false
}

func (lhs Domainname) Equal(rhs Domainname) bool {
	if len(lhs) != len(rhs) {
		return false
	}
	for i, l := range lhs {
		r := rhs[i]
		if len(l) != len(r) {
			return false
		}
		for j, a := range l {
			b := r[j]
			if a != b {
				return false
			}
		}
	}

	return true
}

func NewNameCompressionDB() *NameCompressionDB {
	db := new(NameCompressionDB)
	db.nameToPointer = make(map[[DOMAINNAME_MAX_LENGTH]byte]uint16)
	return db
}

func (db *NameCompressionDB) Find(name Domainname) (pointer uint16, found bool) {
	if db == nil {
		return 0, false
	}
	key := name.DBKey()
	pointer, found = db.nameToPointer[key]
	return
}

func (db *NameCompressionDB) Add(name Domainname, p uint16) {
	if db == nil {
		return
	}
	if db.nameToPointer == nil {
		db.nameToPointer = make(map[[DOMAINNAME_MAX_LENGTH]byte]uint16)
	}
	db.nameToPointer[name.DBKey()] = p
}

func (db *NameCompressionDB) Reset() {
	if db == nil {
		return
	}
	db.nameToPointer = make(map[[DOMAINNAME_MAX_LENGTH]byte]uint16)
}
