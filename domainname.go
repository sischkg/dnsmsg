package dnsmsg

import (
	"bytes"
	"encoding/json"
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

// Label is a single label of a DNS domain name: 1 to 63 octets (RFC 1035
// Section 3.1). A label is an opaque byte string: it is preserved as stored,
// compared case-insensitively with respect to ASCII letters (RFC 4343
// Section 2), and available in canonical lowercase form via
// CanonicalLabel (RFC 4034 Section 6.2). The only zero-length label
// permitted is the root label, which terminates a DomainName.
type Label struct {
	data []byte
}

// NewLabelFromString constructs a Label from the octets of s.
// s is used verbatim as the label's data. s must be 1-63 octets long.
func NewLabelFromString(s string) (Label, error) {
	if len(s) == 0 || len(s) >= 64 {
		return Label{}, fmt.Errorf("invalid label length for %s(len=%d)", s, len(s))
	}
	return Label{data: []byte(s)}, nil
}

// NewLabel constructs a Label from the byte slice s.
// s must be 1-63 octets long.
func NewLabel(s []byte) (Label, error) {
	if len(s) == 0 || len(s) >= 64 {
		return Label{}, fmt.Errorf("invalid label length for %s(len=%d)", s, len(s))
	}
	return Label{data: s}, nil
}

// NewRootLabel returns the root label (a zero-length label), which is used
// as the last label of a DomainName.
func NewRootLabel() Label {
	return Label{data: []byte{}}
}

// WireFormat returns the wire-format encoding of l: a length octet
// followed by the label's octets. For the root label, the result is a
// single zero octet.
func (l Label) WireFormat() []byte {
	b := []byte{uint8(len(l.data))}
	for _, c := range l.data {
		b = append(b, c)
	}

	return b
}

// WriteWireFormat appends the wire-format encoding of l to w and returns
// the number of octets written (0 if w is nil).
func (l Label) WriteWireFormat(w *WireFormat) uint32 {
	return w.AppendBytes(l.WireFormat())
}

// Size returns the length of the label in octets, excluding the length
// octet. The size of the root label is 0.
func (l Label) Size() uint32 {
	return uint32(len(l.data))
}

// toLower maps an ASCII uppercase letter to its lowercase counterpart
// and returns any other byte unchanged.
func toLower(s byte) byte {
	if 'A' <= s && s <= 'Z' {
		return s - byte('A') + byte('a')
	}
	return s
}

// Equal reports whether lhs and rhs are the same label.
// Comparison is case insensitive with respect to ASCII letters,
// as in RFC 4343 Section 2.
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

// CanonicalLabel returns a copy of l with ASCII uppercase letters mapped
// to lowercase, in the canonical form of RFC 4034 Section 6.2.
func (l Label) CanonicalLabel() Label {
	var dst []byte
	for _, src := range l.data {
		dst = append(dst, toLower(src))
	}
	n, _ := NewLabel(dst)
	return n
}

// String returns the presentation form of the label, as in RFC 1035
// Section 5: printable octets (other than '.' and '\') are printed as-is,
// while '.' and '\' are backslash-escaped and non-printable octets are
// printed as three-digit decimal escapes such as "\065".
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

// DomainName is a DNS domain name: an ordered sequence of Labels from the
// most specific to the least specific, terminated by the root label. The
// total length of the name in wire format (RFC 1035 Section 4.1.4) must not
// exceed 255 octets. The empty name (root domain) consists of the root
// label alone.
type DomainName struct {
	labels []Label
}

// NewRootDomainName returns the root domain, whose only label is the root
// label.
func NewRootDomainName() DomainName {
	return DomainName{labels: []Label{NewRootLabel()}}
}

// NewDomainNameFromString parses a domain name in presentation form
// (RFC 1035 Section 5): labels separated by '.', in which '.' and '\' may be
// backslash-escaped and a backslash followed by three digits denotes the
// corresponding octet. The empty string and "." both denote the root domain.
// An empty label, a label of 64 or more octets, or a name whose wire-format
// length exceeds 255 octets is an error.
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

// NewDomainNameFromLabel constructs a DomainName from a slice of Labels
// given from the most specific to the least specific, terminated by the root
// label. The labels are not otherwise validated; the caller is responsible
// for providing a valid sequence of labels.
func NewDomainNameFromLabel(ls []Label) (DomainName, error) {
	return DomainName{labels: ls}, nil
}

// NewDomainNameFromWireFormat reads the domain name that begins at index in
// the wire format.  Name compression is not expanded: a compression pointer,
// a missing root label by the end of the wire format, or a label type other
// than a length-prefixed label all produce an error.
func NewDomainNameFromWireFormat(w *WireFormat, index uint32) (DomainName, error) {
	if w == nil {
		return DomainName{}, fmt.Errorf("wireFormat is nil")
	}

	labels, _, err := parseDomainnameLabels(*w, index, false)
	if err != nil {
		return DomainName{}, err
	}
	return newDomainNameFromLabels(labels)
}

// NewDomainNameFromCompressedWireFormat reads the domain name that begins at
// index in the wire format, expanding name compression (RFC 1035 Section
// 4.1.4).  The returned end is the offset immediately after the encoded
// name, not after the pointer target; that distinction is important when
// parsing fields which follow the name.
func NewDomainNameFromCompressedWireFormat(w *WireFormat, index uint32) (DomainName, uint32, error) {
	if w == nil {
		return DomainName{}, 0, fmt.Errorf("wireFormat is nil")
	}

	labels, end, err := parseDomainnameLabels(*w, index, true)
	if err != nil {
		return DomainName{}, end, err
	}

	d, e := newDomainNameFromLabels(labels)
	if e != nil {
		return DomainName{}, end, e
	}
	return d, end, nil
}

// newDomainNameFromLabels builds a DomainName from the wire labels, most
// specific first, appended to the root-terminated name.
func newDomainNameFromLabels(labels [][]byte) (DomainName, error) {
	d := NewRootDomainName()
	for _, label := range labels {
		l, e := NewLabel(label)
		if e != nil {
			return DomainName{}, e
		}
		d.AppendLabel(l)
	}
	return d, nil
}

// String returns the presentation form of the domain name: the labels
// joined by '.', with the trailing root label printing as the final '.'
// (so the root domain prints as "." and the singleton "com" as "com.").
func (d DomainName) String() string {
	if d.IsRoot() {
		return "."
	}
	labels := []string{}
	for _, l := range d.labels {
		labels = append(labels, l.String())
	}
	return strings.Join(labels, ".")
}

// MarshalJSON encodes the domain name as its presentation-format string.
func (d DomainName) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// AppendLabel adds a label to the domain name. The receiver must be
// terminated by the root label. The new label is inserted just before the
// root label, replacing it, and a fresh root label is appended after it, so
// that the result remains root-terminated. Labels therefore accumulate from
// most specific to least specific: appending "www", then "example", then
// "com" to the root domain yields "www.example.com.".
func (d *DomainName) AppendLabel(l Label) {
	d.labels[len(d.labels)-1] = l
	d.labels = append(d.labels, NewRootLabel())
}

// CanonicalDomainName returns a copy of the domain name with each label in
// canonical (lowercase) form, in the sense of RFC 4034 Section 6.2,
// suitable for canonical wire-format encoding.
func (d *DomainName) CanonicalDomainName() DomainName {
	labels := []Label{}
	for _, l := range d.labels {
		labels = append(labels, l.CanonicalLabel())
	}
	canonical, _ := NewDomainNameFromLabel(labels)
	return canonical
}

// CanonicalWireFormat returns the canonical wire-format encoding (RFC 4034
// Section 6.2) of the domain name: labels are written most specific first,
// each as a length octet followed by its characters in canonical (lower-case)
// form, and the name is terminated by a single zero octet. No compression
// pointers are used.
func (d DomainName) CanonicalWireFormat() []byte {
	size := uint32(1) // terminating zero octet
	for _, label := range d.labels {
		if s := label.Size(); s > 0 {
			size += 1 + s
		}
	}

	msg := make([]byte, 0, size)
	for _, label := range d.labels {
		s := label.Size()
		if s == 0 {
			// The root label terminates the name.
			continue
		}
		msg = append(msg, byte(s))
		for _, c := range label.data {
			msg = append(msg, asciiLower(c))
		}
	}
	return append(msg, 0)
}

// Equal reports whether lhs and rhs are the same domain name: they have the
// same number of labels and each pair of corresponding labels is Equal
// (hence case insensitive).
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

// ParentDomainNames returns d itself followed by each of its parent
// domains, most specific first: "www.example.com." yields
// ["www.example.com.", "example.com.", "com."].
// The root domain is never included in the result; for the root domain
// itself, which has no non-root labels, the result is empty.  The names
// are returned in canonical lower-case form (RFC 4034 Section 6.2).
func (d DomainName) ParentDomainNames() []DomainName {
	if len(d.labels) == 0 {
		return []DomainName{}
	}

	var parents []DomainName
	for i := 0; i < len(d.labels)-1; i++ {
		parent, _ := NewDomainNameFromLabel(d.labels[i:])
		parents = append(parents, parent.CanonicalDomainName())
	}

	return parents
}

// DBKey returns a fixed-size key that identifies d in the map maintained by
// NameCompressionDB.  The key is the wire-format encoding of the name
// (RFC 1035 Section 4.1.4) with ASCII letters in canonical lower-case form
// (RFC 4034 Section 6.2), so that names compare equal regardless of case,
// as in RFC 4343 Section 2.  Names whose encoding does not fit in
// DOMAINNAME_MAX_LENGTH octets yield the truncated encoding.
func (d DomainName) DBKey() [DOMAINNAME_MAX_LENGTH]byte {
	var msg [DOMAINNAME_MAX_LENGTH]byte

	i := 0
	for _, label := range d.labels {
		if len(label.data) == 0 || len(label.data) > domainnameMaxLabelLength || i+1+len(label.data) >= len(msg) {
			break
		}
		msg[i] = byte(len(label.data))
		i++
		for _, c := range label.data {
			msg[i] = asciiLower(c)
			i++
		}
	}
	msg[i] = 0
	return msg
}

// Size returns the number of bytes the domain name occupies in the canonical
// wire format, including the terminating root label: one length octet plus
// each character for every non-root label, and one octet for the root label
// itself.
func (d DomainName) Size() uint32 {
	size := uint32(1) // terminating root label
	for _, label := range d.labels {
		if s := label.Size(); s > 0 {
			size += 1 + s
		}
	}
	return size
}

// IsRoot reports whether d is the root domain, i.e. it has no non-root
// labels. The zero-value DomainName (no labels) represents the root domain.
func (d DomainName) IsRoot() bool {
	for _, label := range d.labels {
		if label.Size() > 0 {
			return false
		}
	}
	return true
}

type NameCompressionDB struct {
	nameToPointer map[[DOMAINNAME_MAX_LENGTH]byte]uint16
}

// parseDomainnameLabels is shared by the canonical (uncompressed) parser and
// the message parser, and returns the raw wire labels of the name.  A pointer
// must point to an earlier location in the message.  In addition to enforcing
// that rule, we remember pointer locations so malformed messages cannot make
// us follow a compression cycle.
func parseDomainnameLabels(msg []byte, begin uint32, allowCompression bool) ([][]byte, uint32, error) {
	var name [][]byte

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

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func NewNameCompressionDB() *NameCompressionDB {
	db := new(NameCompressionDB)
	db.nameToPointer = make(map[[DOMAINNAME_MAX_LENGTH]byte]uint16)
	return db
}

// FindDomainName reports whether the name has already been written to the
// message and returns the offset at which it begins.  Lookups are case
// insensitive, as in RFC 4343 Section 2.
func (db *NameCompressionDB) FindDomainName(name DomainName) (pointer uint16, found bool) {
	if db == nil {
		return 0, false
	}
	pointer, found = db.nameToPointer[name.DBKey()]
	return
}

// AddDomainName records the offset at which the name has been written to the
// message, so that later occurrences of the same name can be written as a
// compression pointer.
func (db *NameCompressionDB) AddDomainName(name DomainName, p uint16) {
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
