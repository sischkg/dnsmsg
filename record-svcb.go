package dnsmsg

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// RecordSVCB represents a SVCB record (RFC 9460 Section 2).
//
// The SvcParams of the wire format are stored as an ordered list: the params
// in SvcParams are in strictly increasing SvcParamKey order, which is the
// order the wire format requires (RFC 9460 Section 2.2).  NewRecordSVCB and
// NewRecordSVCBFromString sort the params they are given, so a caller may add
// them in any order.
//
// An HTTPS record (TYPE_HTTPS) has exactly the same RDATA layout and is
// represented by RecordHTTPS, which embeds this type and shares its methods.
type RecordSVCB struct {
	SvcPriority uint16
	TargetName  DomainName
	SvcParams   []SvcParam
}

// SvcParam is one SvcParamKey=SvcParamValue pair of a SVCB or HTTPS record.
//
// The value is the decoded value of RFC 9460 Section 2.1: the character-string
// decoding of Appendix A has already been applied, so KeyAlpn holds the octets
// of the ALPN IDs and their length octets, and KeyPort holds the decimal
// digits of the port number.  A value of a key whose wire format is a
// sequence of fixed-size items holds whole items only.
//
// A param with no SvcParamValue, such as "no-default-alpn", has a nil or
// empty Value.
type SvcParam struct {
	Key   SvcParamKey
	Value []byte
}

// SvcParamKey identifies a SvcParam of a SVCB or HTTPS record
// (RFC 9460 Section 14.3).  The initial registered keys are KeyMandatory
// through KeyIPv6Hint; any other key number is an unregistered key whose
// value this library keeps uninterpreted.
type SvcParamKey uint16

// SvcParamKeys registered by RFC 9460 Section 14.3.2.
const (
	KeyMandatory     SvcParamKey = 0
	KeyAlpn          SvcParamKey = 1
	KeyNoDefaultAlpn SvcParamKey = 2
	KeyPort          SvcParamKey = 3
	KeyIPv4Hint      SvcParamKey = 4
	KeyECH           SvcParamKey = 5
	KeyIPv6Hint      SvcParamKey = 6
)

var svcParamKeyName = map[SvcParamKey]string{
	KeyMandatory:     "mandatory",
	KeyAlpn:          "alpn",
	KeyNoDefaultAlpn: "no-default-alpn",
	KeyPort:          "port",
	KeyIPv4Hint:      "ipv4hint",
	KeyECH:           "ech",
	KeyIPv6Hint:      "ipv6hint",
}

// svcParamKeyPattern matches the presentation-format form of a SvcParamKey:
// 1-63 characters from "a"-"z", "0"-"9" and "-" (RFC 9460 Section 2.1).
var svcParamKeyPattern = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// knownSvcParamKeys holds the registered keys, for NewSvcParamKey.
var knownSvcParamKeys = map[string]SvcParamKey{
	"mandatory":       KeyMandatory,
	"alpn":            KeyAlpn,
	"no-default-alpn": KeyNoDefaultAlpn,
	"port":            KeyPort,
	"ipv4hint":        KeyIPv4Hint,
	"ech":             KeyECH,
	"ipv6hint":        KeyIPv6Hint,
}

// String returns the name of the key in presentation format: the registered
// name for a registered key, and the "keyNNNNN" unknown-key form for any
// other key (RFC 9460 Section 2.1).
func (k SvcParamKey) String() string {
	if name, ok := svcParamKeyName[k]; ok {
		return name
	}
	return "key" + strconv.FormatUint(uint64(k), 10)
}

// NewSvcParamKey returns the key a presentation-format name denotes.  A name
// in the "keyNNNNN" form denotes that key number, and an unregistered name is
// reported as an error because it has no key number.
func NewSvcParamKey(name string) (SvcParamKey, error) {
	if !svcParamKeyPattern.MatchString(name) {
		return 0, fmt.Errorf("invalid SvcParamKey %q", name)
	}
	if key, ok := knownSvcParamKeys[name]; ok {
		return key, nil
	}
	if strings.HasPrefix(name, "key") {
		n, err := strconv.ParseUint(name[3:], 10, 16)
		if err == nil {
			return SvcParamKey(n), nil
		}
	}
	return 0, fmt.Errorf("unknown SvcParamKey %q", name)
}

// itemSize returns the size of one item of the key's value, or 0 when the
// key's value is not a sequence of fixed-size items.
func (k SvcParamKey) itemSize() int {
	switch k {
	case KeyIPv4Hint:
		return 4
	case KeyIPv6Hint:
		return 16
	}
	return 0
}

// String returns the presentation-format form of the param: the key name, then
// "=" and the value in the form its key defines (RFC 9460 Section 2.1 and
// Section 7).  A key whose value is empty is returned as the standalone key,
// as a zone file writes "no-default-alpn".
func (p SvcParam) String() string {
	value := p.presentationValue()
	if value == "" {
		return p.Key.String()
	}
	return p.Key.String() + "=" + value
}

// presentationValue returns the value of a validated param in the presentation
// form of its key.  The items of a list are escaped for the value-list syntax
// first and the joined text is then encoded as a character-string, which is what
// makes the escapes of RFC 9460 Appendix A.1 survive the character-string
// decoding of Appendix A.
func (p SvcParam) presentationValue() string {
	switch p.Key {
	case KeyMandatory:
		keys, err := mandatoryKeys(p.Value)
		if err != nil {
			break
		}
		names := make([]string, 0, len(keys))
		for _, key := range keys {
			names = append(names, key.String())
		}
		return strings.Join(names, ",")
	case KeyAlpn:
		ids, err := alpnIDs(p.Value)
		if err != nil {
			break
		}
		items := make([]string, 0, len(ids))
		for _, id := range ids {
			items = append(items, valueListItem(id))
		}
		return charStringEncode([]byte(strings.Join(items, ",")))
	case KeyPort:
		port, err := p.port()
		if err != nil {
			break
		}
		return strconv.FormatUint(uint64(port), 10)
	case KeyIPv4Hint, KeyIPv6Hint:
		addrs, err := p.addresses()
		if err != nil {
			break
		}
		items := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			items = append(items, addr.String())
		}
		return strings.Join(items, ",")
	}
	// The value of a key whose presentation format this library does not know
	// is written in the opaque form of the key: its octets as a
	// character-string, which is also the form RFC 9460 Section 2.1 defines for
	// the value of an unknown key.
	return charStringEncode(p.Value)
}

// valueListItem returns the octets of an item of a comma-separated list in the
// form the value-list syntax of RFC 9460 Appendix A.1 reads: a "," or a "\" of
// the item is written as "\," or "\\".
func valueListItem(item []byte) string {
	if !strings.ContainsRune(string(item), ',') && !strings.ContainsRune(string(item), '\\') {
		return string(item)
	}
	var buf strings.Builder
	buf.Grow(len(item) + 4)
	for _, c := range item {
		if c == ',' || c == '\\' {
			buf.WriteByte('\\')
		}
		buf.WriteByte(c)
	}
	return buf.String()
}

// charStringEncode returns a byte string as a character-string a zone file can
// read (RFC 9460 Appendix A): an octet that is not a "non-special" character is
// written as an escape sequence, either the "\" form of a character that is not
// a digit or the three-digit decimal form, and the whole string is quoted when
// it holds a quotation mark, one of the ";" "(" ")" delimiters, a white space
// character, or an octet outside printable ASCII.
func charStringEncode(v []byte) string {
	quoted := false
	for _, c := range v {
		if c == '"' || c == ';' || c == '(' || c == ')' || c <= ' ' || c >= 0x7f {
			quoted = true
			break
		}
	}
	var buf strings.Builder
	buf.Grow(len(v) + 2)
	if quoted {
		buf.WriteByte('"')
	}
	for _, c := range v {
		switch {
		case c == '"', c == '\\', c == ';', c == '(', c == ')':
			buf.WriteByte('\\')
			buf.WriteByte(c)
		case c >= '!' && c <= '~':
			buf.WriteByte(c)
		default:
			buf.WriteByte('\\')
			buf.WriteByte('0' + c/100)
			buf.WriteByte('0' + (c/10)%10)
			buf.WriteByte('0' + c%10)
		}
	}
	if quoted {
		buf.WriteByte('"')
	}
	return buf.String()
}

// validate reports a SvcParamValue that does not have the format its key
// defines (RFC 9460 Section 7).  A value of a key this library does not know
// has no defined format and is always accepted.
func (p SvcParam) validate() error {
	switch p.Key {
	case KeyMandatory:
		keys, err := mandatoryKeys(p.Value)
		if err != nil {
			return fmt.Errorf("mandatory= value: %v", err)
		}
		for _, key := range keys {
			if key == KeyMandatory {
				return fmt.Errorf("mandatory= lists the mandatory key itself")
			}
		}
	case KeyAlpn:
		ids, err := alpnIDs(p.Value)
		if err != nil {
			return fmt.Errorf("alpn= value: %v", err)
		}
		if len(ids) == 0 {
			return fmt.Errorf("alpn= has no ALPN IDs")
		}
	case KeyNoDefaultAlpn:
		if len(p.Value) != 0 {
			return fmt.Errorf("no-default-alpn= value is not empty")
		}
	case KeyPort:
		if _, err := p.port(); err != nil {
			return err
		}
	case KeyIPv4Hint, KeyIPv6Hint:
		addrs, err := p.addresses()
		if err != nil {
			return err
		}
		if len(addrs) == 0 {
			return fmt.Errorf("%s= has no IP addresses", p.Key)
		}
	}
	return nil
}

// alpnIDs splits an ALPN value into the octets of its ALPN IDs (RFC 9460
// Section 7.1).  The value is a sequence of length-prefixed ALPN IDs, so the
// octets of one ID are the value[pos+1 : pos+1+length] of the ID at value[pos].
func alpnIDs(value []byte) ([][]byte, error) {
	ids := make([][]byte, 0, 4)
	for pos := 0; pos < len(value); {
		n := int(value[pos])
		if n == 0 {
			return nil, fmt.Errorf("ALPN ID of length 0")
		}
		if pos+1+n > len(value) {
			return nil, fmt.Errorf("ALPN ID of length %d ends within the value", n)
		}
		ids = append(ids, value[pos+1:pos+1+n])
		pos += 1 + n
	}
	return ids, nil
}

// mandatoryKeys returns the SvcParamKeys a "mandatory" value lists: the value
// is a sequence of 2-octet key numbers in strictly increasing numeric order
// (RFC 9460 Section 8).
func mandatoryKeys(value []byte) ([]SvcParamKey, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("has no SvcParamKeys")
	}
	if len(value)%2 != 0 {
		return nil, fmt.Errorf("of %d octets is not a whole number of 2-octet SvcParamKeys", len(value))
	}
	keys := make([]SvcParamKey, 0, len(value)/2)
	for pos := 0; pos+2 <= len(value); pos += 2 {
		keys = append(keys, SvcParamKey(uint16(value[pos])<<8|uint16(value[pos+1])))
	}
	for i := 1; i < len(keys); i++ {
		if keys[i-1] >= keys[i] {
			return nil, fmt.Errorf("SvcParamKeys are not in strictly increasing order")
		}
	}
	return keys, nil
}

// port returns the port number of a "port" param, whose value is the 2-octet
// number in network byte order (RFC 9460 Section 7.2).
func (p SvcParam) port() (uint16, error) {
	if len(p.Value) != 2 {
		return 0, fmt.Errorf("port= value of %d octets is not 2 octets", len(p.Value))
	}
	return uint16(p.Value[0])<<8 | uint16(p.Value[1]), nil
}

// addresses returns the IP addresses of an "ipv4hint" or "ipv6hint" param:
// the value is a sequence of addresses of the appropriate family in network
// byte order (RFC 9460 Section 7.3).
func (p SvcParam) addresses() ([]netip.Addr, error) {
	n := p.Key.itemSize()
	if n == 0 {
		return nil, fmt.Errorf("%s= value is not a sequence of addresses", p.Key)
	}
	if len(p.Value)%n != 0 {
		return nil, fmt.Errorf("%s= value of %d octets is not a whole number of %d-octet addresses", p.Key, len(p.Value), n)
	}
	family := "IPv4"
	if n == 16 {
		family = "IPv6"
	}
	addrs := make([]netip.Addr, 0, len(p.Value)/n)
	for pos := 0; pos+n <= len(p.Value); pos += n {
		addr, ok := netip.AddrFromSlice(p.Value[pos : pos+n])
		if !ok {
			return nil, fmt.Errorf("%s= value has an address that is not 4 or 16 octets", p.Key)
		}
		addr = addr.Unmap()
		if len(addr.AsSlice()) != n {
			return nil, fmt.Errorf("%s= value has %s, which is not an %s address", p.Key, addr, family)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// NewSvcParam returns the param with the given key whose value is given in the
// text form of the key, which is the form a SvcParamValue has after the
// character-string decoding of RFC 9460 Appendix A: escape sequences are already
// resolved, but the items of a list are still separated by ",", and a "," or a
// "\" of an item itself is still written as "\," or "\\" (Appendix A.1).
//
//	mandatory      comma-separated SvcParamKeys
//	alpn           comma-separated ALPN IDs
//	no-default-alpn an empty value
//	port           a decimal number in the range 0-65535
//	ipv4hint       comma-separated IPv4 addresses
//	ech            the octets of the ECHConfigList
//	ipv6hint       comma-separated IPv6 addresses
//	other keys     the octets used as the wire-format encoding
func NewSvcParam(key SvcParamKey, value string) (SvcParam, error) {
	switch key {
	case KeyMandatory:
		names, err := splitValueList([]byte(value))
		if err != nil {
			return SvcParam{}, err
		}
		if len(names) == 0 {
			return SvcParam{}, fmt.Errorf("mandatory= has no SvcParamKeys")
		}
		var keys []SvcParamKey
		for _, name := range names {
			k, err := NewSvcParamKey(name)
			if err != nil {
				return SvcParam{}, err
			}
			if k == KeyMandatory {
				return SvcParam{}, fmt.Errorf("mandatory= lists the mandatory key itself")
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		buf := make([]byte, 0, 2*len(keys))
		for i, k := range keys {
			if i > 0 && k == keys[i-1] {
				return SvcParam{}, fmt.Errorf("mandatory= lists %s more than once", k)
			}
			buf = append(buf, byte(k>>8), byte(k))
		}
		return SvcParam{Key: key, Value: buf}, nil
	case KeyNoDefaultAlpn:
		if value != "" {
			return SvcParam{}, fmt.Errorf("no-default-alpn= value is not empty")
		}
		return SvcParam{Key: key}, nil
	case KeyAlpn:
		ids, err := splitValueList([]byte(value))
		if err != nil {
			return SvcParam{}, err
		}
		if len(ids) == 0 {
			return SvcParam{}, fmt.Errorf("alpn= has no ALPN IDs")
		}
		var buf []byte
		for _, id := range ids {
			if len(id) > 255 {
				return SvcParam{}, fmt.Errorf("ALPN ID %q is longer than 255 octets", id)
			}
			buf = append(buf, byte(len(id)))
			buf = append(buf, id...)
		}
		return SvcParam{Key: key, Value: buf}, nil
	case KeyPort:
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return SvcParam{}, fmt.Errorf("port=%s is not a decimal number in the range 0-65535", value)
		}
		return SvcParam{Key: key, Value: []byte{byte(n >> 8), byte(n)}}, nil
	case KeyIPv4Hint, KeyIPv6Hint:
		want, name := 4, "IPv4"
		if key == KeyIPv6Hint {
			want, name = 16, "IPv6"
		}
		var buf []byte
		items, err := splitValueList([]byte(value))
		if err != nil {
			return SvcParam{}, err
		}
		if len(items) == 0 {
			return SvcParam{}, fmt.Errorf("%s= has no IP addresses", key)
		}
		for _, s := range items {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return SvcParam{}, fmt.Errorf("%s=%s: %v", key, s, err)
			}
			addr = addr.Unmap()
			if addr.Zone() != "" || len(addr.AsSlice()) != want {
				return SvcParam{}, fmt.Errorf("%s=%s is not an %s address", key, s, name)
			}
			buf = append(buf, addr.AsSlice()...)
		}
		return SvcParam{Key: key, Value: buf}, nil
	default:
		return SvcParam{Key: key, Value: []byte(value)}, nil
	}
}

// String returns the record in presentation format: SvcPriority, TargetName,
// and then the SvcParams as key=value pairs (RFC 9460 Section 2.1).
func (r RecordSVCB) String() string {
	parts := make([]string, 0, 2+len(r.SvcParams))
	parts = append(parts, strconv.FormatUint(uint64(r.SvcPriority), 10), r.TargetName.String())
	for _, p := range r.SvcParams {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, " ")
}

func (r RecordSVCB) Type() ResourceType {
	return TYPE_SVCB
}

func (r RecordSVCB) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

// AppendWireFormat writes the SvcPriority, then the TargetName, then the
// SvcParams in increasing key order with each value length.  The target name is
// written in full and never compressed, because a SVCB target name is
// uncompressed on the wire (RFC 9460 Section 2.2, RFC 3597 Section 4), so db is
// deliberately not used here.
func (r RecordSVCB) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	return r.appendWireFormat(w, false)
}

func (r RecordSVCB) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return r.appendWireFormat(w, true)
}

// appendWireFormat writes the RDATA layout, with the target name lower-cased
// when canonical and written as it is when not.
func (r RecordSVCB) appendWireFormat(w *WireFormat, canonical bool) uint32 {
	var size uint32 = 0
	size += w.AppendUInt16(r.SvcPriority)
	if canonical {
		size += w.AppendCanonicalDomainName(r.TargetName)
	} else {
		size += w.AppendDomainName(r.TargetName, nil)
	}
	for _, p := range r.SvcParams {
		size += w.AppendUInt16(uint16(p.Key))
		size += w.AppendUInt16(uint16(len(p.Value)))
		size += w.AppendBytes(p.Value)
	}
	return size
}

// ParseRecordSVCB reads a SVCB record from the wire format.  The RDATA is
// read from begin up to end, the RDLENGTH-derived end of the RDATA, so the
// parsed record is bounded by its own RDLENGTH rather than by the remainder of
// the message.  An RDATA that ends within a SvcParam, whose SvcParamKeys are
// not in strictly increasing order, whose SvcParams repeat a key, or whose
// SvcParams are not the ones its SvcPriority allows is malformed (RFC 9460
// Section 2.2, Section 2.4.1, Section 8).
func ParseRecordSVCB(w WireFormat, begin, end uint32) (r RecordSVCB, next uint32, err error) {
	return parseSvcBRecord(w, begin, end, TYPE_SVCB)
}

// parseSvcBRecord reads the RDATA layout that a SVCB record and a HTTPS record
// share (RFC 9460 Section 2, Section 3).  rtype is the record the RDATA is read
// for, and it is only used to name the record in error messages.
func parseSvcBRecord(w WireFormat, begin, end uint32, rtype ResourceType) (r RecordSVCB, next uint32, err error) {
	r = RecordSVCB{}
	name := rtype.String()
	if begin+2 > end {
		err = fmt.Errorf("not enough size for %s record SvcPriority", name)
		return
	}
	priority, _ := w.GetUInt16(begin)
	r.SvcPriority = priority
	pos := begin + 2

	target, next, err := parseDomainnameLabels(w, pos, false)
	if err != nil {
		err = fmt.Errorf("cannot parse %s record TargetName: %v", name, err)
		return
	}
	r.TargetName, err = newDomainNameFromLabels(target)
	if err != nil {
		err = fmt.Errorf("cannot parse %s record TargetName: %v", name, err)
		r = RecordSVCB{}
		return
	}
	if next > end {
		err = fmt.Errorf("%s record TargetName extends beyond the RDATA", name)
		r = RecordSVCB{}
		return
	}
	pos = next

	seen := make(map[SvcParamKey]bool)
	var last SvcParamKey
	for pos < end {
		if pos+4 > end {
			err = fmt.Errorf("%s record SvcParam header is truncated at the end of the RDATA", name)
			r = RecordSVCB{}
			return
		}
		key, _ := w.GetUInt16(pos)
		vlen, _ := w.GetUInt16(pos + 2)
		pos += 4
		if len(r.SvcParams) > 0 && uint16(last) >= key {
			err = fmt.Errorf("%s record SvcParamKey %d does not follow %d in increasing order", name, key, last)
			r = RecordSVCB{}
			return
		}
		valueEnd := pos + uint32(vlen)
		if valueEnd > end {
			err = fmt.Errorf("%s record SvcParamKey %d value of %d octets extends beyond the RDATA", name, key, vlen)
			r = RecordSVCB{}
			return
		}
		var value []byte
		if valueEnd > pos {
			value = append(value, w[pos:valueEnd]...)
		}
		param := SvcParam{Key: SvcParamKey(key), Value: value}
		pos = valueEnd
		if seen[param.Key] {
			err = fmt.Errorf("%s record has more than one %s SvcParam", name, param.Key)
			r = RecordSVCB{}
			return
		}
		seen[param.Key] = true
		last = param.Key
		if err = param.validate(); err != nil {
			err = fmt.Errorf("malformed %s record: %v", name, err)
			r = RecordSVCB{}
			return
		}
		r.SvcParams = append(r.SvcParams, param)
	}

	if err = validateSvcParams(r.SvcPriority, r.SvcParams); err != nil {
		err = fmt.Errorf("malformed %s record: %v", name, err)
		r = RecordSVCB{}
		return
	}
	next = pos
	return
}

// NewRecordSVCB returns the SVCB record with the given priority, target name,
// and SvcParams, which may be given in any order: they are sorted into the
// increasing key order the wire format requires.  A record in AliasMode, with
// SvcPriority 0, MUST NOT have SvcParams (RFC 9460 Section 2.4.1).
func NewRecordSVCB(svcPriority uint16, targetName DomainName, params ...SvcParam) (RecordSVCB, error) {
	return newSvcBRecord(svcPriority, targetName, params...)
}

// newSvcBRecord returns a record with the RDATA layout a SVCB record and a
// HTTPS record share, with its SvcParams sorted into the order the wire format
// requires.  A record without SvcParams has a nil SvcParams, which is the form
// parseSvcBRecord reads one in.
func newSvcBRecord(svcPriority uint16, targetName DomainName, params ...SvcParam) (RecordSVCB, error) {
	r := RecordSVCB{
		SvcPriority: svcPriority,
		TargetName:  targetName,
	}
	if len(params) > 0 {
		r.SvcParams = append([]SvcParam{}, params...)
	}
	sort.SliceStable(r.SvcParams, func(i, j int) bool { return r.SvcParams[i].Key < r.SvcParams[j].Key })
	if err := validateSvcParams(r.SvcPriority, r.SvcParams); err != nil {
		return RecordSVCB{}, err
	}

	if err := validateSvcBRDATA(r); err != nil {
		return RecordSVCB{}, err
	}
	return r, nil
}

// validateSvcBRDATA reports whether the record fits the 16-bit RDLENGTH that
// carries a RDATA: the SvcPriority, the TargetName, and the SvcParams are a
// SvcPriority and a name of at most 255 octets, and each SvcParam is a 4-octet
// header and a value of at most 65535 octets, so the whole is checked against
// the RDLENGTH rather than against the parts (RFC 9460 Section 2).
func validateSvcBRDATA(r RecordSVCB) error {
	size := 2 + len(r.TargetName.CanonicalWireFormat())
	for _, p := range r.SvcParams {
		size += 4 + len(p.Value)
	}
	if size > 65535 {
		return fmt.Errorf("SvcParams make a RDATA of %d octets, which does not fit 16 bits", size)
	}
	return nil
}

// NewRecordSVCBFromParams returns the SVCB record whose SvcParams are given
// in the presentation form of their keys, as a zone file writes them.  The
// target name is given in presentation format.
func NewRecordSVCBFromParams(svcPriority uint16, targetName string, params map[string]string) (RecordSVCB, error) {
	return newSvcBRecordFromParams(svcPriority, targetName, params)
}

// newSvcBRecordFromParams returns a record whose RDATA is built from
// presentation-format SvcParam keys and values.
func newSvcBRecordFromParams(svcPriority uint16, targetName string, params map[string]string) (RecordSVCB, error) {
	target, err := NewDomainNameFromString(targetName)
	if err != nil {
		return RecordSVCB{}, err
	}
	list := make([]SvcParam, 0, len(params))
	for name, value := range params {
		key, err := NewSvcParamKey(name)
		if err != nil {
			return RecordSVCB{}, err
		}
		param, err := NewSvcParam(key, value)
		if err != nil {
			return RecordSVCB{}, err
		}
		list = append(list, param)
	}
	return newSvcBRecord(svcPriority, target, list...)
}

// validateSvcParams reports whether the params may appear in a record with the
// given SvcPriority: an AliasMode record has none, no key appears twice, and
// the keys a "mandatory" param lists all appear in the record
// (RFC 9460 Section 2.4.3, Section 8).
func validateSvcParams(svcPriority uint16, params []SvcParam) error {
	if svcPriority == 0 && len(params) > 0 {
		return fmt.Errorf("SvcPriority 0 (AliasMode) does not allow SvcParams")
	}
	seen := make(map[SvcParamKey]bool)
	for _, p := range params {
		if seen[p.Key] {
			return fmt.Errorf("more than one %s SvcParam", p.Key)
		}
		seen[p.Key] = true
		if err := p.validate(); err != nil {
			return fmt.Errorf("malformed SvcParam: %v", err)
		}
	}
	for _, p := range params {
		if p.Key != KeyMandatory {
			continue
		}
		keys, err := mandatoryKeys(p.Value)
		if err != nil {
			return fmt.Errorf("malformed SvcParam: %v", err)
		}
		for _, key := range keys {
			if !seen[key] {
				return fmt.Errorf("mandatory= lists %s, which the record does not have", key)
			}
		}
	}
	return nil
}

// NewRecordSVCBFromString parses a SVCB record from a presentation-format
// string such as "1 svcb.example.com. alpn=h2,h3 port=8443"
// (RFC 9460 Section 2.1), which is the form RecordSVCB.String writes; a value
// written as a quoted character-string, such as alpn="h2,h3", is read as well.
// The SvcParams may appear in any order, but a key may not appear twice.
func NewRecordSVCBFromString(s string) (RecordSVCB, error) {
	return newSvcBRecordFromString(s, TYPE_SVCB)
}

// newSvcBRecordFromString parses the presentation format that a SVCB record
// and a HTTPS record share (RFC 9460 Section 2.1, Section 3).  rtype names the
// record in error messages.
func newSvcBRecordFromString(s string, rtype ResourceType) (r RecordSVCB, err error) {
	name := rtype.String()
	fields := splitPresentationFields(s)
	if len(fields) < 2 {
		err = fmt.Errorf("%s record %q has fewer than 2 fields", name, s)
		return
	}
	priority, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		err = fmt.Errorf("%s record %q has an invalid SvcPriority", name, s)
		return
	}
	r.SvcPriority = uint16(priority)

	target, err := NewDomainNameFromString(fields[1])
	if err != nil {
		err = fmt.Errorf("cannot parse %s record TargetName: %v", name, err)
		return
	}
	r.TargetName = target

	if len(fields) > 2 {
		r.SvcParams = make([]SvcParam, 0, len(fields)-2)
		for _, field := range fields[2:] {
			key, value := field, ""
			if k, v, ok := splitSvcParam(field); ok {
				key, value = k, v
			}
			p, err := parseSvcParam(key, value)
			if err != nil {
				r = RecordSVCB{}
				return RecordSVCB{}, err
			}
			r.SvcParams = append(r.SvcParams, p)
		}
	}

	sort.SliceStable(r.SvcParams, func(i, j int) bool { return r.SvcParams[i].Key < r.SvcParams[j].Key })
	if err = validateSvcParams(r.SvcPriority, r.SvcParams); err != nil {
		r = RecordSVCB{}
		return
	}
	if err = validateSvcBRDATA(r); err != nil {
		r = RecordSVCB{}
		return
	}
	return
}

// splitPresentationFields splits a RDATA presentation-format string on the
// white space that separates its fields, which is not the white space of a
// quoted character-string.
func splitPresentationFields(s string) []string {
	var fields []string
	var buf []byte
	quoted := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			buf = append(buf, c)
			escaped = false
		case c == '\\':
			buf = append(buf, c)
			escaped = true
		case c == '"':
			buf = append(buf, c)
			quoted = !quoted
		case !quoted && isTXTDelimiter(c):
			if len(buf) > 0 {
				fields = append(fields, string(buf))
				buf = nil
			}
		default:
			buf = append(buf, c)
		}
	}
	if len(buf) > 0 {
		fields = append(fields, string(buf))
	}
	return fields
}

// splitSvcParam splits a "key=value" field.  The separator is the first '='
// that is not inside a quoted character-string: a value such as the one of
// "ech" may contain '=' (RFC 9460 Section 2.1).
func splitSvcParam(field string) (key, value string, ok bool) {
	quoted := false
	escaped := false
	for i := 0; i < len(field); i++ {
		c := field[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case c == '=' && !quoted:
			return field[:i], field[i+1:], true
		}
	}
	return "", "", false
}

// parseSvcParam returns the param a presentation-format key and value denote.
// The value is decoded with the character-string algorithm of RFC 9460
// Appendix A: a quoted string takes its contents with the escape sequences
// decoded, an unquoted string takes its octets with the "\" escapes decoded,
// and then the key-specific form of the value is parsed.
func parseSvcParam(keyName, value string) (SvcParam, error) {
	key, err := NewSvcParamKey(keyName)
	if err != nil {
		return SvcParam{}, err
	}
	decoded, err := decodeSvcParamValue(value)
	if err != nil {
		return SvcParam{}, err
	}
	switch key {
	case KeyMandatory, KeyAlpn, KeyNoDefaultAlpn, KeyPort, KeyIPv4Hint, KeyIPv6Hint:
		return NewSvcParam(key, string(decoded))
	default:
		param := SvcParam{Key: key, Value: decoded}
		if err := param.validate(); err != nil {
			return SvcParam{}, err
		}
		return param, nil
	}
}

// decodeSvcParamValue applies the character-string decoding algorithm of
// RFC 9460 Appendix A: "\DDD" becomes the octet its three decimal digits
// denote, "\" before a non-digit becomes that character, and the contents of a
// quoted character-string are taken up to its closing quotation mark.  The
// result is the value the key's own parser then sees; it is not yet split into
// the items of a list, because the commas of a comma-separated list are part of
// the character-string (Appendix A.1).
func decodeSvcParamValue(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	quoted := s[0] == '"'
	pos := 0
	if quoted {
		pos = 1
	}
	var buf []byte
	for pos < len(s) {
		c := s[pos]
		switch {
		case c == '"':
			if !quoted {
				return nil, fmt.Errorf("SvcParamValue %q has a quotation mark after the first character", s)
			}
			if pos+1 != len(s) {
				return nil, fmt.Errorf("SvcParamValue %q has text after the closing quotation mark", s)
			}
			return buf, nil
		case c == ';', c == '(', c == ')':
			if !quoted {
				return nil, fmt.Errorf("SvcParamValue %q has %c outside quotation marks", s, c)
			}
			buf = append(buf, c)
			pos++
		case c != '\\':
			buf = append(buf, c)
			pos++
		default:
			octet, next, err := decodeOctetEscape(s, pos)
			if err != nil {
				return nil, err
			}
			buf = append(buf, octet)
			pos = next
		}
	}
	if quoted {
		return nil, fmt.Errorf("SvcParamValue %q has no closing quotation mark", s)
	}
	return buf, nil
}

// decodeOctetEscape decodes the escape sequence that begins at pos, which is
// "\DDD" for the octet 0-255 its three decimal digits denote, or "\" followed
// by a non-digit for that character (RFC 9460 Appendix A).  The returned offset
// is the one after the escape sequence.
func decodeOctetEscape(s string, pos int) (byte, int, error) {
	if pos+1 >= len(s) {
		return 0, 0, fmt.Errorf("SvcParamValue %q ends with a backslash", s)
	}
	c := s[pos+1]
	if c < '0' || c > '9' {
		return c, pos + 2, nil
	}
	if pos+3 >= len(s) {
		return 0, 0, fmt.Errorf("SvcParamValue %q has an incomplete \\DDD escape", s)
	}
	n := 0
	for _, d := range []byte(s[pos+1 : pos+4]) {
		if d < '0' || d > '9' {
			return 0, 0, fmt.Errorf("SvcParamValue %q has an incomplete \\DDD escape", s)
		}
		n = n*10 + int(d-'0')
	}
	if n > 255 {
		return 0, 0, fmt.Errorf("SvcParamValue %q has escape sequence \\%03d of more than 255", s, n)
	}
	return byte(n), pos + 4, nil
}

// splitValueList decodes a comma-separated list (RFC 9460 Appendix A.1): the
// value is split on the commas that do not follow a backslash, and the "\,"
// and "\\" escape sequences that hold a comma or a backslash in an item are
// resolved.  Empty items are not allowed, but an empty value is a list of no
// items.
func splitValueList(value []byte) ([]string, error) {
	if len(value) == 0 {
		return nil, nil
	}
	var items []string
	var buf []byte
	escaped := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if escaped {
			escaped = false
			if c != ',' && c != '\\' {
				return nil, fmt.Errorf("list item has a backslash before %c", c)
			}
			buf = append(buf, c)
			continue
		}
		switch c {
		case '\\':
			escaped = true
		case ',':
			if len(buf) == 0 {
				return nil, fmt.Errorf("comma-separated list has an empty item")
			}
			items = append(items, string(buf))
			buf = nil
		default:
			buf = append(buf, c)
		}
	}
	if escaped {
		return nil, fmt.Errorf("comma-separated list ends with a backslash")
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("comma-separated list has an empty item")
	}
	return append(items, string(buf)), nil
}

// MarshalJSON encodes the record as a JSON object.  The target name is
// encoded as its presentation-format string, and each SvcParam as a JSON
// object with the presentation-format name of the key, the value as its
// presentation-format string, and the value as a base64 string so that values
// that are not text, such as "ech", round-trip.
func (r RecordSVCB) MarshalJSON() ([]byte, error) {
	params := make([]map[string]any, 0, len(r.SvcParams))
	for _, p := range r.SvcParams {
		params = append(params, map[string]any{
			"Key":   p.Key.String(),
			"Value": p.presentationValue(),
			"Raw":   encodeBase64(p.Value),
		})
	}
	return json.Marshal(map[string]any{
		"SvcPriority": r.SvcPriority,
		"TargetName":  r.TargetName,
		"SvcParams":   params,
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON produces.
func (r *RecordSVCB) UnmarshalJSON(data []byte) error {
	rec, err := unmarshalSvcBJSON(data, TYPE_SVCB)
	if err != nil {
		return err
	}
	*r = rec
	return nil
}

// unmarshalSvcBJSON decodes the JSON object that MarshalJSON writes for the
// RDATA a SVCB record and a HTTPS record share.  rtype names the record in
// error messages.  A SvcParam with a "Raw" field takes its value from that
// field; otherwise it takes the presentation-format value.
func unmarshalSvcBJSON(data []byte, rtype ResourceType) (r RecordSVCB, err error) {
	name := rtype.String()
	var fields struct {
		SvcPriority uint16 `json:"SvcPriority"`
		TargetName  DomainName
		SvcParams   []struct {
			Key   string
			Value string
			Raw   string
		}
	}
	if err = json.Unmarshal(data, &fields); err != nil {
		return RecordSVCB{}, fmt.Errorf("cannot parse %s record: %w", name, err)
	}
	r.SvcPriority = fields.SvcPriority
	r.TargetName = fields.TargetName
	if len(fields.SvcParams) > 0 {
		r.SvcParams = make([]SvcParam, 0, len(fields.SvcParams))
		for _, f := range fields.SvcParams {
			key, err := NewSvcParamKey(f.Key)
			if err != nil {
				return RecordSVCB{}, fmt.Errorf("cannot parse %s record: %v", name, err)
			}
			param := SvcParam{Key: key}
			if f.Raw != "" {
				value, err := decodeBase64(f.Raw)
				if err != nil {
					return RecordSVCB{}, fmt.Errorf("cannot parse %s record: %v", name, err)
				}
				param.Value = value
				if err := param.validate(); err != nil {
					return RecordSVCB{}, fmt.Errorf("cannot parse %s record: %v", name, err)
				}
			} else {
				param, err = parseSvcParam(f.Key, f.Value)
				if err != nil {
					return RecordSVCB{}, fmt.Errorf("cannot parse %s record: %v", name, err)
				}
			}
			r.SvcParams = append(r.SvcParams, param)
		}
	}
	sort.SliceStable(r.SvcParams, func(i, j int) bool { return r.SvcParams[i].Key < r.SvcParams[j].Key })
	if err := validateSvcParams(r.SvcPriority, r.SvcParams); err != nil {
		return RecordSVCB{}, fmt.Errorf("cannot parse %s record: %v", name, err)
	}
	if err := validateSvcBRDATA(r); err != nil {
		return RecordSVCB{}, fmt.Errorf("cannot parse %s record: %v", name, err)
	}
	return r, nil
}
