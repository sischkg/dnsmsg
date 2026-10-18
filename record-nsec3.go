package dnsmsg

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Hash algorithm constants for NSEC3 records (RFC 5155 Section 3.2).
const (
	HashAlgorithmSHA1 uint8 = 1
)

// NSEC3 flag constants (RFC 5155 Section 3.2).
const (
	FlagOptOut uint8 = 0x01
)

// RecordNSEC3 represents an NSEC3 (NSEC version 3) record per RFC 5155 Section 3.2.
//
// NSEC3 RDATA wire format:
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Hash Alg. |   Flags   |     Iterations      |  Salt Length  |  Salt   /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   /      Hash Length    /   Next Hashed Owner Name  /    Type Bit Maps    /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// The Next Hashed Owner Name is encoded as a length-prefixed label: the
// first octet is the label length (which must equal Hash Length), followed
// by Hash Length octets of the hashed owner name.
type RecordNSEC3 struct {
	HashAlgorithm  uint8
	Flags          uint8
	Iterations     uint16
	Salt           []byte
	NextHashedName []byte
	Types          []ResourceType
}

func (r RecordNSEC3) Type() ResourceType {
	return TYPE_NSEC3
}

func (r RecordNSEC3) String() string {
	typeNames := make([]string, 0, len(r.Types))
	for _, typ := range r.Types {
		typeNames = append(typeNames, typ.String())
	}
	return fmt.Sprintf("%d %d %d %s %s %s",
		r.HashAlgorithm,
		r.Flags,
		r.Iterations,
		hex.EncodeToString(r.Salt),
		hex.EncodeToString(r.NextHashedName),
		strings.Join(typeNames, " "),
	)
}

func (r RecordNSEC3) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

func (r RecordNSEC3) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendUInt8(r.HashAlgorithm)
	size += w.AppendUInt8(r.Flags)
	size += w.AppendUInt16(r.Iterations)
	size += w.AppendUInt8(uint8(len(r.Salt)))
	size += w.AppendBytes(r.Salt)
	// Hash Length (1 octet)
	size += w.AppendUInt8(uint8(len(r.NextHashedName)))
	// Next Hashed Owner Name: label length (= Hash Length) + hashed name
	size += w.AppendUInt8(uint8(len(r.NextHashedName)))
	size += w.AppendBytes(r.NextHashedName)
	size += appendTypeBitMaps(w, r.Types)
	return size
}

func (r RecordNSEC3) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return r.AppendWireFormat(w, nil)
}

// MarshalJSON encodes the record as a JSON object.  Salt, hash length, and
// next hashed name are encoded as lower-case hexadecimal strings, and types
// as an array of resource type names.
func (r RecordNSEC3) MarshalJSON() ([]byte, error) {
	typeNames := make([]string, 0, len(r.Types))
	for _, typ := range r.Types {
		typeNames = append(typeNames, typ.String())
	}
	return json.Marshal(map[string]any{
		"HashAlgorithm":  r.HashAlgorithm,
		"Flags":          r.Flags,
		"Iterations":     r.Iterations,
		"Salt":           hex.EncodeToString(r.Salt),
		"NextHashedName": hex.EncodeToString(r.NextHashedName),
		"Types":          typeNames,
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces.  Salt and next hashed name are taken from hexadecimal strings,
// and each type from a resource type name or a numeric code.
func (r *RecordNSEC3) UnmarshalJSON(data []byte) error {
	var fields struct {
		HashAlgorithm  uint8      `json:"HashAlgorithm"`
		Flags          uint8      `json:"Flags"`
		Iterations     uint16     `json:"Iterations"`
		Salt           string     `json:"Salt"`
		NextHashedName string     `json:"NextHashedName"`
		Types          json.RawMessage `json:"Types"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse NSEC3 record: %w", err)
	}
	salt, err := hex.DecodeString(fields.Salt)
	if err != nil {
		return fmt.Errorf("invalid NSEC3 salt %q: %w", fields.Salt, err)
	}
	nextHashedName, err := hex.DecodeString(fields.NextHashedName)
	if err != nil {
		return fmt.Errorf("invalid NSEC3 next hashed name %q: %w", fields.NextHashedName, err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(fields.Types, &items); err != nil {
		return fmt.Errorf("invalid NSEC3 types: %w", err)
	}
	types := make([]ResourceType, 0, len(items))
	for _, item := range items {
		typ, err := decodeNSECTypeItem(item)
		if err != nil {
			return fmt.Errorf("invalid NSEC3 type: %w", err)
		}
		types = append(types, typ)
	}
	*r = RecordNSEC3{
		HashAlgorithm:  fields.HashAlgorithm,
		Flags:          fields.Flags,
		Iterations:     fields.Iterations,
		Salt:           salt,
		NextHashedName: nextHashedName,
		Types:          types,
	}
	return nil
}

// NewRecordNSEC3 creates a new RecordNSEC3 from structured values.  The types
// are sorted for deterministic wire-format encoding.
func NewRecordNSEC3(hashAlgorithm uint8, flags uint8, iterations uint16,
	salt []byte, nextHashedName []byte, types []ResourceType) RecordNSEC3 {
	sorted := make([]ResourceType, len(types))
	copy(sorted, types)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return RecordNSEC3{
		HashAlgorithm:  hashAlgorithm,
		Flags:          flags,
		Iterations:     iterations,
		Salt:           salt,
		NextHashedName: nextHashedName,
		Types:          sorted,
	}
}

// NewRecordNSEC3FromString parses an NSEC3 record from presentation format string
// Format: <hash-algorithm> <flags> <iterations> <salt-hex> <next-hashed-hex> <type> [<type> ...]
func NewRecordNSEC3FromString(s string) (RecordNSEC3, error) {
	fields := strings.Fields(s)
	if len(fields) < 6 {
		return RecordNSEC3{}, fmt.Errorf(`invalid NSEC3 record format "%s"`, s)
	}

	hashAlgorithm, err := strconv.ParseUint(fields[0], 10, 8)
	if err != nil {
		return RecordNSEC3{}, fmt.Errorf(`invalid hash algorithm "%s"`, fields[0])
	}

	flags, err := strconv.ParseUint(fields[1], 10, 8)
	if err != nil {
		return RecordNSEC3{}, fmt.Errorf(`invalid flags "%s"`, fields[1])
	}

	iterations, err := strconv.ParseUint(fields[2], 10, 16)
	if err != nil {
		return RecordNSEC3{}, fmt.Errorf(`invalid iterations "%s"`, fields[2])
	}

	salt, err := hex.DecodeString(fields[3])
	if err != nil {
		return RecordNSEC3{}, fmt.Errorf(`invalid salt "%s"`, fields[3])
	}

	nextHashedName, err := hex.DecodeString(fields[4])
	if err != nil {
		return RecordNSEC3{}, fmt.Errorf(`invalid next hashed name "%s"`, fields[4])
	}

	var types []ResourceType
	for _, f := range fields[5:] {
		typ, err := parseTypeString(f)
		if err != nil {
			return RecordNSEC3{}, err
		}
		types = append(types, typ)
	}

	return NewRecordNSEC3(
		uint8(hashAlgorithm),
		uint8(flags),
		uint16(iterations),
		salt,
		nextHashedName,
		types,
	), nil
}

// ParseRecordNSEC3 parses an NSEC3 record from wire format. The type bit maps
// are bounded by end, the RDLENGTH-derived offset of the record, rather than
// the remainder of the whole message.
func ParseRecordNSEC3(w WireFormat, begin uint32, end uint32) (r RecordNSEC3, pos uint32, err error) {
	var p uint32 = begin

	// Hash Algorithm (1 octet)
	if p+1 > end {
		return r, begin, fmt.Errorf("cannot parse NSEC3 hash algorithm")
	}
	hashAlgorithm, err := w.GetUInt8(p)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3 hash algorithm: %w", err)
	}
	p++

	// Flags (1 octet)
	if p+1 > end {
		return r, begin, fmt.Errorf("cannot parse NSEC3 flags")
	}
	flags, err := w.GetUInt8(p)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3 flags: %w", err)
	}
	p++

	// Iterations (2 octets, network byte order)
	if p+2 > end {
		return r, begin, fmt.Errorf("cannot parse NSEC3 iterations")
	}
	iterations, err := w.GetUInt16(p)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3 iterations: %w", err)
	}
	p += 2

	// Salt Length (1 octet)
	if p+1 > end {
		return r, begin, fmt.Errorf("cannot parse NSEC3 salt length")
	}
	saltLength, err := w.GetUInt8(p)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3 salt length: %w", err)
	}
	p++

	// Salt (Salt Length octets)
	if p+uint32(saltLength) > end {
		return r, begin, fmt.Errorf("NSEC3 salt extends beyond record")
	}
	salt := w[p : p+uint32(saltLength)]
	p += uint32(saltLength)

	// Hash Length (1 octet)
	if p+1 > end {
		return r, begin, fmt.Errorf("cannot parse NSEC3 hash length")
	}
	hashLength, err := w.GetUInt8(p)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3 hash length: %w", err)
	}
	p++

	// Next Hashed Owner Name (Hash Length octets, length-prefixed label)
	// The wire format of the hashed name is a single label: a length octet
	// followed by Hash Length octets.  The length octet must equal Hash Length.
	if p+1+uint32(hashLength) > end {
		return r, begin, fmt.Errorf("NSEC3 next hashed owner name extends beyond record")
	}
	labelLength, err := w.GetUInt8(p)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3 next hashed owner name label length: %w", err)
	}
	p++
	if uint32(labelLength) != uint32(hashLength) {
		return r, begin, fmt.Errorf("NSEC3 next hashed owner name label length %d does not match hash length %d",
			labelLength, hashLength)
	}
	nextHashedName := w[p : p+uint32(hashLength)]
	p += uint32(hashLength)

	// Type Bit Maps (remainder of the record, bounded by end)
	types, p, err := parseTypeBitMaps(w, p, end)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3 type bit maps: %w", err)
	}

	r = RecordNSEC3{
		HashAlgorithm:  hashAlgorithm,
		Flags:          flags,
		Iterations:     iterations,
		Salt:           salt,
		NextHashedName: nextHashedName,
		Types:          types,
	}
	pos = p
	return
}
