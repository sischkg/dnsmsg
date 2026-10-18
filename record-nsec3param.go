package dnsmsg

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// RecordNSEC3PARAM represents an NSEC3PARAM record per RFC 5155 Section 6.
//
// NSEC3PARAM RDATA wire format:
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Hash Alg. |   Flags   |     Iterations      |  Salt Length  |  Salt   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// NSEC3PARAM is used in NSEC3-signed zones to indicate the parameters used
// for hashing owner names. It does not contain a Next Hashed Owner Name
// (unlike NSEC3).
type RecordNSEC3PARAM struct {
	HashAlgorithm uint8
	Flags         uint8
	Iterations    uint16
	Salt          []byte
	Types         []ResourceType
}

func (r RecordNSEC3PARAM) Type() ResourceType {
	return TYPE_NSEC3PARAM
}

func (r RecordNSEC3PARAM) String() string {
	typeNames := make([]string, 0, len(r.Types))
	for _, typ := range r.Types {
		typeNames = append(typeNames, typ.String())
	}
	return fmt.Sprintf("%d %d %d %s %s",
		r.HashAlgorithm,
		r.Flags,
		r.Iterations,
		hex.EncodeToString(r.Salt),
		strings.Join(typeNames, " "),
	)
}

func (r RecordNSEC3PARAM) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

func (r RecordNSEC3PARAM) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendUInt8(r.HashAlgorithm)
	size += w.AppendUInt8(r.Flags)
	size += w.AppendUInt16(r.Iterations)
	size += w.AppendUInt8(uint8(len(r.Salt)))
	size += w.AppendBytes(r.Salt)
	size += appendTypeBitMaps(w, r.Types)
	return size
}

func (r RecordNSEC3PARAM) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return r.AppendWireFormat(w, nil)
}

// MarshalJSON encodes the record as a JSON object.  Salt is encoded as a
// lower-case hexadecimal string, and types as an array of resource type names.
func (r RecordNSEC3PARAM) MarshalJSON() ([]byte, error) {
	typeNames := make([]string, 0, len(r.Types))
	for _, typ := range r.Types {
		typeNames = append(typeNames, typ.String())
	}
	return json.Marshal(map[string]any{
		"HashAlgorithm": r.HashAlgorithm,
		"Flags":         r.Flags,
		"Iterations":    r.Iterations,
		"Salt":          hex.EncodeToString(r.Salt),
		"Types":         typeNames,
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces.  Salt is taken from a hexadecimal string, and each type from a
// resource type name or a numeric code.
func (r *RecordNSEC3PARAM) UnmarshalJSON(data []byte) error {
	var fields struct {
		HashAlgorithm uint8      `json:"HashAlgorithm"`
		Flags         uint8      `json:"Flags"`
		Iterations    uint16     `json:"Iterations"`
		Salt          string     `json:"Salt"`
		Types         json.RawMessage `json:"Types"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse NSEC3PARAM record: %w", err)
	}
	salt, err := hex.DecodeString(fields.Salt)
	if err != nil {
		return fmt.Errorf("invalid NSEC3PARAM salt %q: %w", fields.Salt, err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(fields.Types, &items); err != nil {
		return fmt.Errorf("invalid NSEC3PARAM types: %w", err)
	}
	types := make([]ResourceType, 0, len(items))
	for _, item := range items {
		typ, err := decodeNSECTypeItem(item)
		if err != nil {
			return fmt.Errorf("invalid NSEC3PARAM type: %w", err)
		}
		types = append(types, typ)
	}
	*r = RecordNSEC3PARAM{
		HashAlgorithm: fields.HashAlgorithm,
		Flags:         fields.Flags,
		Iterations:    fields.Iterations,
		Salt:          salt,
		Types:         types,
	}
	return nil
}

// NewRecordNSEC3PARAM creates a new RecordNSEC3PARAM from structured values.
// The types are sorted for deterministic wire-format encoding.
func NewRecordNSEC3PARAM(hashAlgorithm uint8, flags uint8, iterations uint16,
	salt []byte, types []ResourceType) RecordNSEC3PARAM {
	sorted := make([]ResourceType, len(types))
	copy(sorted, types)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return RecordNSEC3PARAM{
		HashAlgorithm: hashAlgorithm,
		Flags:         flags,
		Iterations:    iterations,
		Salt:          salt,
		Types:         sorted,
	}
}

// NewRecordNSEC3PARAMFromString parses an NSEC3PARAM record from presentation format string
// Format: <hash-algorithm> <flags> <iterations> <salt-hex> <type> [<type> ...]
func NewRecordNSEC3PARAMFromString(s string) (RecordNSEC3PARAM, error) {
	fields := strings.Fields(s)
	if len(fields) < 5 {
		return RecordNSEC3PARAM{}, fmt.Errorf(`invalid NSEC3PARAM record format "%s"`, s)
	}

	hashAlgorithm, err := strconv.ParseUint(fields[0], 10, 8)
	if err != nil {
		return RecordNSEC3PARAM{}, fmt.Errorf(`invalid hash algorithm "%s"`, fields[0])
	}

	flags, err := strconv.ParseUint(fields[1], 10, 8)
	if err != nil {
		return RecordNSEC3PARAM{}, fmt.Errorf(`invalid flags "%s"`, fields[1])
	}

	iterations, err := strconv.ParseUint(fields[2], 10, 16)
	if err != nil {
		return RecordNSEC3PARAM{}, fmt.Errorf(`invalid iterations "%s"`, fields[2])
	}

	salt, err := hex.DecodeString(fields[3])
	if err != nil {
		return RecordNSEC3PARAM{}, fmt.Errorf(`invalid salt "%s"`, fields[3])
	}

	var types []ResourceType
	for _, f := range fields[4:] {
		typ, err := parseTypeString(f)
		if err != nil {
			return RecordNSEC3PARAM{}, err
		}
		types = append(types, typ)
	}

	return NewRecordNSEC3PARAM(
		uint8(hashAlgorithm),
		uint8(flags),
		uint16(iterations),
		salt,
		types,
	), nil
}

// ParseRecordNSEC3PARAM parses an NSEC3PARAM record from wire format. The type bit maps
// are bounded by end, the RDLENGTH-derived offset of the record, rather than
// the remainder of the whole message.
func ParseRecordNSEC3PARAM(w WireFormat, begin uint32, end uint32) (r RecordNSEC3PARAM, pos uint32, err error) {
	var p uint32 = begin

	// Hash Algorithm (1 octet)
	if p+1 > end {
		return r, begin, fmt.Errorf("cannot parse NSEC3PARAM hash algorithm")
	}
	hashAlgorithm, err := w.GetUInt8(p)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3PARAM hash algorithm: %w", err)
	}
	p++

	// Flags (1 octet)
	if p+1 > end {
		return r, begin, fmt.Errorf("cannot parse NSEC3PARAM flags")
	}
	flags, err := w.GetUInt8(p)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3PARAM flags: %w", err)
	}
	p++

	// Iterations (2 octets, network byte order)
	if p+2 > end {
		return r, begin, fmt.Errorf("cannot parse NSEC3PARAM iterations")
	}
	iterations, err := w.GetUInt16(p)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3PARAM iterations: %w", err)
	}
	p += 2

	// Salt Length (1 octet)
	if p+1 > end {
		return r, begin, fmt.Errorf("cannot parse NSEC3PARAM salt length")
	}
	saltLength, err := w.GetUInt8(p)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3PARAM salt length: %w", err)
	}
	p++

	// Salt (Salt Length octets)
	if p+uint32(saltLength) > end {
		return r, begin, fmt.Errorf("NSEC3PARAM salt extends beyond record")
	}
	salt := w[p : p+uint32(saltLength)]
	p += uint32(saltLength)

	// Type Bit Maps (remainder of the record, bounded by end)
	types, p, err := parseTypeBitMaps(w, p, end)
	if err != nil {
		return r, begin, fmt.Errorf("cannot parse NSEC3PARAM type bit maps: %w", err)
	}

	r = RecordNSEC3PARAM{
		HashAlgorithm: hashAlgorithm,
		Flags:         flags,
		Iterations:    iterations,
		Salt:          salt,
		Types:         types,
	}
	pos = p
	return
}
