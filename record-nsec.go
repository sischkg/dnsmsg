package dnsmsg

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// RecordNSEC represents an NSEC (Next Secure) record per RFC 4034 Section 5.2.
//
// NSEC RDATA wire format:
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   /                     Next Domain Name /                                \
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   /                     Type Bit Maps /                                     \
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// The Next Domain Name is the owner name of the next NSEC record in
// canonical order. The Type Bit Maps identify the set of RR types present
// at the owner name.
type RecordNSEC struct {
	NextDomainName DomainName
	Types          []ResourceType
}

func (r RecordNSEC) Type() ResourceType {
	return TYPE_NSEC
}

func (r RecordNSEC) String() string {
	typeNames := make([]string, 0, len(r.Types))
	for _, typ := range r.Types {
		typeNames = append(typeNames, typ.String())
	}
	return fmt.Sprintf("%s %s", r.NextDomainName.String(), strings.Join(typeNames, " "))
}

func (r RecordNSEC) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

func (r RecordNSEC) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendDomainName(r.NextDomainName, db)
	size += appendTypeBitMaps(w, r.Types)
	return size
}

func (r RecordNSEC) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	var size uint32 = 0
	size += w.AppendCanonicalDomainName(r.NextDomainName)
	size += appendTypeBitMaps(w, r.Types)
	return size
}

// MarshalJSON encodes the record as a JSON object.  The next domain name is
// encoded as its presentation-format string and the types as an array of
// resource type names.
func (r RecordNSEC) MarshalJSON() ([]byte, error) {
	typeNames := make([]string, 0, len(r.Types))
	for _, typ := range r.Types {
		typeNames = append(typeNames, typ.String())
	}
	return json.Marshal(map[string]any{
		"NextDomainName": r.NextDomainName,
		"Types":          typeNames,
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces.  The next domain name is taken from its presentation-format
// string and each type from a resource type name or a numeric code.
func (r *RecordNSEC) UnmarshalJSON(data []byte) error {
	var fields struct {
		NextDomainName DomainName      `json:"NextDomainName"`
		Types          json.RawMessage `json:"Types"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse NSEC record: %w", err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(fields.Types, &items); err != nil {
		return fmt.Errorf("invalid NSEC types: %w", err)
	}
	types := make([]ResourceType, 0, len(items))
	for _, item := range items {
		typ, err := decodeNSECTypeItem(item)
		if err != nil {
			return fmt.Errorf("invalid NSEC type: %w", err)
		}
		types = append(types, typ)
	}
	*r = RecordNSEC{
		NextDomainName: fields.NextDomainName,
		Types:          types,
	}
	return nil
}

// NewRecordNSEC creates a new RecordNSEC from structured values.  The types
// are sorted for deterministic wire-format encoding.
func NewRecordNSEC(nextDomainName DomainName, types []ResourceType) RecordNSEC {
	sorted := make([]ResourceType, len(types))
	copy(sorted, types)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return RecordNSEC{
		NextDomainName: nextDomainName,
		Types:          sorted,
	}
}

// NewRecordNSECFromString parses an NSEC record from presentation format string
// Format: <next-domain-name> <type> [<type> ...]
func NewRecordNSECFromString(s string) (RecordNSEC, error) {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return RecordNSEC{}, fmt.Errorf(`invalid NSEC record format "%s"`, s)
	}

	nextDomainName, err := NewDomainNameFromString(fields[0])
	if err != nil {
		return RecordNSEC{}, fmt.Errorf(`invalid next domain name "%s"`, fields[0])
	}

	var types []ResourceType
	for _, f := range fields[1:] {
		typ, err := parseTypeString(f)
		if err != nil {
			return RecordNSEC{}, err
		}
		types = append(types, typ)
	}

	return NewRecordNSEC(nextDomainName, types), nil
}

// ParseRecordNSEC parses an NSEC record from wire format. The type bit maps
// are bounded by end, the RDLENGTH-derived offset of the record, rather than
// the remainder of the whole message.
func ParseRecordNSEC(w WireFormat, begin uint32, end uint32) (r RecordNSEC, pos uint32, err error) {
	var p uint32 = begin

	nextDomainName, p, err := NewDomainNameFromCompressedWireFormat(&w, p)
	if err != nil {
		err = fmt.Errorf("cannot parse next domain name: %w", err)
		return
	}

	types, p, err := parseTypeBitMaps(w, p, end)
	if err != nil {
		err = fmt.Errorf("cannot parse type bit maps: %w", err)
		return
	}

	r = RecordNSEC{
		NextDomainName: nextDomainName,
		Types:          types,
	}
	pos = p
	return
}

// parseTypeString parses a single type from a presentation-format token,
// accepting either a numeric code ("32") or a type name ("NSEC", "TYPE32").
func parseTypeString(s string) (ResourceType, error) {
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return ResourceType(n), nil
	}
	return NewType(s)
}

// decodeNSECTypeItem decodes a single NSEC type from a JSON value, accepting
// either a type name string or a numeric code.
func decodeNSECTypeItem(data json.RawMessage) (ResourceType, error) {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return NewType(s)
	}
	var n uint16
	if err := json.Unmarshal(data, &n); err != nil {
		return 0, fmt.Errorf("invalid NSEC type %s", data)
	}
	return ResourceType(n), nil
}

// appendTypeBitMaps appends the NSEC type bit maps for the given types to w
// and returns the number of octets written.  Windows are emitted in ascending
// order and windows with no types are omitted.  Within each window the bitmap
// is trimmed to the minimum length needed to cover the highest present type.
func appendTypeBitMaps(w *WireFormat, types []ResourceType) uint32 {
	var size uint32 = 0

	// Group types by window (type / 256).
	windows := make(map[uint8][]uint8)
	for _, typ := range types {
		window := uint8(typ >> 8)
		offset := uint8(typ & 0xff)
		windows[window] = append(windows[window], offset)
	}

	// Emit windows in ascending order.
	var windowNums []uint8
	for window := range windows {
		windowNums = append(windowNums, window)
	}
	sort.Slice(windowNums, func(i, j int) bool { return windowNums[i] < windowNums[j] })

	for _, window := range windowNums {
		offsets := windows[window]
		sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })

		// The bitmap length covers the highest present type, rounded up to a
		// whole octet.  At least one octet is required.
		maxOffset := offsets[len(offsets)-1]
		length := (maxOffset+1+7) / 8
		if length > 32 {
			length = 32
		}

		bitmap := make([]byte, length)
		for _, offset := range offsets {
			octet := offset / 8
			// Bit 7 (MSB) of the octet corresponds to the lowest type in the
			// octet group; bit 0 (LSB) to the highest.
			bitmap[octet] |= 1 << (7 - uint(offset%8))
		}

		size += w.AppendUInt8(window)
		size += w.AppendUInt8(length)
		size += w.AppendBytes(bitmap)
	}
	return size
}

// parseTypeBitMaps parses NSEC type bit maps from w over [begin, end) and
// returns the sorted list of RR types present.
func parseTypeBitMaps(w WireFormat, begin uint32, end uint32) ([]ResourceType, uint32, error) {
	var p uint32 = begin
	types := make([]ResourceType, 0)

	for p < end {
		if p+2 > end {
			return nil, p, fmt.Errorf("cannot parse NSEC type bitmap window header")
		}
		window, err := w.GetUInt8(p)
		if err != nil {
			return nil, p, fmt.Errorf("cannot parse NSEC type bitmap window: %w", err)
		}
		p++
		length, err := w.GetUInt8(p)
		if err != nil {
			return nil, p, fmt.Errorf("cannot parse NSEC type bitmap length: %w", err)
		}
		p++
		if length == 0 || length > 32 {
			return nil, p, fmt.Errorf("invalid NSEC type bitmap length %d", length)
		}
		if p+uint32(length) > end {
			return nil, p, fmt.Errorf("NSEC type bitmap extends beyond record")
		}
		bitmap := w[p : p+uint32(length)]
		p += uint32(length)

		base := uint32(window) * 256
		for i, b := range bitmap {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<uint(7-bit)) != 0 {
					types = append(types, ResourceType(base+uint32(i)*8+uint32(bit)))
				}
			}
		}
	}

	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types, p, nil
}
