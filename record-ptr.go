package dnsmsg

import (
	"encoding/json"
	"fmt"
)

// RecordPTR represents a PTR (domain name pointer) record per RFC 1035
// Section 3.3.12.
//
// PTR RDATA wire format:
//
//	<the domain name the owner name points to>
//
// The RDATA is a single domain name, so RDLENGTH depends on the length of
// the name itself (1 octet for the root alone) and a name written with a
// compression pointer is shorter on the wire than in presentation format.
//
// RFC 1035 Section 3.3 states that NS, SOA, CNAME and PTR records have the
// same format in every class, so the domain name in their RDATA may be
// compressed.
type RecordPTR struct {
	PTR DomainName
}

func (r RecordPTR) Type() ResourceType {
	return TYPE_PTR
}

func (r RecordPTR) String() string {
	return r.PTR.String()
}

func (r RecordPTR) CanonicalWireFormat() []byte {
	return r.PTR.CanonicalWireFormat()
}

func (r RecordPTR) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	return w.AppendDomainName(r.PTR, db)
}

func (r RecordPTR) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return w.AppendCanonicalDomainName(r.PTR)
}

// MarshalJSON encodes the record as a JSON object.  The pointed-to name is
// encoded as its presentation-format string.
func (r RecordPTR) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"PTR": r.PTR,
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces, taking the pointed-to name from its presentation-format string.
func (r *RecordPTR) UnmarshalJSON(data []byte) error {
	var fields struct {
		PTR DomainName `json:"PTR"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse PTR record: %w", err)
	}
	r.PTR = fields.PTR
	return nil
}

// NewRecordPTR creates a new RecordPTR from the name the owner name points
// to.
func NewRecordPTR(ptr DomainName) RecordPTR {
	return RecordPTR{PTR: ptr}
}

// NewRecordPTRFromString parses a PTR record from a presentation-format
// string.  Format: <ptr>
func NewRecordPTRFromString(s string) (r RecordPTR, err error) {
	name, err := NewDomainNameFromString(s)
	if err != nil {
		return
	}
	return NewRecordPTR(name), nil
}

// ParseRecordPTR parses a PTR record from the wire format at begin,
// following compression pointers.  It returns the record and the offset just
// past the domain name it read.
func ParseRecordPTR(w WireFormat, begin uint32) (r RecordPTR, end uint32, err error) {
	ptr, end, err := NewDomainNameFromCompressedWireFormat(&w, begin)
	if err != nil {
		err = fmt.Errorf("cannot parse ptr: %w", err)
		return
	}
	return NewRecordPTR(ptr), end, nil
}
