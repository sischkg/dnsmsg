package dnsmsg

import (
	"encoding/json"
	"fmt"
)

// RecordCNAME represents a CNAME (canonical name) record per RFC 1035
// Section 3.3.1.
//
// CNAME RDATA wire format:
//
//	<the domain name the owner name is an alias for>
//
// The RDATA is a single domain name, so RDLENGTH depends on the length of
// the name itself (1 octet for the root alone) and a name written with a
// compression pointer is shorter on the wire than in presentation format.
type RecordCNAME struct {
	CNAME DomainName
}

func (r RecordCNAME) Type() ResourceType {
	return TYPE_CNAME
}

func (r RecordCNAME) String() string {
	return r.CNAME.String()
}

func (r RecordCNAME) CanonicalWireFormat() []byte {
	return r.CNAME.CanonicalWireFormat()
}

func (r RecordCNAME) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	return w.AppendDomainName(r.CNAME, db)
}

func (r RecordCNAME) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return w.AppendCanonicalDomainName(r.CNAME)
}

// MarshalJSON encodes the record as a JSON object.  The canonical name is
// encoded as its presentation-format string.
func (r RecordCNAME) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"CNAME": r.CNAME,
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces, taking the canonical name from its presentation-format string.
func (r *RecordCNAME) UnmarshalJSON(data []byte) error {
	var fields struct {
		CNAME DomainName `json:"CNAME"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse CNAME record: %w", err)
	}
	r.CNAME = fields.CNAME
	return nil
}

// NewRecordCNAME creates a new RecordCNAME from the canonical name it points
// to.
func NewRecordCNAME(cname DomainName) RecordCNAME {
	return RecordCNAME{CNAME: cname}
}

// NewRecordCNAMEFromString parses a CNAME record from a presentation-format
// string.  Format: <cname>
func NewRecordCNAMEFromString(s string) (r RecordCNAME, err error) {
	name, err := NewDomainNameFromString(s)
	if err != nil {
		return
	}
	return NewRecordCNAME(name), nil
}

// ParseRecordCNAME parses a CNAME record from the wire format at begin,
// following compression pointers.  It returns the record and the offset just
// past the domain name it read.
func ParseRecordCNAME(w WireFormat, begin uint32) (r RecordCNAME, end uint32, err error) {
	cname, end, err := NewDomainNameFromCompressedWireFormat(&w, begin)
	if err != nil {
		err = fmt.Errorf("cannot parse cname: %w", err)
		return
	}
	return NewRecordCNAME(cname), end, nil
}
