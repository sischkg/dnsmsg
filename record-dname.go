package dnsmsg

import (
	"encoding/json"
	"fmt"
)

// RecordDNAME represents a DNAME (delegation of a name subtree) record per
// RFC 6672 Section 4.
//
// DNAME RDATA wire format:
//
//	<the target domain name the subtree below the owner name is redirected to>
//
// The RDATA is a single domain name, so RDLENGTH depends on the length of
// the name itself (1 octet for the root alone) and a name written with a
// compression pointer is shorter on the wire than in presentation format.
type RecordDNAME struct {
	DNAME DomainName
}

func (r RecordDNAME) Type() ResourceType {
	return TYPE_DNAME
}

func (r RecordDNAME) String() string {
	return r.DNAME.String()
}

func (r RecordDNAME) CanonicalWireFormat() []byte {
	return r.DNAME.CanonicalWireFormat()
}

func (r RecordDNAME) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	return w.AppendDomainName(r.DNAME, db)
}

func (r RecordDNAME) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return w.AppendCanonicalDomainName(r.DNAME)
}

// MarshalJSON encodes the record as a JSON object.  The target name is
// encoded as its presentation-format string.
func (r RecordDNAME) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"DNAME": r.DNAME,
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces, taking the target name from its presentation-format string.
func (r *RecordDNAME) UnmarshalJSON(data []byte) error {
	var fields struct {
		DNAME DomainName `json:"DNAME"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse DNAME record: %w", err)
	}
	r.DNAME = fields.DNAME
	return nil
}

// NewRecordDNAME creates a new RecordDNAME from the target name its subtree
// is redirected to.
func NewRecordDNAME(dname DomainName) RecordDNAME {
	return RecordDNAME{DNAME: dname}
}

// NewRecordDNAMEFromString parses a DNAME record from a presentation-format
// string.  Format: <target>
func NewRecordDNAMEFromString(s string) (r RecordDNAME, err error) {
	name, err := NewDomainNameFromString(s)
	if err != nil {
		return
	}
	return NewRecordDNAME(name), nil
}

// ParseRecordDNAME parses a DNAME record from the wire format at begin,
// following compression pointers.  It returns the record and the offset just
// past the domain name it read.
func ParseRecordDNAME(w WireFormat, begin uint32) (r RecordDNAME, end uint32, err error) {
	dname, end, err := NewDomainNameFromCompressedWireFormat(&w, begin)
	if err != nil {
		err = fmt.Errorf("cannot parse dname: %w", err)
		return
	}
	return NewRecordDNAME(dname), end, nil
}
