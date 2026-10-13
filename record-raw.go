package dnsmsg

import (
	"encoding/json"
	"fmt"
)

type RecordRaw struct {
	Data  []byte
	rtype ResourceType
}

func (a RecordRaw) Type() ResourceType {
	return a.rtype
}

func (a RecordRaw) String() string {
	return "raw"
}

func (a RecordRaw) CanonicalWireFormat() []byte {
	return a.Data
}

func (a RecordRaw) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	return w.AppendBytes(a.Data)
}

func (a RecordRaw) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return w.AppendBytes(a.Data)
}

// MarshalJSON encodes the record as a JSON object.  The raw RDATA is
// encoded as a base64 string and the record type as a type name.
func (a RecordRaw) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"Data":  encodeBase64(a.Data),
		"rtype": a.rtype.String(),
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces, taking the raw RDATA from its base64 string and the record
// type from its type name.  When the record is decoded as part of a
// ResourceRecord the enclosing record type takes precedence.
func (a *RecordRaw) UnmarshalJSON(data []byte) error {
	var fields struct {
		Data  string          `json:"Data"`
		RType json.RawMessage `json:"rtype"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse raw record: %w", err)
	}
	rawData, err := decodeBase64(fields.Data)
	if err != nil {
		return fmt.Errorf("invalid raw record data: %w", err)
	}
	rtype := ResourceType(0)
	if len(fields.RType) != 0 {
		rtype, err = decodeResourceType(fields.RType)
		if err != nil {
			return fmt.Errorf("invalid raw record type: %w", err)
		}
	}
	a.Data = rawData
	a.rtype = rtype
	return nil
}

func NewRecordRaw(rtype ResourceType, data []byte) (r RecordRaw) {
	r.Data = data
	r.rtype = rtype
	return
}

func ParseRecordRaw(msg WireFormat, begin uint32, end uint32, rtype ResourceType) (RecordRaw, uint32, error) {
	if end > uint32(msg.Size()) {
		return NewRecordRaw(rtype, []byte{}), begin, fmt.Errorf("invalid A record RDATA size")
	}

	return NewRecordRaw(rtype, msg[begin:end]), end, nil
}
