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

func NewRecordRaw(rtype ResourceType, data []byte) (r RecordRaw) {
	r.Data = data
	return
}

func ParseRecordRaw(msg WireFormat, begin uint32, end uint32, rtype ResourceType) (RecordRaw, uint32, error) {
	if end > uint32(msg.Size()) {
		return NewRecordRaw(rtype, []byte{}), begin, fmt.Errorf("invalid A record RDATA size")
	}

	return NewRecordRaw(rtype, msg[begin:end]), end, nil
}
