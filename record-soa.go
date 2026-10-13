package dnsmsg

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

type RecordSOA struct {
	mname   DomainName
	rname   DomainName
	serial  uint32
	refresh uint32
	retry   uint32
	expire  uint32
	minimum uint32
}

func (soa RecordSOA) Type() ResourceType {
	return TYPE_SOA
}

func (soa RecordSOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", soa.mname.String(), soa.rname.String(), soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum)
}

func (lhs RecordSOA) Equal(rhs RecordSOA) bool {
	return lhs.mname.Equal(rhs.mname) && lhs.rname.Equal(rhs.rname) &&
		lhs.serial == rhs.serial && lhs.refresh == rhs.refresh &&
		lhs.retry == rhs.retry && lhs.expire == rhs.expire &&
		lhs.minimum == rhs.minimum
}

func (a RecordSOA) Size(w WireFormat, db *NameCompressionDB) uint32 {
	// Compute the actual RDATA size: two domain names + 5 × 4 bytes for timers
	return a.mname.Size() + a.rname.Size() + 5*4
}

func (soa RecordSOA) CanonicalWireFormat() []byte {
	var w WireFormat
	w.AppendCanonicalDomainName(soa.mname)
	w.AppendCanonicalDomainName(soa.rname)
	w.AppendUInt32(soa.serial)
	w.AppendUInt32(soa.refresh)
	w.AppendUInt32(soa.retry)
	w.AppendUInt32(soa.expire)
	w.AppendUInt32(soa.minimum)
	return w
}

func (soa RecordSOA) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendDomainName(soa.mname, db)
	size += w.AppendDomainName(soa.rname, db)
	size += w.AppendUInt32(soa.serial)
	size += w.AppendUInt32(soa.refresh)
	size += w.AppendUInt32(soa.retry)
	size += w.AppendUInt32(soa.expire)
	size += w.AppendUInt32(soa.minimum)

	return size
}

func (soa RecordSOA) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	var size uint32 = 0
	size += w.AppendCanonicalDomainName(soa.mname)
	size += w.AppendCanonicalDomainName(soa.rname)
	size += w.AppendUInt32(soa.serial)
	size += w.AppendUInt32(soa.refresh)
	size += w.AppendUInt32(soa.retry)
	size += w.AppendUInt32(soa.expire)
	size += w.AppendUInt32(soa.minimum)

	return size
}

func NewRecordSOAFromString(s string) (soa RecordSOA, err error) {
	pattern, err := regexp.Compile(`\A(?P<mname>\S+)\s+(?P<rname>\S+)\s+(?P<serial>\d+)\s+(?P<refresh>\d+)\s+(?P<retry>\d+)\s+(?P<expire>\d+)\s+(?P<minimum>\d+)\z`)
	if err != nil {
		return
	}
	matched := pattern.FindStringSubmatch(s)
	if matched == nil {
		err = fmt.Errorf(`cannot parse SOA record "%s"`, s)
		return
	}
	mname, err := NewDomainNameFromString(matched[pattern.SubexpIndex("mname")])
	if err != nil {
		err = fmt.Errorf("cannot parse mname of SOA: %v", err)
		return
	}
	rname, err := NewDomainNameFromString(matched[pattern.SubexpIndex("rname")])
	if err != nil {
		err = fmt.Errorf("cannot parse rname of SOA: %v", err)
		return
	}
	serial, _ := strconv.ParseUint(matched[pattern.SubexpIndex("serial")], 10, 32)
	refresh, _ := strconv.ParseUint(matched[pattern.SubexpIndex("refresh")], 10, 32)
	retry, _ := strconv.ParseUint(matched[pattern.SubexpIndex("retry")], 10, 32)
	expire, _ := strconv.ParseUint(matched[pattern.SubexpIndex("expire")], 10, 32)
	minimum, _ := strconv.ParseUint(matched[pattern.SubexpIndex("minimum")], 10, 32)

	soa = NewRecordSOA(mname, rname, uint32(serial), uint32(refresh), uint32(retry), uint32(expire), uint32(minimum))
	err = nil
	return
}

// MarshalJSON encodes the record as a JSON object.  The management and
// owner names are encoded as presentation-format strings and the timer
// fields as numbers.
func (soa RecordSOA) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"mname":   soa.mname,
		"rname":   soa.rname,
		"serial":  soa.serial,
		"refresh": soa.refresh,
		"retry":   soa.retry,
		"expire":  soa.expire,
		"minimum": soa.minimum,
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces, taking the management and owner names from their
// presentation-format strings and the timer fields as numbers.
func (soa *RecordSOA) UnmarshalJSON(data []byte) error {
	var fields struct {
		MName   DomainName `json:"mname"`
		RName   DomainName `json:"rname"`
		Serial  uint32     `json:"serial"`
		Refresh uint32     `json:"refresh"`
		Retry   uint32     `json:"retry"`
		Expire  uint32     `json:"expire"`
		Minimum uint32     `json:"minimum"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse SOA record: %w", err)
	}
	*soa = RecordSOA{
		mname:   fields.MName,
		rname:   fields.RName,
		serial:  fields.Serial,
		refresh: fields.Refresh,
		retry:   fields.Retry,
		expire:  fields.Expire,
		minimum: fields.Minimum,
	}
	return nil
}

func NewRecordSOA(mname, rname DomainName, serial, refresh, retry, expire, minimum uint32) (soa RecordSOA) {
	soa.mname = mname
	soa.rname = rname
	soa.serial = serial
	soa.refresh = refresh
	soa.retry = retry
	soa.expire = expire
	soa.minimum = minimum
	return
}

func ParseRecordSOA(w WireFormat, begin uint32) (soa RecordSOA, end uint32, err error) {
	var p uint32
	soa.mname, p, err = NewDomainNameFromCompressedWireFormat(&w, begin)
	if err != nil {
		return
	}
	soa.rname, p, err = NewDomainNameFromCompressedWireFormat(&w, p)
	if err != nil {
		return
	}

	if p+20 > w.Size() {
		err = fmt.Errorf("too few message size for SOA")
		return
	}

	serial, err := w.GetUInt32(p)
	if err != nil {
		return
	}
	p += 4
	soa.serial = serial
	refresh, err := w.GetUInt32(p)
	if err != nil {
		return
	}
	p += 4
	soa.refresh = refresh
	retry, err := w.GetUInt32(p)
	if err != nil {
		return
	}
	p += 4
	soa.retry = retry
	expire, err := w.GetUInt32(p)
	if err != nil {
		return
	}
	p += 4
	soa.expire = expire
	minimum, err := w.GetUInt32(p)
	if err != nil {
		return
	}
	p += 4
	soa.minimum = minimum

	end = p
	return
}
