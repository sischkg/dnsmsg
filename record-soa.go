package dnsmsg

import (
	"fmt"
	"regexp"
	"strconv"
)

type RecordSOA struct {
	mname   Domainname
	rname   Domainname
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

func (soa RecordSOA) CanonicalWireFormat() []byte {
	var w WireFormat
	w.AppendCanonicalDomainname(soa.mname)
	w.AppendCanonicalDomainname(soa.rname)
	w.AppendUInt32(soa.serial)
	w.AppendUInt32(soa.refresh)
	w.AppendUInt32(soa.retry)
	w.AppendUInt32(soa.expire)
	w.AppendUInt32(soa.minimum)
	return w
}

func (soa RecordSOA) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendDomainname(soa.mname, db)
	size += w.AppendDomainname(soa.rname, db)
	size += w.AppendUInt32(soa.serial)
	size += w.AppendUInt32(soa.refresh)
	size += w.AppendUInt32(soa.retry)
	size += w.AppendUInt32(soa.expire)
	size += w.AppendUInt32(soa.minimum)

	return size
}

func (soa RecordSOA) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	var size uint32 = 0
	size += w.AppendCanonicalDomainname(soa.mname)
	size += w.AppendCanonicalDomainname(soa.rname)
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
	mname, err := NewDomainname(matched[pattern.SubexpIndex("mname")])
	if err != nil {
		err = fmt.Errorf("cannot parse mname of SOA: %v", err)
		return
	}
	rname, err := NewDomainname(matched[pattern.SubexpIndex("rname")])
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

func NewRecordSOA(mname, rname Domainname, serial, refresh, retry, expire, minimum uint32) (soa RecordSOA) {
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
	soa.mname, p, err = NewDomainnameFromWireFormat(w, begin)
	if err != nil {
		return
	}
	soa.rname, p, err = NewDomainnameFromWireFormat(w, p)
	if err != nil {
		return
	}

	if p+20 > w.Size() {
		err = fmt.Errorf("too few message size for SOA")
	}

	serial, _ := w.GetUInt32(p)
	p += 4
	soa.serial = serial
	refresh, _ := w.GetUInt32(p)
	p += 4
	soa.refresh = refresh
	retry, _ := w.GetUInt32(p)
	p += 4
	soa.retry = retry
	expire, _ := w.GetUInt32(p)
	p += 4
	soa.expire = expire
	minimum, _ := w.GetUInt32(p)
	p += 4
	soa.minimum = minimum

	end = p
	return
}
