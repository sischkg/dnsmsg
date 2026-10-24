package dnsmsg

// RecordHTTPS represents a HTTPS record (RFC 9460 Section 3), the service binding
// of an HTTP or HTTPS service.  Its RDATA has exactly the layout of a SVCB
// record, so RecordHTTPS embeds RecordSVCB and takes its presentation format,
// wire format, and JSON methods from it unchanged: only the record type
// differs.
//
// The SvcParams are held in the strictly increasing SvcParamKey order the wire
// format requires (RFC 9460 Section 2.2).  NewRecordHTTPS,
// NewRecordHTTPSFromParams, and NewRecordHTTPSFromString sort the params they
// are given, so a caller may hand them over in any order.
//
// The SvcParamKeys registered for HTTPS records (RFC 9460 Section 7.2.1) are
// the ones RecordSVCB documents, and a key this library does not register is
// kept with its uninterpreted value.
type RecordHTTPS struct {
	RecordSVCB
}

// Type returns TYPE_HTTPS.  It is the one method RecordHTTPS does not take from
// the embedded RecordSVCB.
func (r RecordHTTPS) Type() ResourceType {
	return TYPE_HTTPS
}

// ParseRecordHTTPS reads a HTTPS record from the wire format.  The RDATA is
// read from begin up to end, the RDLENGTH-derived end of the RDATA, so the
// parsed record is bounded by its own RDLENGTH rather than by the remainder of
// the message.  An RDATA that ends within a SvcParam, whose SvcParamKeys are
// not in strictly increasing order, whose SvcParams repeat a key, or whose
// SvcParams are not the ones its SvcPriority allows is malformed (RFC 9460
// Section 2.2, Section 2.4.1, Section 8).
func ParseRecordHTTPS(w WireFormat, begin, end uint32) (r RecordHTTPS, next uint32, err error) {
	rec, next, err := parseSvcBRecord(w, begin, end, TYPE_HTTPS)
	if err != nil {
		return RecordHTTPS{}, next, err
	}
	return RecordHTTPS{rec}, next, nil
}

// NewRecordHTTPS returns the HTTPS record with the given priority, target name,
// and SvcParams, which may be given in any order: they are sorted into the
// increasing key order the wire format requires.  A record in AliasMode, with
// SvcPriority 0, MUST NOT have SvcParams (RFC 9460 Section 2.4.1).
func NewRecordHTTPS(svcPriority uint16, targetName DomainName, params ...SvcParam) (RecordHTTPS, error) {
	rec, err := newSvcBRecord(svcPriority, targetName, params...)
	if err != nil {
		return RecordHTTPS{}, err
	}
	return RecordHTTPS{rec}, nil
}

// NewRecordHTTPSFromParams returns the HTTPS record whose SvcParams are given
// in the presentation form of their keys, as a zone file writes them.  The
// target name is given in presentation format.
func NewRecordHTTPSFromParams(svcPriority uint16, targetName string, params map[string]string) (RecordHTTPS, error) {
	rec, err := newSvcBRecordFromParams(svcPriority, targetName, params)
	if err != nil {
		return RecordHTTPS{}, err
	}
	return RecordHTTPS{rec}, nil
}

// NewRecordHTTPSFromString parses a HTTPS record from a presentation-format
// string such as "1 svc.example.com. alpn=h2,port=8443"
// (RFC 9460 Section 2.1), which is the form RecordHTTPS.String writes; a value
// written as a quoted character-string, such as alpn="h2,h3", is read as well.
// The SvcParams may appear in any order, but a key may not appear twice.
func NewRecordHTTPSFromString(s string) (RecordHTTPS, error) {
	rec, err := newSvcBRecordFromString(s, TYPE_HTTPS)
	if err != nil {
		return RecordHTTPS{}, err
	}
	return RecordHTTPS{rec}, nil
}

// UnmarshalJSON decodes the record from the JSON object the embedded MarshalJSON
// writes.  Only the record named in an error differs from the embedded
// RecordSVCB's own UnmarshalJSON, which names a SVCB record.
func (r *RecordHTTPS) UnmarshalJSON(data []byte) error {
	rec, err := unmarshalSvcBJSON(data, TYPE_HTTPS)
	if err != nil {
		return err
	}
	r.RecordSVCB = rec
	return nil
}
