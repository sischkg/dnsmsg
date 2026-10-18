package dnsmsg

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"
	"time"
)

// TSIGAlgorithm is the name of a shared-secret algorithm used to compute the
// MAC of a TSIG record (RFC 8945 Section 6.1).
type TSIGAlgorithm string

// The algorithm names are stored exactly as they appear on the wire, with the
// root label included.
const (
	TSIGAlgHMACMD5        TSIGAlgorithm = "HMAC-MD5.SIG-ALG.REG.INT."
	TSIGAlgHMACSHA1       TSIGAlgorithm = "hmac-sha1."
	TSIGAlgHMACSHA224     TSIGAlgorithm = "hmac-sha224."
	TSIGAlgHMACSHA256     TSIGAlgorithm = "hmac-sha256."
	TSIGAlgHMACSHA256_128 TSIGAlgorithm = "hmac-sha256-128."
	TSIGAlgHMACSHA384     TSIGAlgorithm = "hmac-sha384."
	TSIGAlgHMACSHA384_192 TSIGAlgorithm = "hmac-sha384-192."
	TSIGAlgHMACSHA512     TSIGAlgorithm = "hmac-sha512."
	TSIGAlgHMACSHA512_256 TSIGAlgorithm = "hmac-sha512-256."
)

// TSIGDefaultFudge is the Fudge value used when a TSIGOptions does not set one.
// RFC 8945 recommends a default of 5 minutes.
const TSIGDefaultFudge uint16 = 300

// tsigAlgorithmInfo describes how to compute the keyed hash of an algorithm and
// how long its MACs are allowed to be.
type tsigAlgorithmInfo struct {
	algorithm TSIGAlgorithm
	newHash   func() hash.Hash
	hashLen   int
	macLen    int
}

// minMACLen returns the shortest MAC the algorithm accepts: the larger of 10
// octets and half the length of the hash function (RFC 8945 Section 5.2.2.1).
func (ai tsigAlgorithmInfo) minMACLen() int {
	half := ai.hashLen / 2
	if half < 10 {
		return 10
	}
	return half
}

// The truncated algorithms (hmac-sha256-128 and so on) are the same hash
// function with a fixed MAC size, so their minimum and maximum MAC lengths are
// equal.
var tsigAlgorithmTable = map[string]tsigAlgorithmInfo{
	"hmac-md5.sig-alg.reg.int": {TSIGAlgHMACMD5, md5.New, md5.Size, 16},
	"hmac-sha1":                {TSIGAlgHMACSHA1, sha1.New, sha1.Size, 20},
	"hmac-sha224":              {TSIGAlgHMACSHA224, sha256.New224, 28, 28},
	"hmac-sha256":              {TSIGAlgHMACSHA256, sha256.New, sha256.Size, 32},
	"hmac-sha256-128":          {TSIGAlgHMACSHA256_128, sha256.New, sha256.Size, 16},
	"hmac-sha384":              {TSIGAlgHMACSHA384, sha512.New384, 48, 48},
	"hmac-sha384-192":          {TSIGAlgHMACSHA384_192, sha512.New384, 48, 24},
	"hmac-sha512":              {TSIGAlgHMACSHA512, sha512.New, sha512.Size, 64},
	"hmac-sha512-256":          {TSIGAlgHMACSHA512_256, sha512.New, sha512.Size, 32},
}

// tsigAlgorithmKey normalizes an algorithm name for a lookup in
// tsigAlgorithmTable.
func tsigAlgorithmKey(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// info returns the properties of the algorithm, or false if this implementation
// does not know it.
func (a TSIGAlgorithm) info() (tsigAlgorithmInfo, bool) {
	ai, ok := tsigAlgorithmTable[tsigAlgorithmKey(string(a))]
	return ai, ok
}

// String returns the canonical form of the algorithm name, with the root label
// included.  Algorithm names this implementation does not know are returned
// unchanged.
func (a TSIGAlgorithm) String() string {
	if ai, ok := a.info(); ok {
		return string(ai.algorithm)
	}
	return string(a)
}

// DomainName returns the algorithm as a DomainName in its canonical form.  An
// algorithm name which cannot be parsed becomes the root domain name.
func (a TSIGAlgorithm) DomainName() DomainName {
	name, err := NewDomainNameFromString(a.String())
	if err != nil {
		return NewRootDomainName()
	}
	return name
}

// HashLen returns the length in octets of the hash function the algorithm is
// built from.  Unknown algorithms have no hash function and return 0.
func (a TSIGAlgorithm) HashLen() int {
	ai, ok := a.info()
	if !ok {
		return 0
	}
	return ai.hashLen
}

// MACLen returns the longest MAC the algorithm produces: the length of the
// untruncated keyed hash.  Unknown algorithms return 0.
func (a TSIGAlgorithm) MACLen() int {
	ai, ok := a.info()
	if !ok {
		return 0
	}
	return ai.macLen
}

// minMACLen returns the shortest MAC the algorithm accepts.  Unknown algorithms
// return 0.
func (a TSIGAlgorithm) minMACLen() int {
	ai, ok := a.info()
	if !ok {
		return 0
	}
	return ai.minMACLen()
}

// NewTSIGAlgorithm returns the canonical form of a TSIG algorithm name.  The
// name may be given in any case and with or without the root label.  Names this
// implementation does not implement are returned as they were given, so that a
// peer using an unsupported algorithm can still be reported as BADKEY.
func NewTSIGAlgorithm(s string) (TSIGAlgorithm, error) {
	if ai, ok := tsigAlgorithmTable[tsigAlgorithmKey(s)]; ok {
		return ai.algorithm, nil
	}
	if _, err := NewDomainNameFromString(s); err != nil {
		return "", fmt.Errorf("invalid TSIG algorithm name: %s", err)
	}
	return TSIGAlgorithm(s), nil
}

// A TSIGKey is the shared secret a TSIG record is computed with.
type TSIGKey struct {
	Name      DomainName
	Algorithm TSIGAlgorithm
	Secret    []byte

	// MACLen is the MAC length to use when signing.  Zero means the longest
	// MAC the algorithm allows.
	MACLen int

	// MinMACLen is the shortest MAC this key will accept when verifying.  Zero
	// means every MAC length the algorithm allows.
	MinMACLen int
}

// NewTSIGKey returns a key which uses the longest MAC its algorithm allows.
func NewTSIGKey(name DomainName, algorithm TSIGAlgorithm, secret []byte) (TSIGKey, error) {
	key := TSIGKey{
		Name:      name,
		Algorithm: algorithm,
		Secret:    secret,
	}
	if err := key.validate(); err != nil {
		return TSIGKey{}, err
	}
	return key, nil
}

// NewTSIGKeyFromString returns a key from a key name, an algorithm name and a
// secret in base64 presentation format.
func NewTSIGKeyFromString(name, algorithm, secret string) (TSIGKey, error) {
	keyName, err := NewDomainNameFromString(name)
	if err != nil {
		return TSIGKey{}, fmt.Errorf("invalid TSIG key name: %s", err)
	}
	tsigAlgorithm, err := NewTSIGAlgorithm(algorithm)
	if err != nil {
		return TSIGKey{}, err
	}
	rawSecret, err := decodeBase64(secret)
	if err != nil {
		return TSIGKey{}, fmt.Errorf("invalid TSIG key secret: %s", err)
	}
	return NewTSIGKey(keyName, tsigAlgorithm, rawSecret)
}

// validate reports whether the key and its MAC length preferences are usable.
func (k TSIGKey) validate() error {
	if k.Name.Size() == 0 {
		return fmt.Errorf("TSIG key name is empty")
	}
	ai, ok := k.Algorithm.info()
	if !ok {
		return fmt.Errorf("unsupported TSIG algorithm: %s", k.Algorithm)
	}
	if len(k.Secret) == 0 {
		return fmt.Errorf("TSIG key secret is empty")
	}
	low, high := ai.minMACLen(), ai.macLen
	if k.MACLen != 0 && (k.MACLen < low || k.MACLen > high) {
		return fmt.Errorf("TSIG MAC length %d is not in the range %d..%d for %s", k.MACLen, low, high, k.Algorithm)
	}
	if k.MinMACLen != 0 && (k.MinMACLen < low || k.MinMACLen > high) {
		return fmt.Errorf("TSIG minimum MAC length %d is not in the range %d..%d for %s", k.MinMACLen, low, high, k.Algorithm)
	}
	return nil
}

// keyedHash returns the MAC of data truncated to length octets.  A length of 0
// means the longest MAC the algorithm allows; a length greater than the
// algorithm produces returns the whole keyed hash.
func (k TSIGKey) keyedHash(data []byte, length int) ([]byte, error) {
	ai, ok := k.Algorithm.info()
	if !ok {
		return nil, fmt.Errorf("unsupported TSIG algorithm: %s", k.Algorithm)
	}
	mac := hmac.New(ai.newHash, k.Secret)
	mac.Write(data)
	sum := mac.Sum(nil)
	if length == 0 {
		// 長さゼロは、アルゴリズムが許容する最長の MAC を返す。
		return sum[:ai.macLen], nil
	}
	if length > ai.macLen {
		return sum, nil
	}
	return sum[:length], nil
}

// MAC returns the keyed hash of data, truncated to the MAC length the key
// prefers.
func (k TSIGKey) MAC(data []byte) ([]byte, error) {
	return k.keyedHash(data, k.MACLen)
}

// TSIGOptions describes how a TSIG record is generated.  The zero value asks
// for a signature for the current time with the default Fudge, which is what a
// client signing a query wants.
type TSIGOptions struct {
	// TimeSigned is the time the record is signed at.  The zero value means
	// the current time.
	TimeSigned time.Time

	// Fudge is the number of seconds the signature is valid for on either side
	// of TimeSigned.  Zero means TSIGDefaultFudge.
	Fudge uint16

	// Error is the TSIG error the signer is reporting, normally
	// TSIGErrorNoError.
	Error uint16

	// OtherData is the variable length field of the record.  A BADTIME
	// response uses it to report the signer's current time.
	OtherData []byte

	// RequestMAC is the MAC of the request a response is answering.  Signing a
	// request leaves it empty.
	RequestMAC []byte

	// TimersOnly signs only the TSIG Timers, as RFC 8945 Section 5.3.1
	// requires for the third and later messages of a multi-message response.
	TimersOnly bool
}

func (o *TSIGOptions) time() time.Time {
	if o == nil || o.TimeSigned.IsZero() {
		return time.Now()
	}
	return o.TimeSigned
}

func (o *TSIGOptions) fudge() uint16 {
	if o == nil || o.Fudge == 0 {
		return TSIGDefaultFudge
	}
	return o.Fudge
}

func (o *TSIGOptions) tsigError() uint16 {
	if o == nil {
		return TSIGErrorNoError
	}
	return o.Error
}

func (o *TSIGOptions) otherData() []byte {
	if o == nil {
		return nil
	}
	return o.OtherData
}

func (o *TSIGOptions) requestMAC() []byte {
	if o == nil {
		return nil
	}
	return o.RequestMAC
}

func (o *TSIGOptions) timersOnly() bool {
	return o != nil && o.TimersOnly
}

// tsigTimeSigned converts a time into the 48 bit unsigned integer the Time
// Signed field holds.
func tsigTimeSigned(t time.Time) (uint64, error) {
	seconds := t.UTC().Unix()
	if seconds < 0 || uint64(seconds) > maxTSIGTimeSigned {
		return 0, fmt.Errorf("time %s does not fit in the TSIG Time Signed field", t.UTC().Format(time.RFC3339))
	}
	return uint64(seconds), nil
}

// tsigVariables is the TSIG Variables part of the data a TSIG record signs:
// the fields of the record which are not the MAC itself, in the order of
// RFC 8945 Table 2.  The TYPE, Original ID, MAC Size and MAC fields are not
// part of it.
type tsigVariables struct {
	name       DomainName
	algorithm  DomainName
	timeSigned uint64
	fudge      uint16
	err        uint16
	otherData  []byte
}

func (v tsigVariables) appendTo(w *WireFormat) {
	w.AppendCanonicalDomainName(v.name)
	w.AppendUInt16(uint16(CLASS_ANY))
	w.AppendUInt32(0)
	w.AppendCanonicalDomainName(v.algorithm)
	w.AppendUInt48(v.timeSigned)
	w.AppendUInt16(v.fudge)
	w.AppendUInt16(v.err)
	w.AppendUInt16(uint16(len(v.otherData)))
	w.AppendBytes(v.otherData)
}

// tsigDigest builds the data a TSIG record is computed over.  The message is
// the DNS message exactly as it was (or will be) transmitted, with its TSIG
// record already removed.  For a response, requestMAC is the MAC of the request
// exactly as it was transmitted.  With timersOnly, only the TSIG Timers are
// used, as RFC 8945 Section 5.3.1 requires.
func tsigDigest(requestMAC []byte, message WireFormat, vars tsigVariables, timersOnly bool) WireFormat {
	size := len(requestMAC) + len(message) + int(vars.name.Size()) + int(vars.algorithm.Size()) + 32
	w := make(WireFormat, 0, size)
	if len(requestMAC) > 0 {
		w.AppendUInt16(uint16(len(requestMAC)))
		w.AppendBytes(requestMAC)
	}
	w.AppendBytes(message)
	if timersOnly {
		w.AppendUInt48(vars.timeSigned)
		w.AppendUInt16(vars.fudge)
	} else {
		vars.appendTo(&w)
	}
	return w
}

// TSIGVerifyError reports why a TSIG record was not accepted.  TSIGError is the
// TSIG error to put in the reply, RCODE is the DNS error code to reply with, and
// OtherData is the TSIG Other Data to reply with.  A form error is reported with
// a TSIGError of TSIGErrorNoError and an RCODE of 1.
type TSIGVerifyError struct {
	TSIGError uint16
	RCODE     uint8
	OtherData []byte
	Reason    string
}

func (e *TSIGVerifyError) Error() string {
	s := "TSIG verification failed: "
	if e.TSIGError == TSIGErrorNoError {
		s += fmt.Sprintf("RCODE %d", e.RCODE)
	} else {
		s += fmt.Sprintf("%s (RCODE %d)", TSIGErrorString(e.TSIGError), e.RCODE)
	}
	if e.Reason != "" {
		s += ": " + e.Reason
	}
	return s
}

// tsigRData returns the TSIG record stored in an RDATA value.
func tsigRData(rdata RDATA) (*RecordTSIG, bool) {
	switch value := rdata.(type) {
	case RecordTSIG:
		return &value, true
	case *RecordTSIG:
		return value, true
	}
	return nil, false
}

// hasTSIG reports whether any record of the message is a TSIG record.
func (msg Message) hasTSIG() bool {
	for _, section := range [][]ResourceRecord{
		msg.AnswerSection,
		msg.AuthoritySection,
		msg.AdditionalSection,
	} {
		for _, rr := range section {
			if rr.Type == TYPE_TSIG {
				return true
			}
		}
	}
	return false
}

// checkSectionCounts reports whether the record counts of the header match the
// lengths of the sections.
func (msg Message) checkSectionCounts() error {
	counts := []struct {
		name  string
		want  uint16
		got   int
		limit uint32
	}{
		{"question", msg.QDCOUNT, len(msg.QuestionSection), 14},
		{"answer", msg.ANCOUNT, len(msg.AnswerSection), 14},
		{"authority", msg.NSCOUNT, len(msg.AuthoritySection), 14},
		{"additional", msg.ARCOUNT, len(msg.AdditionalSection), 14},
	}
	for _, c := range counts {
		if uint32(c.got) > c.limit {
			return fmt.Errorf("%s section has %d records, which does not fit in a %d bit count", c.name, c.got, c.limit)
		}
		if uint16(c.got) != c.want {
			return fmt.Errorf("%s section has %d records but the header says %d", c.name, c.got, c.want)
		}
	}
	return nil
}

// wireFormatForSigning returns the message as the octets which will be put on
// the wire, which is the data its TSIG record is computed over.
func (msg Message) wireFormatForSigning() WireFormat {
	w := make(WireFormat, 0, DNS_HEADER_SIZE)
	w.WriteWireFormat(msg)
	return w
}

// SignTSIG returns a TSIG record which authenticates the message with the given
// key.  The message itself is not modified: append the returned record to the
// additional section and raise ARCOUNT by one to transmit it.
//
// The message is signed exactly as it will be transmitted, so the counts of the
// header must match the lengths of the sections.  A message which already has a
// TSIG record cannot be signed.
func (msg Message) SignTSIG(key TSIGKey, opts *TSIGOptions) (ResourceRecord, error) {
	if err := key.validate(); err != nil {
		return ResourceRecord{}, err
	}
	if err := msg.checkSectionCounts(); err != nil {
		return ResourceRecord{}, err
	}
	if msg.hasTSIG() {
		return ResourceRecord{}, fmt.Errorf("message already has a TSIG record")
	}

	timeSigned, err := tsigTimeSigned(opts.time())
	if err != nil {
		return ResourceRecord{}, err
	}
	fudge := opts.fudge()
	errCode := opts.tsigError()
	otherData := opts.otherData()
	requestMAC := opts.requestMAC()

	vars := tsigVariables{
		name:       key.Name,
		algorithm:  key.Algorithm.DomainName(),
		timeSigned: timeSigned,
		fudge:      fudge,
		err:        errCode,
		otherData:  otherData,
	}
	data := tsigDigest(requestMAC, msg.wireFormatForSigning(), vars, opts.timersOnly())
	mac, err := key.MAC(data)
	if err != nil {
		return ResourceRecord{}, err
	}
	return ResourceRecord{
		Name:  key.Name,
		Class: CLASS_ANY,
		Type:  TYPE_TSIG,
		TTL:   0,
		RData: RecordTSIG{
			Algorithm:  key.Algorithm.DomainName(),
			TimeSigned: timeSigned,
			Fudge:      fudge,
			MAC:        mac,
			OriginalID: msg.ID,
			Error:      errCode,
			OtherData:  otherData,
		},
	}, nil
}

// TSIGVerifyOptions describes how the TSIG record of a message is verified.  The
// zero value verifies the TSIG record of a request at the current time, which is
// what a server answering a signed query wants.
type TSIGVerifyOptions struct {
	// RequestMAC is the MAC of the request this message answers, exactly as it
	// was received, including any truncation the request used.  Verifying a
	// request leaves it empty.
	RequestMAC []byte

	// TimersOnly verifies a signature made over only the TSIG Timers, as RFC
	// 8945 Section 5.3.1 requires for the third and later messages of a
	// multi-message response.
	TimersOnly bool

	// Now is the time the signature is checked against.  The zero value means
	// the current time.
	Now time.Time
}

func (o *TSIGVerifyOptions) requestMAC() []byte {
	if o == nil {
		return nil
	}
	return o.RequestMAC
}

func (o *TSIGVerifyOptions) timersOnly() bool {
	return o != nil && o.TimersOnly
}

func (o *TSIGVerifyOptions) now() time.Time {
	if o == nil || o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// tsigPlacement is where the TSIG record of a wire format message is.
type tsigPlacement struct {
	msg   Message
	rr    ResourceRecord
	begin uint32
	end   uint32
	count uint16

	// lastExtra reports whether the record was the last record of the additional
	// section.
	lastExtra bool
}

// isTSIGRecord reports whether the record beginning at begin is a TSIG record.
// It is how a record which is a malformed TSIG is told apart from a malformed
// record of another type.
func isTSIGRecord(w WireFormat, begin uint32) bool {
	_, p, err := NewDomainNameFromCompressedWireFormat(&w, begin)
	if err != nil {
		return false
	}
	t, err := w.GetUInt16(p)
	return err == nil && ResourceType(t) == TYPE_TSIG
}

// findTSIGRecord parses a wire format message and reports the position of its
// TSIG record.  A message without one is returned with a count of zero.  A
// message whose TSIG record cannot be interpreted is reported as a form error,
// because RFC 8945 Section 5.2 drops such a message.
func findTSIGRecord(w WireFormat) (found tsigPlacement, err error) {
	var p uint32
	p, err = ParseHeader(w, &found.msg)
	if err != nil {
		return
	}
	for i := uint16(0); i < found.msg.QDCOUNT; i++ {
		if _, p, err = ParseQuestionSectionEntry(w, p); err != nil {
			return
		}
	}
	sections := []struct {
		count uint16
		extra bool
	}{
		{found.msg.ANCOUNT, false},
		{found.msg.NSCOUNT, false},
		{found.msg.ARCOUNT, true},
	}
	for _, section := range sections {
		for i := uint16(0); i < section.count; i++ {
			begin := p
			var rr ResourceRecord
			rr, p, err = ParseResourceRecord(w, p)
			if err != nil {
				if isTSIGRecord(w, begin) {
					err = &TSIGVerifyError{RCODE: 1, Reason: "the TSIG record could not be interpreted"}
				}
				return
			}
			found.end = p
			if rr.Type != TYPE_TSIG {
				continue
			}
			found.count++
			if section.extra {
				found.rr = rr
				found.begin = begin
				found.lastExtra = i+1 == section.count
			}
		}
	}
	return
}

// VerifyTSIG checks the TSIG record of a wire format message against a key and
// returns nil when the message is authenticated.
//
// The checks are made in the order RFC 8945 Section 5.2 gives them: the position
// of the record, the key name and algorithm, the length of the MAC, the MAC
// itself, the time values and the truncation policy.  A failure the RFC answers
// with a DNS error code is returned as a *TSIGVerifyError, which carries the TSIG
// error and RCODE to answer with.  A message which cannot be parsed at all, and a
// key which cannot be used, are returned as errors of another kind.
func VerifyTSIG(w WireFormat, key TSIGKey, opts *TSIGVerifyOptions) error {
	if err := key.validate(); err != nil {
		return err
	}
	found, err := findTSIGRecord(w)
	if err != nil {
		return err
	}
	switch {
	case found.count == 0:
		return fmt.Errorf("message has no TSIG record")
	case found.count > 1:
		return &TSIGVerifyError{RCODE: 1, Reason: "the message has more than one TSIG record"}
	case !found.lastExtra:
		return &TSIGVerifyError{
			RCODE:  1,
			Reason: "the TSIG record is not the last record of the additional section",
		}
	case found.end != w.Size():
		return &TSIGVerifyError{
			RCODE:  1,
			Reason: fmt.Sprintf("the message has %d octets after its TSIG record", w.Size()-found.end),
		}
	}
	rec, ok := tsigRData(found.rr.RData)
	if !ok {
		return &TSIGVerifyError{RCODE: 1, Reason: "the TSIG record could not be interpreted"}
	}
	// RFC 8945 Section 4.2: the class of a TSIG record MUST be ANY and its TTL
	// MUST be zero.
	if found.rr.Class != CLASS_ANY {
		return &TSIGVerifyError{
			RCODE:  1,
			Reason: fmt.Sprintf("the class of the TSIG record is %s, which must be ANY", found.rr.Class),
		}
	}
	if found.rr.TTL != 0 {
		return &TSIGVerifyError{
			RCODE:  1,
			Reason: fmt.Sprintf("the TTL of the TSIG record is %d, which must be zero", found.rr.TTL),
		}
	}

	// Section 5.2.1: a key name or an algorithm which is not recognized is a
	// BADKEY error, and the answer is not signed.
	if !found.rr.Name.Equal(key.Name) {
		return &TSIGVerifyError{
			TSIGError: TSIGErrorBadKey,
			RCODE:     9,
			Reason:    fmt.Sprintf("unknown TSIG key: %s", found.rr.Name),
		}
	}
	if !rec.Algorithm.Equal(key.Algorithm.DomainName()) {
		return &TSIGVerifyError{
			TSIGError: TSIGErrorBadKey,
			RCODE:     9,
			Reason: fmt.Sprintf("the key %s uses the algorithm %s, not %s",
				found.rr.Name, rec.Algorithm, key.Algorithm),
		}
	}

	// Section 5.2.2.1: the MAC Size field must be a length the algorithm allows.
	// The bounds of the RFC are form errors, and they are checked before the
	// keyed hash is computed.
	macLen := len(rec.MAC)
	if maxLen := key.Algorithm.MACLen(); macLen > maxLen {
		return &TSIGVerifyError{
			RCODE: 1,
			Reason: fmt.Sprintf("the TSIG MAC is %d octets, which is longer than the %d octets %s produces",
				macLen, maxLen, key.Algorithm),
		}
	}
	if macLen == 0 {
		if rec.Error == TSIGErrorNoError {
			return &TSIGVerifyError{RCODE: 1, Reason: "the TSIG record has an empty MAC"}
		}
		// Section 5.3.2: an answer about a key or a MAC which is not accepted is
		// not signed.
		return &TSIGVerifyError{
			TSIGError: rec.Error,
			RCODE:     9,
			OtherData: rec.OtherData,
			Reason:    "the peer returned an unsigned TSIG error answer",
		}
	}
	if minLen := key.Algorithm.minMACLen(); macLen < minLen {
		return &TSIGVerifyError{
			RCODE: 1,
			Reason: fmt.Sprintf("the TSIG MAC is %d octets, which is shorter than the %d octets %s allows",
				macLen, minLen, key.Algorithm),
		}
	}

	// The message is the octets which were transmitted, with its TSIG record
	// removed, its record count lowered by one and its ID replaced by the
	// Original ID of the record.  The octets given are left as they are.
	message := make(WireFormat, found.begin)
	copy(message, w[:found.begin])
	if _, err = message.PutUint16(0, rec.OriginalID); err != nil {
		return err
	}
	if _, err = message.PutUint16(10, found.msg.ARCOUNT-1); err != nil {
		return err
	}
	vars := tsigVariables{
		name:       found.rr.Name,
		algorithm:  rec.Algorithm,
		timeSigned: rec.TimeSigned,
		fudge:      rec.Fudge,
		err:        rec.Error,
		otherData:  rec.OtherData,
	}
	data := tsigDigest(opts.requestMAC(), message, vars, opts.timersOnly())

	// Section 5.2.2: the locally computed MAC is truncated to the length the
	// record used before the two are compared.
	mac, err := key.keyedHash(data, macLen)
	if err != nil {
		return err
	}
	if !hmac.Equal(mac, rec.MAC) {
		return &TSIGVerifyError{
			TSIGError: TSIGErrorBadSig,
			RCODE:     9,
			Reason:    "the MAC does not match",
		}
	}

	// Section 5.2.3 lets a BADTIME answer reuse the timers of the request so that
	// the request can be verified without the verification failing with another
	// BADTIME, so the error the peer reported comes before the time check.
	if rec.Error != TSIGErrorNoError {
		return &TSIGVerifyError{
			TSIGError: rec.Error,
			RCODE:     9,
			OtherData: rec.OtherData,
			Reason:    fmt.Sprintf("the peer reported %s", TSIGErrorString(rec.Error)),
		}
	}

	// Section 5.2.3: the local time must be inside the interval the record's
	// Time Signed and Fudge describe.
	seconds := opts.now().UTC().Unix()
	signed, fudge := int64(rec.TimeSigned), int64(rec.Fudge)
	if seconds < signed-fudge || seconds > signed+fudge {
		if seconds < 0 {
			seconds = 0
		}
		var otherData WireFormat
		otherData.AppendUInt48(uint64(seconds))
		return &TSIGVerifyError{
			TSIGError: TSIGErrorBadTime,
			RCODE:     9,
			OtherData: otherData,
			Reason: fmt.Sprintf("the record is signed at %s with a fudge of %d seconds, which does not include %s",
				time.Unix(signed, 0).UTC().Format(time.RFC3339), rec.Fudge,
				opts.now().UTC().Format(time.RFC3339)),
		}
	}

	// Section 5.2.4: a MAC which the algorithm allows but the local policy does
	// not is a BADTRUNC error.
	if key.MinMACLen != 0 && macLen < key.MinMACLen {
		return &TSIGVerifyError{
			TSIGError: TSIGErrorBadTrunc,
			RCODE:     9,
			Reason: fmt.Sprintf("the TSIG MAC is %d octets, which is shorter than the %d octets this key requires",
				macLen, key.MinMACLen),
		}
	}
	return nil
}

// VerifyTSIG checks the TSIG record of the message against a key and returns
// nil when the message is authenticated.
//
// The message must have exactly one TSIG record, and it must be the last
// record of the additional section.  The checks follow RFC 8945 Section 5.2:
// the position of the record, the key name and algorithm, the length of the
// MAC, the MAC itself, the time values and the truncation policy.
//
// The message is verified exactly as it was received: the TSIG record is
// removed from the additional section, the record count is lowered by one and
// the message ID is replaced by the TSIG record's Original ID before the MAC
// is computed.
func (msg Message) VerifyTSIG(key TSIGKey, opts *TSIGVerifyOptions) error {
	if err := key.validate(); err != nil {
		return err
	}

	// Find the TSIG record in the additional section.
	tsigIndex := -1
	for i, rr := range msg.AdditionalSection {
		if rr.Type == TYPE_TSIG {
			if tsigIndex != -1 {
				return &TSIGVerifyError{RCODE: 1, Reason: "the message has more than one TSIG record"}
			}
			tsigIndex = i
		}
	}
	if tsigIndex == -1 {
		return fmt.Errorf("message has no TSIG record")
	}
	if tsigIndex != len(msg.AdditionalSection)-1 {
		return &TSIGVerifyError{
			RCODE:  1,
			Reason: "the TSIG record is not the last record of the additional section",
		}
	}

	rr := msg.AdditionalSection[tsigIndex]
	rec, ok := tsigRData(rr.RData)
	if !ok {
		return &TSIGVerifyError{RCODE: 1, Reason: "the TSIG record could not be interpreted"}
	}

	// RFC 8945 Section 4.2: the class of a TSIG record MUST be ANY and its TTL
	// MUST be zero.
	if rr.Class != CLASS_ANY {
		return &TSIGVerifyError{
			RCODE:  1,
			Reason: fmt.Sprintf("the class of the TSIG record is %s, which must be ANY", rr.Class),
		}
	}
	if rr.TTL != 0 {
		return &TSIGVerifyError{
			RCODE:  1,
			Reason: fmt.Sprintf("the TTL of the TSIG record is %d, which must be zero", rr.TTL),
		}
	}

	// Section 5.2.1: a key name or an algorithm which is not recognized is a
	// BADKEY error, and the answer is not signed.
	if !rr.Name.Equal(key.Name) {
		return &TSIGVerifyError{
			TSIGError: TSIGErrorBadKey,
			RCODE:     9,
			Reason:    fmt.Sprintf("unknown TSIG key: %s", rr.Name),
		}
	}
	if !rec.Algorithm.Equal(key.Algorithm.DomainName()) {
		return &TSIGVerifyError{
			TSIGError: TSIGErrorBadKey,
			RCODE:     9,
			Reason: fmt.Sprintf("the key %s uses the algorithm %s, not %s",
				rr.Name, rec.Algorithm, key.Algorithm),
		}
	}

	// Section 5.2.2.1: the MAC Size field must be a length the algorithm allows.
	// The bounds of the RFC are form errors, and they are checked before the
	// keyed hash is computed.
	macLen := len(rec.MAC)
	if maxLen := key.Algorithm.MACLen(); macLen > maxLen {
		return &TSIGVerifyError{
			RCODE: 1,
			Reason: fmt.Sprintf("the TSIG MAC is %d octets, which is longer than the %d octets %s produces",
				macLen, maxLen, key.Algorithm),
		}
	}
	if macLen == 0 {
		if rec.Error == TSIGErrorNoError {
			return &TSIGVerifyError{RCODE: 1, Reason: "the TSIG record has an empty MAC"}
		}
		// Section 5.3.2: an answer about a key or a MAC which is not accepted is
		// not signed.
		return &TSIGVerifyError{
			TSIGError: rec.Error,
			RCODE:     9,
			OtherData: rec.OtherData,
			Reason:    "the peer returned an unsigned TSIG error answer",
		}
	}
	if minLen := key.Algorithm.minMACLen(); macLen < minLen {
		return &TSIGVerifyError{
			RCODE: 1,
			Reason: fmt.Sprintf("the TSIG MAC is %d octets, which is shorter than the %d octets %s allows",
				macLen, minLen, key.Algorithm),
		}
	}

	// The message is the octets which were transmitted, with its TSIG record
	// removed, its record count lowered by one and its ID replaced by the
	// Original ID of the record.
	msgForSigning := msg
	msgForSigning.AdditionalSection = append(msgForSigning.AdditionalSection[:tsigIndex],
		msgForSigning.AdditionalSection[tsigIndex+1:]...)
	msgForSigning.ARCOUNT--
	msgForSigning.ID = rec.OriginalID

	var w WireFormat
	w.WriteWireFormat(msgForSigning)

	vars := tsigVariables{
		name:       rr.Name,
		algorithm:  rec.Algorithm,
		timeSigned: rec.TimeSigned,
		fudge:      rec.Fudge,
		err:        rec.Error,
		otherData:  rec.OtherData,
	}
	data := tsigDigest(opts.requestMAC(), w, vars, opts.timersOnly())

	// Section 5.2.2: the locally computed MAC is truncated to the length the
	// record used before the two are compared.
	mac, err := key.keyedHash(data, macLen)
	if err != nil {
		return err
	}
	if !hmac.Equal(mac, rec.MAC) {
		return &TSIGVerifyError{
			TSIGError: TSIGErrorBadSig,
			RCODE:     9,
			Reason:    "the MAC does not match",
		}
	}

	// Section 5.2.3 lets a BADTIME answer reuse the timers of the request so
	// that the request can be verified without the verification failing with
	// another BADTIME, so the error the peer reported comes before the time
	// check.
	if rec.Error != TSIGErrorNoError {
		return &TSIGVerifyError{
			TSIGError: rec.Error,
			RCODE:     9,
			OtherData: rec.OtherData,
			Reason:    fmt.Sprintf("the peer reported %s", TSIGErrorString(rec.Error)),
		}
	}

	// Section 5.2.3: the local time must be inside the interval the record's
	// Time Signed and Fudge describe.
	seconds := opts.now().UTC().Unix()
	signedTime, fudge := int64(rec.TimeSigned), int64(rec.Fudge)
	if seconds < signedTime-fudge || seconds > signedTime+fudge {
		if seconds < 0 {
			seconds = 0
		}
		var otherData WireFormat
		otherData.AppendUInt48(uint64(seconds))
		return &TSIGVerifyError{
			TSIGError: TSIGErrorBadTime,
			RCODE:     9,
			OtherData: otherData,
			Reason: fmt.Sprintf("the record is signed at %s with a fudge of %d seconds, which does not include %s",
				time.Unix(signedTime, 0).UTC().Format(time.RFC3339), rec.Fudge,
				opts.now().UTC().Format(time.RFC3339)),
		}
	}

	// Section 5.2.4: a MAC which the algorithm allows but the local policy does
	// not is a BADTRUNC error.
	if key.MinMACLen != 0 && macLen < key.MinMACLen {
		return &TSIGVerifyError{
			TSIGError: TSIGErrorBadTrunc,
			RCODE:     9,
			Reason: fmt.Sprintf("the TSIG MAC is %d octets, which is shorter than the %d octets this key requires",
				macLen, key.MinMACLen),
		}
	}
	return nil
}

// NewUnsignedTSIGResponse returns a TSIG record which reports a TSIG error without
// a MAC, as RFC 8945 Section 5.3.2 requires when a key or a MAC is not accepted.
// The record carries the name and algorithm the peer used, because the reason the
// signature was not accepted may be that this implementation does not know them.
//
// The record is not signed: its MAC is empty.  Use opts to report the error and
// the Other Data to answer with, such as the 48 bit current time of a BADTIME
// error.  The error must not be TSIGErrorNoError, because a record with neither a
// MAC nor an error is a form error.
func NewUnsignedTSIGResponse(keyName DomainName, algorithm TSIGAlgorithm, originalID uint16, opts *TSIGOptions) (ResourceRecord, error) {
	if keyName.Size() == 0 {
		return ResourceRecord{}, fmt.Errorf("TSIG key name is empty")
	}
	if _, err := NewDomainNameFromString(algorithm.String()); err != nil {
		return ResourceRecord{}, fmt.Errorf("invalid TSIG algorithm name: %s", err)
	}
	errCode := opts.tsigError()
	if errCode == TSIGErrorNoError {
		return ResourceRecord{}, fmt.Errorf("an unsigned TSIG response must report a TSIG error")
	}
	timeSigned, err := tsigTimeSigned(opts.time())
	if err != nil {
		return ResourceRecord{}, err
	}
	return ResourceRecord{
		Name:  keyName,
		Class: CLASS_ANY,
		Type:  TYPE_TSIG,
		TTL:   0,
		RData: RecordTSIG{
			Algorithm:  algorithm.DomainName(),
			TimeSigned: timeSigned,
			Fudge:      opts.fudge(),
			MAC:        []byte{},
			OriginalID: originalID,
			Error:      errCode,
			OtherData:  opts.otherData(),
		},
	}, nil
}
