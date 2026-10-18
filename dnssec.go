package dnsmsg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DNSSECKey is a DNSSEC key read from a dnssec-keygen key file.
//
// The .key file holds the public key material (flags, protocol, algorithm and
// public key) which corresponds to a DNSKEY record.  The .private file holds
// the private key material which is used to sign RRsets.
type DNSSECKey struct {
	// Name is the domain name the key is for (the owner name of the DNSKEY
	// record).
	Name DomainName
	// Flags are the DNSKEY flags (256 = zone key, 257 = secure entry point).
	Flags uint16
	// Protocol is the security protocol (always 3 for DNSSEC).
	Protocol uint8
	// Algorithm is the DNSSEC algorithm number (RFC 4034 Section 5.1.1).
	Algorithm uint8
	// PublicKey is the public key material.  It is populated when the key is
	// read from a .key file.
	PublicKey []byte
	// PrivateKey is the primary private key material.  It is populated when
	// the key is read from a .private file; its meaning depends on the
	// algorithm (for RSA it is the private exponent, for ECDSA it is the
	// private scalar).
	PrivateKey []byte
	// PrivateParams holds the named private key parameters parsed from a
	// .private file (for example "Modulus", "PrivateExponent", "PrivateKey").
	// It is nil when the key is read from a .key file.
	PrivateParams map[string][]byte
}

// ToDNSKEY converts the key into a RecordDNSKEY suitable for publishing in a
// zone file.  The private key material is not part of the DNSKEY record.
func (k *DNSSECKey) ToDNSKEY() RecordDNSKEY {
	return NewRecordDNSKEY(k.Flags, k.Protocol, k.Algorithm, k.PublicKey)
}

// ReadKeyFile reads a dnssec-keygen .key file and returns the DNSSEC key it
// contains.  The file is expected to contain a DNSKEY record in zone file
// format, for example:
//
//	example.com. IN DNSKEY 256 3 5 <base64-public-key>
//
// Only the first DNSKEY record in the file is returned; comment and blank
// lines are skipped.
func ReadKeyFile(filename string) (*DNSSECKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot read key file %s: %w", filename, err)
	}
	return parseKeyData(data, filename)
}

// ReadPrivateKeyFile reads a dnssec-keygen .private file and returns the
// DNSSEC key it contains.  The private key material and parameters are
// populated; the public key is not present in a .private file and is left nil.
func ReadPrivateKeyFile(filename string) (*DNSSECKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key file %s: %w", filename, err)
	}
	return parsePrivateKeyData(data, filename)
}

// parseKeyData parses the contents of a .key file.
func parseKeyData(data []byte, filename string) (*DNSSECKey, error) {
	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip zone file directives such as $ORIGIN and $TTL.
		if strings.HasPrefix(line, "$") {
			continue
		}
		key, err := parseKeyLine(line)
		if err != nil {
			return nil, fmt.Errorf("cannot parse key file %s: %w", filename, err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("no DNSKEY record found in %s", filename)
}

// parseKeyLine parses a single DNSKEY record line from a .key file.
//
// Format: <name> IN DNSKEY <flags> <protocol> <algorithm> <base64-public-key>
func parseKeyLine(line string) (*DNSSECKey, error) {
	fields := strings.Fields(line)
	if len(fields) < 7 {
		return nil, fmt.Errorf("invalid DNSKEY key line %q: expected at least 7 fields", line)
	}
	if fields[1] != "IN" {
		return nil, fmt.Errorf("invalid DNSKEY key line %q: expected class IN", line)
	}
	if fields[2] != "DNSKEY" {
		return nil, fmt.Errorf("invalid DNSKEY key line %q: expected type DNSKEY", line)
	}

	name, err := NewDomainNameFromString(fields[0])
	if err != nil {
		return nil, fmt.Errorf("invalid DNSKEY name %q: %w", fields[0], err)
	}

	flags, err := strconvParseUint16(fields[3], "flags")
	if err != nil {
		return nil, err
	}

	protocol, err := strconvParseUint8(fields[4], "protocol")
	if err != nil {
		return nil, err
	}

	algorithm, err := strconvParseUint8(fields[5], "algorithm")
	if err != nil {
		return nil, err
	}

	publicKey, err := decodeBase64(fields[6])
	if err != nil {
		return nil, fmt.Errorf("invalid DNSKEY public key %q: %w", fields[6], err)
	}

	return &DNSSECKey{
		Name:      name,
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		PublicKey: publicKey,
	}, nil
}

// parsePrivateKeyData parses the contents of a dnssec-keygen .private file
// (Private-key-format v1.3).
func parsePrivateKeyData(data []byte, filename string) (*DNSSECKey, error) {
	key := &DNSSECKey{
		PrivateParams: make(map[string][]byte),
	}

	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)

		switch strings.ToLower(name) {
		case "private-key-format":
			// Informational only.
		case "algorithm":
			alg, err := parsePrivateAlgorithm(value)
			if err != nil {
				return nil, fmt.Errorf("cannot parse private key file %s: %w", filename, err)
			}
			key.Algorithm = alg
		case "created", "publish", "activate":
			// Timestamps are informational only.
		default:
			// Any other line is a named private key parameter carrying
			// base64-encoded material.
			decoded, err := decodeBase64(value)
			if err != nil {
				return nil, fmt.Errorf("cannot decode private key parameter %q in %s: %w", name, filename, err)
			}
			key.PrivateParams[name] = decoded
			if strings.EqualFold(name, "privatekey") || strings.EqualFold(name, "privateexponent") {
				key.PrivateKey = decoded
			}
		}
	}

	if key.Algorithm == 0 {
		return nil, fmt.Errorf("no algorithm found in private key file %s", filename)
	}
	return key, nil
}

// parsePrivateAlgorithm parses the "Algorithm: N (name)" line of a .private
// file and returns the algorithm number.
func parsePrivateAlgorithm(value string) (uint8, error) {
	// Value is like "5 (RSASHA1)" or just "5".
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return 0, fmt.Errorf("empty algorithm value %q", value)
	}
	alg, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid algorithm number %q: %w", parts[0], err)
	}
	return uint8(alg), nil
}

// strconvParseUint16 parses a decimal string into a uint16.
func strconvParseUint16(s, field string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", field, s, err)
	}
	return uint16(n), nil
}

// strconvParseUint8 parses a decimal string into a uint8.
func strconvParseUint8(s, field string) (uint8, error) {
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", field, s, err)
	}
	return uint8(n), nil
}

// dnssecAlgorithmHash returns the hash function used by the given DNSSEC
// algorithm number (RFC 4034 Section 5.1.1, RFC 5702, RFC 6605,
// RFC 8078, RFC 8624).  Zero (crypto.Hash(0)) is returned for algorithms
// which do not pre-hash (for example Ed25519).  ok is false for algorithms
// this implementation does not know how to sign with.
func dnssecAlgorithmHash(algorithm uint8) (crypto.Hash, bool) {
	switch algorithm {
	case 5: // RSASHA1
		return crypto.SHA1, true
	case 7: // RSASHA1-NSEC3-SHA1
		return crypto.SHA1, true
	case 8: // RSASHA256
		return crypto.SHA256, true
	case 10: // RSASHA512
		return crypto.SHA512, true
	case 12: // ECC-GOST (not supported)
		return 0, false
	case 13: // ECDSAP256SHA256
		return crypto.SHA256, true
	case 14: // ECDSAP384SHA384
		return crypto.SHA384, true
	case 15: // ED25519
		return 0, true
	default:
		return 0, false
	}
}

// SupportedDNSSECAlgorithms returns the list of DNSSEC algorithm numbers this
// implementation can sign with, in ascending numeric order.  All returned
// algorithms are accepted by dnssecAlgorithmHash and SignRRSet.
func SupportedDNSSECAlgorithms() []uint8 {
	algs := []uint8{5, 7, 8, 10, 13, 14, 15}
	sort.Slice(algs, func(i, j int) bool {
		return algs[i] < algs[j]
	})
	return algs
}

// labelCount returns the number of labels in the domain name, excluding the
// terminating root label.  For example "www.example.com." has 3 labels and
// the root domain "." has 0 labels.
func labelCount(name DomainName) int {
	// DomainName はルートラベルを終端ラベルとして保持する。
	n := len(name.labels)
	if n > 0 {
		n-- // 終端のルートラベルを除外
	}
	return n
}

// DNSSECSignOptions describes how an RRSet is signed to produce an RRSIG
// record (RFC 4034 Section 5.3).
type DNSSECSignOptions struct {
	// Inception is the signature inception time (Unix seconds).  The zero
	// value means the current time.
	Inception uint32
	// Expiration is the signature expiration time (Unix seconds).  The zero
	// value means no expiration (the signature is valid indefinitely).
	Expiration uint32
	// KeyTag is the DNSKEY key tag of the signing key.
	KeyTag uint16
	// SignerName is the name of the signing key (the owner name of the
	// DNSKEY record).  The zero value means the root domain name.
	SignerName DomainName
}

// inceptionTime returns the inception time to use.  Zero means now.
func (o *DNSSECSignOptions) inceptionTime() uint32 {
	if o != nil && o.Inception != 0 {
		return o.Inception
	}
	return uint32(time.Now().UTC().Unix())
}

// expirationTime returns the expiration time to use.  Zero means no
// expiration.
func (o *DNSSECSignOptions) expirationTime() uint32 {
	if o != nil {
		return o.Expiration
	}
	return 0
}

// keyTag returns the key tag to use.
func (o *DNSSECSignOptions) keyTag() uint16 {
	if o != nil {
		return o.KeyTag
	}
	return 0
}

// signerName returns the signer name to use.  Zero means the root domain.
func (o *DNSSECSignOptions) signerName() DomainName {
	if o != nil && !o.SignerName.IsRoot() {
		return o.SignerName
	}
	return NewRootDomainName()
}

// SignRRSet signs the RRSet with the given private key and returns an
// RRSIG record covering the RRSet.  The signature is computed over the
// canonical wire format of the RRSet (RFC 4034 Section 6.2).
//
// signer is a crypto.Signer implementing the private key operation.  The
// algorithm parameter is the DNSSEC algorithm number (for example 8 for
// RSASHA256, 13 for ECDSAP256SHA256).  keyTag is the DNSKEY key tag of the
// signing key, and signerName is the owner name of the DNSKEY record.
//
// The returned RRSIG has TypeCovered set to rs.Type, Algorithm set to the
// given algorithm, Labels set to the label count of rs.Name (RFC 4034
// Section 3.1.3: the terminating root label and the leftmost wildcard label
// of a wildcard domain name such as *.example.com are not counted), OrigTTL
// set to rs.TTL, and Signature set to the signature bytes.
func SignRRSet(rs *RRSet, signer crypto.Signer, algorithm uint8, keyTag uint16, signerName DomainName, inception, expiration uint32) (*RecordRRSIG, error) {
	if rs == nil {
		return nil, fmt.Errorf("RRSet is nil")
	}
	if signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}

	signData, opts, err := dnssecSignData(rs, algorithm)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(rand.Reader, signData, opts)
	if err != nil {
		return nil, fmt.Errorf("cannot sign RRSet: %w", err)
	}

	labels := uint8(labelCount(rs.Name))
	if isWildcardDomainName(rs.Name) {
		// The leftmost wildcard label is part of the owner name in the zone
		// but is not counted by the Labels field (RFC 4034 Section 3.1.3).
		labels--
	}

	rrsig := NewRecordRRSIG(
		uint16(rs.Type),
		algorithm,
		labels,
		rs.TTL,
		expiration,
		inception,
		keyTag,
		signerName,
		signature,
	)
	return &rrsig, nil
}

// dnssecSignData returns the data that is signed for the given algorithm and
// the crypto.SignerOpts to pass to crypto.Signer.Sign.  The signed data is
// the canonical wire format of the RRSet (RFC 4034 Section 6.2), hashed with
// the algorithm's hash function when the algorithm pre-hashes (RFC 4034
// Section 5.1.1).  For algorithms which do not pre-hash (for example
// Ed25519) the canonical wire format itself is returned and opts is
// crypto.Hash(0), which crypto/ed25519 requires in place of nil.
func dnssecSignData(rs *RRSet, algorithm uint8) (signData []byte, opts crypto.SignerOpts, err error) {
	hash, ok := dnssecAlgorithmHash(algorithm)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported DNSSEC algorithm %d", algorithm)
	}

	data := rs.CanonicalWireFormat()

	if hash != 0 {
		opts = hash
		// crypto/rsa と crypto/ecdsa の Sign は crypto.SHA256 などの
		// crypto.SignerOpts を受け取ると、データを「すでにハッシュ済み」
		// とみなす。そのため、ここでデータをハッシュしてから渡す。
		h := hash.New()
		h.Write(data)
		signData = h.Sum(nil)
	} else {
		// Ed25519 などハッシュを指定しないアルゴリズムでは生データを渡す。
		// opts は nil ではなく crypto.Hash(0) でなければならない
		// （crypto/ed25519 の Sign は opts.Hash() を参照する）。
		signData = data
		opts = crypto.Hash(0)
	}
	return signData, opts, nil
}

// signerNameCovers reports whether signerName is the name of the zone
// containing ownerName: it equals the owner name or one of its parent
// domains (RFC 4034 Section 3.1.8.1).  Comparison is case insensitive.  The
// root domain name covers every name, because DNSSECSignOptions uses the
// root name when no signer name is given.
func signerNameCovers(signerName, ownerName DomainName) bool {
	if signerName.IsRoot() {
		return true
	}
	for _, parent := range ownerName.ParentDomainNames() {
		if parent.Equal(signerName) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Wildcard-expanded owner names (RFC 4035 Section 5.3.4)
// ---------------------------------------------------------------------------

// isWildcardDomainName reports whether the leftmost label of name is the
// wildcard label "*".  The owner name of an RRset created as a result of
// wildcard expansion is such a domain name in the zone, while the
// wildcard-expanded name a validator verifies is not.
func isWildcardDomainName(name DomainName) bool {
	if len(name.labels) < 2 {
		return false
	}
	return string(name.labels[0].data) == "*"
}

// wildcardExpandedName reconstructs the original owner name of an RRset that
// was created as a result of wildcard expansion, following the pseudocode of
// RFC 4035 Section 5.3.2: the original owner name is the wildcard label
// followed by the rightmost rrsigLabels labels of fqdn, the name the
// validator is asked to verify.  rrsigLabels is the Labels field of the
// covering RRSIG RR, which counts the labels of the wildcard pattern without
// the wildcard label itself (RFC 4034 Section 3.1.3).
//
//   - rrsigLabels equal to the number of labels in fqdn: no wildcard
//     expansion took place, and fqdn is returned unchanged.
//   - rrsigLabels smaller than that number: the RRset and its covering RRSIG
//     were created as a result of wildcard expansion, and the wildcard
//     pattern they were expanded from is returned.
//   - rrsigLabels greater than that number: the RRSIG MUST NOT be used
//     (RFC 4035 Section 5.3.2), which is reported as an error.
func wildcardExpandedName(fqdn DomainName, rrsigLabels uint8) (DomainName, error) {
	fqdnLabels := labelCount(fqdn)
	if int(rrsigLabels) > fqdnLabels {
		return DomainName{}, fmt.Errorf(
			"RRSIG Labels field %d is greater than the %d labels in %s: the RRSIG MUST NOT be used",
			rrsigLabels, fqdnLabels, fqdn.String())
	}
	labels := make([]Label, 0, fqdnLabels+1)
	// The leftmost wildcard label (RFC 1034 Section 4.3.3) replaces the
	// labels the wildcard pattern stands for.
	labels = append(labels, Label{data: []byte("*")})
	labels = append(labels, fqdn.labels[fqdnLabels-int(rrsigLabels):]...)
	return NewDomainNameFromLabel(labels)
}

// VerifyRRSet verifies that rrsig is a valid signature over rs produced by
// the private key corresponding to pubkey (RFC 4034 Section 3.1).
//
// The signed data is reconstructed exactly as SignRRSet produces it: the
// canonical wire format of the RRSet (RFC 4034 Section 6.2), hashed with the
// hash function of the RRSIG's algorithm.  Note that, like SignRRSet, this
// implementation signs the canonical RRSet only; it does not prepend the
// RRSIG RDATA as RFC 4034 Section 3.1.8.1 describes, and the TTL field is
// fixed to zero in the canonical wire format, so the RRSIG's Original TTL
// field and the RRSet's TTL are not covered by the signature.
//
// In addition to the cryptographic check, VerifyRRSet enforces the
// consistency requirements of RFC 4034 Section 3.1.8.1: the Type Covered
// field must equal the RRSet type, the Labels field must not exceed the
// label count of the owner name, and the Signer's Name must be the owner
// name or one of its parent domains (the root name is accepted for any
// name).
//
// An RRset whose owner name has more labels than the Labels field of its
// covering RRSIG was created as a result of wildcard expansion (RFC 4035
// Section 5.3.4).  For such an RRset the signature covers the RRset under the
// wildcard owner name it was expanded from, because a wildcard RRset is
// signed in the zone under its unexpanded name (RFC 4034 Section 6.2).
// VerifyRRSet reconstructs that original owner name following the pseudocode
// of RFC 4035 Section 5.3.2 - the wildcard label followed by the rightmost
// Labels labels of the owner name, so www.example.com with a Labels field of
// 2 becomes *.example.com - and verifies the signature over the RRset with
// that owner name and the RRSIG's Original TTL.  An RRset whose owner name is
// a wildcard domain name itself, such as *.example.com with a Labels field of
// 2, is verified under that name unchanged.
//
// The signature validity period is checked against now: the signature is
// rejected when now is before the Inception field or after the Expiration
// field.  An Expiration field of zero means no expiration, matching
// DNSSECSignOptions.  A zero time.Time skips the validity period check.
//
// pubkey is the public key corresponding to the signing key: *rsa.PublicKey
// for RSA algorithms (5, 7, 8, 10), *ecdsa.PublicKey for ECDSA algorithms
// (13, 14) and ed25519.PublicKey for Ed25519 (15).  Use
// NewDNSSECPublicKey to convert DNSKEY public key material, or
// VerifyRRSetWithDNSKEY to verify directly against a DNSKEY record.
func VerifyRRSet(rs *RRSet, rrsig *RecordRRSIG, pubkey crypto.PublicKey, now time.Time) error {
	if rs == nil {
		return fmt.Errorf("RRSet is nil")
	}
	if rrsig == nil {
		return fmt.Errorf("RRSIG is nil")
	}
	if pubkey == nil {
		return fmt.Errorf("public key is nil")
	}

	if rrsig.TypeCovered != uint16(rs.Type) {
		return fmt.Errorf("RRSIG Type Covered is %d, RRSet type is %d", rrsig.TypeCovered, uint16(rs.Type))
	}
	if int(rrsig.Labels) > labelCount(rs.Name) {
		return fmt.Errorf("RRSIG Labels is %d, exceeds label count %d of %s", rrsig.Labels, labelCount(rs.Name), rs.Name.String())
	}
	if !signerNameCovers(rrsig.SignersName, rs.Name) {
		return fmt.Errorf("RRSIG Signer's Name %s does not cover owner name %s", rrsig.SignersName.String(), rs.Name.String())
	}

	if !now.IsZero() {
		t := now.UTC().Unix()
		if t < int64(rrsig.Inception) {
			return fmt.Errorf("RRSIG inception time %d is after verification time %d", rrsig.Inception, t)
		}
		if rrsig.Expiration != 0 && t > int64(rrsig.Expiration) {
			return fmt.Errorf("RRSIG expired at %d, verification time is %d", rrsig.Expiration, t)
		}
	}

	// An owner name with more labels than the Labels field of the covering
	// RRSIG means the RRset and its RRSIG were created as a result of
	// wildcard expansion (RFC 4035 Section 5.3.4).  Verify the signature over
	// the RRset with the original wildcard owner name instead (RFC 4035
	// Section 5.3.2).
	signed := rs
	if int(rrsig.Labels) < labelCount(rs.Name) {
		original, err := wildcardExpandedName(rs.Name, rrsig.Labels)
		if err != nil {
			return err
		}
		signed = &RRSet{
			Name:  original,
			Class: rs.Class,
			Type:  rs.Type,
			TTL:   rrsig.OrigTTL,
			RData: rs.RData,
		}
	}

	signData, _, err := dnssecSignData(signed, rrsig.Algorithm)
	if err != nil {
		return err
	}
	return verifyDNSSECSignature(rrsig.Algorithm, pubkey, signData, rrsig.Signature)
}

// verifyDNSSECSignature checks a DNSSEC signature produced by SignRRSet
// against the given public key.  signData is the value dnssecSignData
// returns for the algorithm: the hash digest for algorithms which
// pre-hash, the raw signed data for algorithms which do not (Ed25519).
func verifyDNSSECSignature(algorithm uint8, pubkey crypto.PublicKey, signData, signature []byte) error {
	hash, ok := dnssecAlgorithmHash(algorithm)
	if !ok {
		return fmt.Errorf("unsupported DNSSEC algorithm %d for verification", algorithm)
	}

	switch algorithm {
	case 5, 7, 8, 10: // RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512
		pub, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %d requires an *rsa.PublicKey", algorithm)
		}
		if err := rsa.VerifyPKCS1v15(pub, hash, signData, signature); err != nil {
			return fmt.Errorf("RSA signature does not match: %w", err)
		}
		return nil

	case 13, 14: // ECDSAP256SHA256, ECDSAP384SHA384
		pub, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %d requires an *ecdsa.PublicKey", algorithm)
		}
		// crypto/ecdsa の Sign は署名を ASN.1 DER（SEQUENCE of INTEGER）で
		// 返すため、同じ形式で復号して検証する。
		var ecdsaSig struct {
			R *big.Int
			S *big.Int
		}
		if _, err := asn1.Unmarshal(signature, &ecdsaSig); err != nil {
			return fmt.Errorf("cannot parse ECDSA signature: %w", err)
		}
		if !ecdsa.Verify(pub, signData, ecdsaSig.R, ecdsaSig.S) {
			return fmt.Errorf("ECDSA signature does not match")
		}
		return nil

	case 15: // ED25519
		pub, ok := pubkey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %d requires an ed25519.PublicKey", algorithm)
		}
		if !ed25519.Verify(pub, signData, signature) {
			return fmt.Errorf("Ed25519 signature does not match")
		}
		return nil
	}

	return fmt.Errorf("unsupported DNSSEC algorithm %d for verification", algorithm)
}

// NewDNSSECPublicKey converts DNSKEY public key material (the Public Key
// field of a DNSKEY RDATA, RFC 4034 Section 2.1 for RSA, RFC 6605
// Section 4 for ECDSA, RFC 8080 Section 3 for Ed25519) into the Go public
// key type used by VerifyRRSet: *rsa.PublicKey for RSA algorithms,
// *ecdsa.PublicKey for ECDSA algorithms and ed25519.PublicKey for Ed25519.
func NewDNSSECPublicKey(algorithm uint8, material []byte) (crypto.PublicKey, error) {
	switch algorithm {
	case 5, 7, 8, 10:
		return rsaPublicKeyFromDNSKEY(material)
	case 13:
		return ecdsaPublicKeyFromDNSKEY(material, elliptic.P256())
	case 14:
		return ecdsaPublicKeyFromDNSKEY(material, elliptic.P384())
	case 15:
		if len(material) != 32 {
			return nil, fmt.Errorf("Ed25519 DNSKEY public key must be 32 octets, got %d", len(material))
		}
		return ed25519.PublicKey(append([]byte(nil), material...)), nil
	default:
		return nil, fmt.Errorf("unsupported DNSSEC algorithm %d", algorithm)
	}
}

// rsaPublicKeyFromDNSKEY decodes RSA public key material as described in
// RFC 4034 Section 2.1: one or three octets give the length of the public
// exponent in octets (a zero length means the exponent is 65537), followed
// by the exponent and the modulus, both in big-endian order.
func rsaPublicKeyFromDNSKEY(material []byte) (*rsa.PublicKey, error) {
	if len(material) == 0 {
		return nil, fmt.Errorf("empty RSA DNSKEY public key")
	}
	var e int
	switch material[0] {
	case 0:
		// 指数の長さが 0 の場合、指数は 65537 である（RFC 4034 Section 2.1）。
		e = 65537
		material = material[1:]
	case 1:
		if len(material) < 2 {
			return nil, fmt.Errorf("truncated RSA DNSKEY public key")
		}
		e = int(material[1])
		material = material[2:]
	case 3:
		if len(material) < 4 {
			return nil, fmt.Errorf("truncated RSA DNSKEY public key")
		}
		e = int(material[1])<<16 | int(material[2])<<8 | int(material[3])
		material = material[4:]
	default:
		return nil, fmt.Errorf("invalid RSA DNSKEY public exponent length %d", material[0])
	}
	if len(material) == 0 {
		return nil, fmt.Errorf("truncated RSA DNSKEY public key: missing modulus")
	}
	if e < 3 {
		return nil, fmt.Errorf("invalid RSA public exponent %d", e)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(material), E: e}, nil
}

// ecdsaPublicKeyFromDNSKEY decodes ECDSA public key material as described
// in RFC 6605 Section 4: the x and y coordinates of the public point, each
// fixed-length big-endian, concatenated.
func ecdsaPublicKeyFromDNSKEY(material []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	size := (curve.Params().N.BitLen() + 7) / 8
	if len(material) != 2*size {
		return nil, fmt.Errorf("ECDSA DNSKEY public key must be %d octets, got %d", 2*size, len(material))
	}
	x := new(big.Int).SetBytes(material[:size])
	y := new(big.Int).SetBytes(material[size:])
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("ECDSA DNSKEY public key is not a point on the curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// VerifyRRSetWithDNSKEY verifies rrsig over rs using the public key carried
// in a DNSKEY record.  The DNSKEY must use the same algorithm as the RRSIG.
// Selecting the DNSKEY by Key Tag (RFC 4034 Section 3.1.1) is left to the
// caller.
func VerifyRRSetWithDNSKEY(rs *RRSet, rrsig *RecordRRSIG, dnskey *RecordDNSKEY, now time.Time) error {
	if dnskey == nil {
		return fmt.Errorf("DNSKEY is nil")
	}
	if dnskey.Algorithm != rrsig.Algorithm {
		return fmt.Errorf("DNSKEY algorithm %d does not match RRSIG algorithm %d", dnskey.Algorithm, rrsig.Algorithm)
	}
	pubkey, err := NewDNSSECPublicKey(dnskey.Algorithm, dnskey.PublicKey)
	if err != nil {
		return err
	}
	return VerifyRRSet(rs, rrsig, pubkey, now)
}
