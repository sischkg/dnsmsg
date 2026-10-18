package dnsmsg

import (
	"crypto"
	"crypto/rand"
	"fmt"
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
// given algorithm, Labels set to the label count of rs.Name, OrigTTL set to
// rs.TTL, and Signature set to the signature bytes.
func SignRRSet(rs *RRSet, signer crypto.Signer, algorithm uint8, keyTag uint16, signerName DomainName, inception, expiration uint32) (*RecordRRSIG, error) {
	if rs == nil {
		return nil, fmt.Errorf("RRSet is nil")
	}
	if signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}

	hash, ok := dnssecAlgorithmHash(algorithm)
	if !ok {
		return nil, fmt.Errorf("unsupported DNSSEC algorithm %d for signing", algorithm)
	}

	data := rs.CanonicalWireFormat()

	var opts crypto.SignerOpts
	var signData []byte
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
		signData = data
	}
	// Ed25519 などハッシュを指定しないアルゴリズムでは opts は nil のまま。

	signature, err := signer.Sign(rand.Reader, signData, opts)
	if err != nil {
		return nil, fmt.Errorf("cannot sign RRSet: %w", err)
	}

	labels := uint8(labelCount(rs.Name))

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
