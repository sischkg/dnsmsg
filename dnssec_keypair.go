package dnsmsg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadDNSSECKeyPair reads the .key and .private files that dnssec-keygen
// generates for one key pair and returns them merged into a single DNSSECKey.
//
// baseName is the name the two files share, without their suffix:
// "Kexample.com.+008+12345" resolves "Kexample.com.+008+12345.key" and
// "Kexample.com.+008+12345.private".  A base name that already carries a
// ".key" or ".private" suffix has that suffix removed first, so any of the
// three spellings - the bare base name, one file name, or the other - selects
// the same pair.  The suffix must be spelled in lower case.  The files are
// read from the local filesystem, relative to the working directory or by
// absolute path, exactly like ReadKeyFile and ReadPrivateKeyFile.
//
// The merged key carries everything the two files hold: the owner name, flags,
// protocol, algorithm and public key material from the .key file, and the
// private key material and private key parameters from the .private file.  It
// is the value the signing helpers need: (*DNSSECKey).KeyTag and
// (*DNSSECKey).ToDNSKEY work on it without reading the .key file again, and
// NewDNSSECSigner builds a signer from it.
//
// The two files must declare the same algorithm, and a key pair whose algorithm
// this package can sign with is checked by building its signer, which reports a
// private key that does not belong to the public key the .key file holds.  A
// pair for an algorithm that cannot be used for signing is loaded without that
// check, so that its DNSKEY and key tag remain available.
func ReadDNSSECKeyPair(baseName string) (*DNSSECKey, error) {
	keyFile, privateFile, err := dnssecKeyPairFileNames(baseName)
	if err != nil {
		return nil, err
	}
	return ReadDNSSECKeyFiles(keyFile, privateFile)
}

// ReadDNSSECKeyFiles reads a key pair from the two file names that select it,
// for a caller that already knows both paths.  The files need not share a base
// name, and no file name is derived from the other.  The result and the rules
// for merging and checking the pair are those of ReadDNSSECKeyPair.
func ReadDNSSECKeyFiles(keyFile, privateFile string) (*DNSSECKey, error) {
	public, err := ReadKeyFile(keyFile)
	if err != nil {
		return nil, err
	}
	private, err := readDNSSECKeyPairPrivateFile(privateFile)
	if err != nil {
		return nil, err
	}

	merged, err := mergeDNSSECKeyPair(public, private, keyFile, privateFile)
	if err != nil {
		return nil, err
	}
	if err := validateDNSSECKeyPair(merged, keyFile, privateFile); err != nil {
		return nil, err
	}
	return merged, nil
}

// dnssecKeyPairFileNames returns the .key and .private file names that baseName
// selects.  A trailing ".key" or ".private" is removed before the two names are
// built, so that a caller may pass either file name instead of the bare base
// name.  A suffix that is a differently spelled form of one of them is an
// error, because dnssec-keygen always writes lower-case suffixes and a
// differently spelled one is more likely a mistake than a different file.
func dnssecKeyPairFileNames(baseName string) (string, string, error) {
	if baseName == "" {
		return "", "", fmt.Errorf("cannot read DNSSEC key pair: the base name is empty")
	}

	base := baseName
	switch ext := filepath.Ext(baseName); ext {
	case ".key", ".private":
		base = strings.TrimSuffix(baseName, ext)
	default:
		if strings.EqualFold(ext, ".key") || strings.EqualFold(ext, ".private") {
			return "", "", fmt.Errorf("cannot read DNSSEC key pair %q: the key file suffix is %q, which is not spelled in lower case", baseName, ext)
		}
	}
	if base == "" {
		return "", "", fmt.Errorf("cannot read DNSSEC key pair %q: the base name is empty", baseName)
	}

	return base + ".key", base + ".private", nil
}

// readDNSSECKeyPairPrivateFile reads a .private file for a key pair.  It is
// ReadPrivateKeyFile with one difference: a "Name:" line is dropped before the
// file is parsed.  Some tools write the owner name into a .private file, which
// the private key format has no field for, and in a pair the owner name comes
// from the .key file anyway.  ReadPrivateKeyFile itself keeps rejecting such a
// line, because a lone .private file has nothing to take the name from.
func readDNSSECKeyPairPrivateFile(filename string) (*DNSSECKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key file %s: %w", filename, err)
	}
	return parsePrivateKeyData(withoutPrivateNameLine(data), filename)
}

// withoutPrivateNameLine removes the lines whose field name is "Name" from the
// contents of a .private file.  The field name is matched the way
// parsePrivateKeyData matches it, and the value is discarded: the name a key
// pair uses is the one its .key file declares.
func withoutPrivateNameLine(data []byte) []byte {
	if !containsPrivateNameLine(data) {
		return data
	}

	kept := make([]byte, 0, len(data))
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			kept = append(kept, raw...)
			kept = append(kept, '\n')
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Name") {
			continue
		}
		kept = append(kept, raw...)
		kept = append(kept, '\n')
	}
	return kept
}

// containsPrivateNameLine reports whether the contents of a .private file carry
// a "Name:" line, so that files without one - which is what dnssec-keygen
// writes - are passed to the parser untouched.
func containsPrivateNameLine(data []byte) bool {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Name") {
			return true
		}
	}
	return false
}

// mergeDNSSECKeyPair combines the key read from a .key file with the key read
// from the .private file of the same pair.  The .key file is the source of the
// owner name, flags, protocol and public key material; the .private file is the
// source of the private key material.  The two files must agree on the
// algorithm, because a pair whose two halves name different algorithms is a
// mixture of two keys and no key at all.
func mergeDNSSECKeyPair(public, private *DNSSECKey, keyFile, privateFile string) (*DNSSECKey, error) {
	if public.Algorithm != private.Algorithm {
		return nil, fmt.Errorf("DNSSEC key pair %s and %s: the key file uses algorithm %d (%s) but the private key file uses algorithm %d (%s)",
			keyFile, privateFile,
			public.Algorithm, DNSSECAlgorithm(public.Algorithm),
			private.Algorithm, DNSSECAlgorithm(private.Algorithm))
	}

	merged := *public
	merged.PrivateKey = private.PrivateKey
	merged.PrivateParams = private.PrivateParams
	return &merged, nil
}

// validateDNSSECKeyPair reports a key pair that cannot be used as a whole.  A
// pair that carries private material and whose algorithm this package can sign
// with must produce a signer, which is where a private key that does not belong
// to the public key of the .key file is found.  A pair without private material,
// or for an algorithm that cannot be signed with, has nothing here to check and
// is loaded as it is.
func validateDNSSECKeyPair(key *DNSSECKey, keyFile, privateFile string) error {
	if len(key.PrivateKey) == 0 && len(key.PrivateParams) == 0 {
		return nil
	}
	if !supportedDNSSECAlgorithmForSigning(key.Algorithm) {
		return nil
	}
	if _, err := NewDNSSECSigner(key); err != nil {
		return fmt.Errorf("DNSSEC key pair %s and %s: %w", keyFile, privateFile, err)
	}
	return nil
}

// supportedDNSSECAlgorithmForSigning reports whether algorithm is one of the
// algorithms SupportedDNSSECAlgorithms says this package can sign with.
func supportedDNSSECAlgorithmForSigning(algorithm uint8) bool {
	for _, supported := range SupportedDNSSECAlgorithms() {
		if supported == algorithm {
			return true
		}
	}
	return false
}
