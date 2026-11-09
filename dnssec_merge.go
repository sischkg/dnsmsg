package dnsmsg

import (
	"fmt"
)

// MergeDNSSECKey combines the public half of a DNSSEC key with the private half
// of the same key into one DNSSECKey that carries both: the value on which
// (*DNSSECKey).KeyTag, (*DNSSECKey).ToDNSKEY, NewDNSSECSigner and SignRRSet all
// work.
//
// A dnssec-keygen key pair is split over two files: the .key file holds the
// owner name, flags, protocol, algorithm and public key material, the .private
// file holds the private key material.  ReadKeyFile and ReadPrivateKeyFile each
// read one half, and neither result can compute a key tag or sign with the other
// half missing.  MergeDNSSECKey is that combination, for a caller that already
// has the two keys - from the two files, from a generated key, or built in
// memory - and wants to combine them itself instead of loading a pair from disk.
// ReadDNSSECKeyFiles is built on the same merge and reports the same rules with
// the pair's file names.
//
// public is the source of Name, Flags, Protocol, Algorithm and PublicKey; private
// is the source of PrivateKey and PrivateParams.  Neither argument is modified,
// and the returned key shares no byte slice, label slice or map with either of
// them: changing the merged key afterwards does not change the arguments, and two
// keys merged from the same pair do not share state.
//
// The two halves must describe one key:
//
//   - neither argument is nil;
//   - public carries public key material, which a key read from a .private file
//     does not have;
//   - private carries private key material, which a key read from a .key file
//     does not have;
//   - both sides name an algorithm, and it is the same algorithm.  An algorithm
//     of 0 is the value a DNSSECKey has when no algorithm was read from a file,
//     and so is reported as missing rather than compared.
//
// When the merged key's algorithm is one this package can sign with
// (SupportedDNSSECAlgorithms), MergeDNSSECKey also builds the signer and compares
// the public key it derives from the private material with the public key
// material, which is where a private key that does not belong to the public key
// is reported: at the merge, not at signing time.  A key whose algorithm is not
// in that set is merged without that check, because there is no signer to build;
// its KeyTag and ToDNSKEY are still correct, and NewDNSSECSigner reports the
// algorithm when a caller tries to sign with it.
//
// The errors name the side that is missing or inconsistent and say which
// information that side cannot provide.  Two of them name the kind of file such
// a key usually comes from, because that is what explains why the material is
// absent; none of them names a file this function opened, because it opens none.
// ReadDNSSECKeyFiles is the function that knows the two file names and prefixes
// its errors with them.
func MergeDNSSECKey(public, private *DNSSECKey) (*DNSSECKey, error) {
	if public == nil {
		return nil, fmt.Errorf("cannot merge DNSSEC key: the public key is nil")
	}
	if private == nil {
		return nil, fmt.Errorf("cannot merge DNSSEC key: the private key is nil")
	}
	if len(public.PublicKey) == 0 {
		return nil, fmt.Errorf("cannot merge DNSSEC key: the public key carries no DNSKEY public key material, which is what a key read from a .private file has, so the merged key would have no DNSKEY to describe")
	}
	if len(private.PrivateKey) == 0 && len(private.PrivateParams) == 0 {
		return nil, fmt.Errorf("cannot merge DNSSEC key: the private key carries no private key material, which is what a key read from a .key file has, so the merged key would have nothing to sign with")
	}

	merged, err := mergeDNSSECKeyParts(public, private)
	if err != nil {
		return nil, fmt.Errorf("cannot merge DNSSEC key: %w", err)
	}
	if err := validateMergedDNSSECKey(merged); err != nil {
		return nil, err
	}
	return merged, nil
}

// mergeDNSSECKeyParts is the merge: the fields of the two keys are copied into a
// new DNSSECKey after the checks both MergeDNSSECKey and the key-pair readers
// need, which are that the two sides exist and name one algorithm.
//
// Unlike MergeDNSSECKey it does not require either side to carry key material.  A
// pair whose .private file holds no private key material is still a faithful
// description of the DNSKEY in the .key file, and ReadDNSSECKeyFiles loads such
// a pair; only a caller that wants to sign needs MergeDNSSECKey's stricter rule.
//
// The errors describe what is wrong and do not name the operation they came from:
// each caller adds the context it has, such as the two file names of a key pair.
func mergeDNSSECKeyParts(public, private *DNSSECKey) (*DNSSECKey, error) {
	if public == nil {
		return nil, fmt.Errorf("the public key is nil")
	}
	if private == nil {
		return nil, fmt.Errorf("the private key is nil")
	}
	if err := checkDNSSECKeyMergeAlgorithms(public, private); err != nil {
		return nil, err
	}

	merged := &DNSSECKey{
		Name:       cloneDNSSECKeyName(public.Name),
		Flags:      public.Flags,
		Protocol:   public.Protocol,
		Algorithm:  public.Algorithm,
		PublicKey:  cloneDNSSECKeyOctets(public.PublicKey),
		PrivateKey: cloneDNSSECKeyOctets(private.PrivateKey),
	}
	if len(private.PrivateParams) > 0 {
		merged.PrivateParams = make(map[string][]byte, len(private.PrivateParams))
		for name, value := range private.PrivateParams {
			merged.PrivateParams[name] = cloneDNSSECKeyOctets(value)
		}
	}
	return merged, nil
}

// checkDNSSECKeyMergeAlgorithms reports two keys that do not name the same
// algorithm, because a merged key whose two halves name different algorithms is a
// mixture of two keys and no key at all.  The algorithm number and its name are
// both reported for each side, so that a caller holding both halves can see which
// one is the odd one out.
func checkDNSSECKeyMergeAlgorithms(public, private *DNSSECKey) error {
	if public.Algorithm == 0 {
		return fmt.Errorf("the public key names no algorithm, so the merged key would have none")
	}
	if private.Algorithm == 0 {
		return fmt.Errorf("the private key names no algorithm, so the merged key would have none")
	}
	if public.Algorithm != private.Algorithm {
		return fmt.Errorf("the algorithms do not match, the public key uses algorithm %d (%s) and the private key uses algorithm %d (%s)",
			public.Algorithm, DNSSECAlgorithm(public.Algorithm),
			private.Algorithm, DNSSECAlgorithm(private.Algorithm))
	}
	return nil
}

// validateMergedDNSSECKey reports a merged key that cannot be used as a whole.
// A key that carries private material and whose algorithm this package can sign
// with must produce a signer, which is where a private key that does not belong
// to the public key material is found.  A key without private material, or for an
// algorithm that cannot be signed with, has nothing here to check and is merged
// as it is.
//
// The errors are the ones NewDNSSECSigner returns, which already name the key and
// the parameter they could not use; the callers of this function add whatever
// context they have, such as the two file names of a key pair.
func validateMergedDNSSECKey(key *DNSSECKey) error {
	if len(key.PrivateKey) == 0 && len(key.PrivateParams) == 0 {
		return nil
	}
	if !supportedDNSSECAlgorithmForSigning(key.Algorithm) {
		return nil
	}
	if _, err := NewDNSSECSigner(key); err != nil {
		return err
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

// cloneDNSSECKeyOctets copies a byte slice so that the merged key and the key it
// was built from do not share it.  A nil slice stays nil, because that is how a
// DNSSECKey says it has no material of that kind, and an empty non-nil slice
// stays a non-nil empty slice.
func cloneDNSSECKeyOctets(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// cloneDNSSECKeyName copies a domain name, label by label, including the octets
// of every label.  The labels are kept as they are - the name of a merged key is
// the name its public key declares, and a name that is not a valid domain name
// stays just as invalid in the copy.
func cloneDNSSECKeyName(name DomainName) DomainName {
	if name.labels == nil {
		return DomainName{}
	}
	labels := make([]Label, len(name.labels))
	for i, l := range name.labels {
		labels[i] = Label{data: cloneDNSSECKeyOctets(l.data)}
	}
	return DomainName{labels: labels}
}
