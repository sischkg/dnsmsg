package dnsmsg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// dnssecPrivateKeyParams returns the private key parameters of a signer, in the
// names a .private file uses.  They are the parameters NewDNSSECSigner reads,
// so a DNSSEC key built from them is the same key.
func dnssecPrivateKeyParams(t *testing.T, signer crypto.Signer) map[string][]byte {
	t.Helper()

	switch key := signer.(type) {
	case *rsa.PrivateKey:
		params := map[string][]byte{
			"Modulus":         key.N.Bytes(),
			"PublicExponent":  big.NewInt(int64(key.E)).Bytes(),
			"PrivateExponent": key.D.Bytes(),
		}
		if key.Precomputed.Dp != nil {
			params["Prime1"] = key.Primes[0].Bytes()
			params["Prime2"] = key.Primes[1].Bytes()
		}
		return params
	case *ecdsa.PrivateKey:
		scalar := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
		key.D.FillBytes(scalar)
		return map[string][]byte{"PrivateKey": scalar}
	case ed25519.PrivateKey:
		return map[string][]byte{"PrivateKey": key.Seed()}
	}

	t.Fatalf("no private key parameters for %T", signer)
	return nil
}

// clonePrivateParams returns private key parameters a test may change without
// changing the parameters the other tests use.
func clonePrivateParams(params map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(params))
	for name, value := range params {
		clone[name] = append([]byte(nil), value...)
	}
	return clone
}

// dnssecKeyFromTestKey builds the DNSSEC key NewDNSSECSigner is given: the
// private key parameters of the test key, and the public key material of the
// DNSKEY record its .key file holds.  A .private file read on its own is the
// same key without that public key material.
func dnssecKeyFromTestKey(t *testing.T, key verifyTestKey) *DNSSECKey {
	t.Helper()

	return &DNSSECKey{
		Name:          testDomainName(t, "example.com."),
		Flags:         257,
		Protocol:      3,
		Algorithm:     key.algorithm,
		PublicKey:     dnskeyMaterialFromPublicKey(t, key.pubkey),
		PrivateParams: dnssecPrivateKeyParams(t, key.signer),
	}
}

// isDNSSECRSAAlgorithm reports whether an algorithm signs with RSA, which is
// the case its private key parameters and its rejections are about.
func isDNSSECRSAAlgorithm(algorithm uint8) bool {
	switch algorithm {
	case 5, 7, 8, 10:
		return true
	}
	return false
}

// supportsDNSSECAlgorithm reports whether an algorithm is one
// NewDNSSECSigner and the signing functions accept.
func supportsDNSSECAlgorithm(algorithms []uint8, algorithm uint8) bool {
	for _, supported := range algorithms {
		if supported == algorithm {
			return true
		}
	}
	return false
}

// errorContains reports whether an error says the thing a test is about.  The
// wording around it is not what the test is checking.
func errorContains(err error, want string) bool {
	return err != nil && strings.Contains(err.Error(), want)
}

// assertDNSSECSigner checks that a signer is the key the private parameters
// describe: of the type the algorithm signs with, holding the key material it
// was given, and deriving the public key of the DNSKEY record it signs for.
func assertDNSSECSigner(t *testing.T, algorithm uint8, signer crypto.Signer, material []byte, withPrimes bool) {
	t.Helper()

	switch algorithm {
	case 5, 7, 8, 10:
		priv, ok := signer.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("NewDNSSECSigner() returned %T, want *rsa.PrivateKey", signer)
		}
		want, err := rsaPublicKeyFromDNSKEY(material)
		if err != nil {
			t.Fatalf("rsaPublicKeyFromDNSKEY() error = %v", err)
		}
		if priv.N.Cmp(want.N) != 0 {
			t.Errorf("the signer modulus does not match the DNSKEY modulus")
		}
		if priv.D.Sign() <= 0 {
			t.Errorf("the signer private exponent is not positive")
		}
		// The primes are private key parameters only when the private key had
		// them, and they are the only case in which the key is validated as
		// a whole key pair.
		if withPrimes {
			if len(priv.Primes) != 2 {
				t.Errorf("len(priv.Primes) = %d, want 2", len(priv.Primes))
			}
			if priv.Precomputed.Dp == nil {
				t.Errorf("priv.Precomputed.Dp is nil: the key was not precomputed")
			}
		} else if len(priv.Primes) != 0 {
			t.Errorf("len(priv.Primes) = %d, want 0", len(priv.Primes))
		}

	case 13, 14:
		priv, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("NewDNSSECSigner() returned %T, want *ecdsa.PrivateKey", signer)
		}
		params := elliptic.P256().Params()
		if algorithm == 14 {
			params = elliptic.P384().Params()
		}
		// The curve is what the algorithm names, and it is not the one the
		// private scalar was read as a number for.
		if priv.Curve.Params().N.Cmp(params.N) != 0 {
			t.Errorf("the signer is not a key of the curve of algorithm %d", algorithm)
		}

	case 15:
		priv, ok := signer.(ed25519.PrivateKey)
		if !ok {
			t.Fatalf("NewDNSSECSigner() returned %T, want ed25519.PrivateKey", signer)
		}
		if len(priv) != 64 {
			t.Errorf("len(signer) = %d, want 64", len(priv))
		}

	default:
		t.Fatalf("no assertions for algorithm %d", algorithm)
	}

	if have := dnskeyMaterialFromPublicKey(t, signer.Public()); !bytes.Equal(have, material) {
		t.Errorf("the public key derived from the private key differs from the DNSKEY public key")
	}
}

// signAndVerifyRRSet signs an RRSet with a signer and verifies the signature
// against the DNSKEY record the public key material describes, which is what a
// resolver does with the .key file of the same key pair.
func signAndVerifyRRSet(t *testing.T, k *DNSSECKey, signer crypto.Signer, material []byte) {
	t.Helper()

	rrset := buildVerifyTestRRSet(t)
	record := NewRecordDNSKEY(k.Flags, k.Protocol, k.Algorithm, material)
	keyTag := record.KeyTag()

	rrsig, err := SignRRSet(&rrset, signer, k.Algorithm, keyTag, k.Name, testInception, testExpiration)
	if err != nil {
		t.Fatalf("SignRRSet() error = %v", err)
	}
	if rrsig.KeyTag != keyTag {
		t.Errorf("rrsig.KeyTag = %d, want the key tag of the signing key, %d", rrsig.KeyTag, keyTag)
	}
	if err := VerifyRRSetWithDNSKEY(&rrset, rrsig, &record, testVerifyTime); err != nil {
		t.Errorf("VerifyRRSetWithDNSKEY() error = %v", err)
	}
}

func TestNewDNSSECSignerFromPrivateKeyParameters(t *testing.T) {
	for _, algorithm := range SupportedDNSSECAlgorithms() {
		t.Run(algorithmName(algorithm), func(t *testing.T) {
			key := dnssecKeyFromTestKey(t, newVerifyTestKey(t, algorithm))
			material := append([]byte(nil), key.PublicKey...)
			params := key.PrivateParams
			withPrimes := len(params["Prime1"]) > 0

			// A key built from the private parameters of a key pair, which is
			// what a .private file describes, must be the key pair the DNSKEY
			// record's public key belongs to.
			signer, err := NewDNSSECSigner(key)
			if err != nil {
				t.Fatalf("NewDNSSECSigner() error = %v", err)
			}
			assertDNSSECSigner(t, algorithm, signer, material, withPrimes)
			signAndVerifyRRSet(t, key, signer, material)

			t.Run("private file only", func(t *testing.T) {
				// What ReadPrivateKeyFile returns: the private key parameters
				// and no public key material to compare the derived one with.
				k := dnssecKeyFromTestKey(t, verifyTestKey{algorithm, signer, signer.Public()})
				k.PublicKey = nil

				signer, err := NewDNSSECSigner(k)
				if err != nil {
					t.Fatalf("NewDNSSECSigner() error = %v", err)
				}
				assertDNSSECSigner(t, algorithm, signer, material, withPrimes)
				signAndVerifyRRSet(t, k, signer, material)
			})

			t.Run("private key field", func(t *testing.T) {
				// ReadPrivateKeyFile also mirrors the private exponent and the
				// private scalar into DNSSECKey.PrivateKey, and a hand-built
				// key may carry its material there alone.  Only the private
				// scalar of an elliptic curve key is a whole private key on its
				// own: an RSA key needs its modulus and public exponent too.
				materialOnly := params["PrivateExponent"]
				if !isDNSSECRSAAlgorithm(algorithm) {
					materialOnly = params["PrivateKey"]
				}

				k := &DNSSECKey{
					Name:       key.Name,
					Flags:      key.Flags,
					Protocol:   key.Protocol,
					Algorithm:  algorithm,
					PrivateKey: materialOnly,
				}

				signer, err := NewDNSSECSigner(k)
				if isDNSSECRSAAlgorithm(algorithm) {
					if err == nil {
						t.Fatal("NewDNSSECSigner() did not return an error")
					}
					if !errorContains(err, "invalid RSA public exponent") {
						t.Errorf("NewDNSSECSigner() error = %v, want it to reject the private exponent read as a public exponent", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("NewDNSSECSigner() error = %v", err)
				}
				assertDNSSECSigner(t, algorithm, signer, material, false)
				signAndVerifyRRSet(t, k, signer, material)
			})
		})
	}
}

func TestNewDNSSECSignerErrors(t *testing.T) {
	t.Run("nil key", func(t *testing.T) {
		if _, err := NewDNSSECSigner(nil); err == nil {
			t.Fatal("NewDNSSECSigner(nil) did not return an error")
		}
	})

	t.Run("key file only", func(t *testing.T) {
		// A .key file read on its own carries public key material, which is not
		// private key material: the .private file is what signs.
		key := dnssecKeyFromTestKey(t, newVerifyTestKey(t, 13))
		k := &DNSSECKey{
			Name:      key.Name,
			Flags:     257,
			Protocol:  3,
			Algorithm: 13,
			PublicKey: append([]byte(nil), key.PublicKey...),
		}

		_, err := NewDNSSECSigner(k)
		if err == nil {
			t.Fatal("NewDNSSECSigner() did not return an error")
		}
		if !errorContains(err, "has no private key material") {
			t.Errorf("NewDNSSECSigner() error = %v, want a key without private key material", err)
		}
	})

	t.Run("unsupported algorithms", func(t *testing.T) {
		supported := SupportedDNSSECAlgorithms()
		for algorithm := 0; algorithm < 256; algorithm++ {
			if supportsDNSSECAlgorithm(supported, uint8(algorithm)) {
				continue
			}

			k := &DNSSECKey{
				Algorithm:     uint8(algorithm),
				PrivateParams: map[string][]byte{"PrivateKey": {1}},
			}
			_, err := NewDNSSECSigner(k)
			if err == nil {
				t.Fatalf("NewDNSSECSigner() algorithm %d did not return an error", algorithm)
			}
			want := fmt.Sprintf("unsupported DNSSEC algorithm %d for signing", algorithm)
			if !errorContains(err, want) {
				t.Errorf("NewDNSSECSigner() algorithm %d error = %v, want %q", algorithm, err, want)
			}
		}
	})

	private := []struct {
		name      string
		algorithm uint8
		mutate    func(*DNSSECKey)
		want      string
	}{
		{"rsa without the modulus", 5, func(k *DNSSECKey) { delete(k.PrivateParams, "Modulus") }, `"Modulus"`},
		{"rsa without the public exponent", 5, func(k *DNSSECKey) { delete(k.PrivateParams, "PublicExponent") }, `"PublicExponent"`},
		{"rsa without the private exponent", 5, func(k *DNSSECKey) { delete(k.PrivateParams, "PrivateExponent") }, `"PrivateExponent"`},
		{"rsa with only one prime", 5, func(k *DNSSECKey) { delete(k.PrivateParams, "Prime2") }, `"Prime1 and Prime2"`},
		{"rsa public exponent of one", 5, func(k *DNSSECKey) { k.PrivateParams["PublicExponent"] = []byte{1} }, "invalid RSA public exponent"},
		{"rsa public exponent of 2^31", 5, func(k *DNSSECKey) {
			k.PrivateParams["PublicExponent"] = []byte{0x80, 0, 0, 0, 0}
		}, "invalid RSA public exponent"},
		{"ecdsa private scalar of the wrong length", 13, func(k *DNSSECKey) {
			k.PrivateParams["PrivateKey"] = []byte{1, 2, 3}
		}, "the private scalar must be 32 octets, got 3"},
		{"ecdsa private scalar of the wrong length for P-384", 14, func(k *DNSSECKey) {
			k.PrivateParams["PrivateKey"] = make([]byte, 32)
		}, "the private scalar must be 48 octets, got 32"},
		{"ecdsa private scalar of zero", 13, func(k *DNSSECKey) {
			k.PrivateParams["PrivateKey"] = make([]byte, 32)
		}, "greater than 0"},
		{"ecdsa private scalar equal to the curve order", 13, func(k *DNSSECKey) {
			k.PrivateParams["PrivateKey"] = elliptic.P256().Params().N.Bytes()
		}, "less than the curve order"},
		{"ecdsa private scalar under another name", 13, func(k *DNSSECKey) {
			k.PrivateParams = map[string][]byte{"NotAScalar": k.PrivateParams["PrivateKey"]}
		}, `no ECDSA private key parameter "PrivateKey"`},
		{"ed25519 seed of the wrong length", 15, func(k *DNSSECKey) {
			k.PrivateParams["PrivateKey"] = []byte{1, 2, 3}
		}, "the seed must be 32 octets, got 3"},
	}

	for _, tc := range private {
		t.Run(tc.name, func(t *testing.T) {
			k := dnssecKeyFromTestKey(t, newVerifyTestKey(t, tc.algorithm))
			tc.mutate(k)

			_, err := NewDNSSECSigner(k)
			if err == nil {
				t.Fatal("NewDNSSECSigner() did not return an error")
			}
			if !errorContains(err, tc.want) {
				t.Errorf("NewDNSSECSigner() error = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	public := []struct {
		name      string
		algorithm uint8
		mutate    func(*testing.T, *DNSSECKey)
		want      string
	}{
		{"truncated rsa public key", 5, func(t *testing.T, k *DNSSECKey) {
			k.PublicKey = []byte{1, 5}
		}, "missing modulus"},
		{"ecdsa public key of the wrong length", 13, func(t *testing.T, k *DNSSECKey) {
			k.PublicKey = []byte{1, 2, 3}
		}, "ECDSA DNSKEY public key must be 64 octets, got 3"},
		{"ecdsa public key that is not a point on the curve", 13, func(t *testing.T, k *DNSSECKey) {
			k.PublicKey = notOnCurveP256()
		}, "not a point on the curve"},
		{"ecdsa public key of the wrong curve", 13, func(t *testing.T, k *DNSSECKey) {
			k.PublicKey = dnskeyMaterialFromPublicKey(t, newVerifyTestKey(t, 14).pubkey)
		}, "must be 64 octets, got 96"},
		{"ed25519 public key of the wrong length", 15, func(t *testing.T, k *DNSSECKey) {
			k.PublicKey = []byte{1}
		}, "Ed25519 DNSKEY public key must be 32 octets, got 1"},
	}

	for _, tc := range public {
		t.Run(tc.name, func(t *testing.T) {
			// The private key parameters and the public key material of one key
			// pair, with the public key material replaced by something that
			// cannot be the public key of any key pair.
			k := dnssecKeyFromTestKey(t, newVerifyTestKey(t, tc.algorithm))
			tc.mutate(t, k)

			_, err := NewDNSSECSigner(k)
			if err == nil {
				t.Fatal("NewDNSSECSigner() did not return an error")
			}
			if !errorContains(err, tc.want) {
				t.Errorf("NewDNSSECSigner() error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestNewDNSSECSignerPublicKeyMismatch(t *testing.T) {
	for _, algorithm := range SupportedDNSSECAlgorithms() {
		t.Run(algorithmName(algorithm), func(t *testing.T) {
			// Two key pairs of the same algorithm: the private key parameters
			// of one are not the key of the DNSKEY record of the other.
			k := dnssecKeyFromTestKey(t, newVerifyTestKey(t, algorithm))
			other := newVerifyTestKey(t, algorithm)
			k.PublicKey = dnskeyMaterialFromPublicKey(t, other.pubkey)

			_, err := NewDNSSECSigner(k)
			if err == nil {
				t.Fatal("NewDNSSECSigner() did not return an error")
			}
			if !errorContains(err, "does not match its DNSKEY public key") {
				t.Errorf("NewDNSSECSigner() error = %v, want a private key that does not match its DNSKEY", err)
			}
		})
	}
}

func TestNewDNSSECSignerWithoutRSAPrimes(t *testing.T) {
	for _, algorithm := range []uint8{5, 7, 8, 10} {
		t.Run(algorithmName(algorithm), func(t *testing.T) {
			// A .private file may hold only the modulus, the public exponent
			// and the private exponent.  Such a key is accepted and signs,
			// because a signature is what a private exponent alone is for.
			k := dnssecKeyFromTestKey(t, newVerifyTestKey(t, algorithm))
			delete(k.PrivateParams, "Prime1")
			delete(k.PrivateParams, "Prime2")

			signer, err := NewDNSSECSigner(k)
			if err != nil {
				t.Fatalf("NewDNSSECSigner() error = %v", err)
			}
			assertDNSSECSigner(t, algorithm, signer, k.PublicKey, false)
			signAndVerifyRRSet(t, k, signer, k.PublicKey)

			// The private exponent is not checked against the key pair without
			// primes to multiply back together, so a private exponent that is
			// not the key's own is only noticed when it signs.
			priv, ok := signer.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("NewDNSSECSigner() returned %T, want *rsa.PrivateKey", signer)
			}
			priv.D.Add(priv.D, big.NewInt(1))
			rrset := buildVerifyTestRRSet(t)
			if _, err := SignRRSet(&rrset, priv, algorithm, 12345, k.Name, testInception, testExpiration); err == nil {
				t.Error("SignRRSet() signed with a private exponent that is not the key's own without an error")
			}
		})
	}

	t.Run("rejected without primes", func(t *testing.T) {
		// Without primes, the ranges the three numbers must be in are checked
		// instead: the values that cannot be a modulus, a public exponent or a
		// private exponent are rejected before anything is signed.  The public
		// exponent is rejected by the same range check whether or not the primes
		// are present.
		cases := []struct {
			name            string
			modulus         []byte
			publicExponent  []byte
			privateExponent []byte
			want            string
		}{
			{"modulus of one", []byte{1}, []byte{3}, []byte{1}, "the modulus must be at least 3"},
			{"even modulus", []byte{78}, []byte{3}, []byte{3}, "the modulus must be odd"},
			{"public exponent of one", []byte{55}, []byte{1}, []byte{3}, "invalid RSA public exponent"},
			{"public exponent not smaller than the modulus", []byte{55}, []byte{65, 161}, []byte{3}, "the public exponent must be smaller than the modulus"},
			{"private exponent equal to the modulus", []byte{1, 134, 163}, []byte{1, 1, 1}, []byte{1, 134, 163}, "the private exponent must be greater than 0 and smaller than the modulus"},
			{"private exponent of zero", []byte{1, 134, 163}, []byte{1, 1, 1}, []byte{0}, "the private exponent must be greater than 0 and smaller than the modulus"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				k := &DNSSECKey{
					Name:      testDomainName(t, "rsa.invalid."),
					Algorithm: 5,
					PrivateParams: map[string][]byte{
						"Modulus":         tc.modulus,
						"PublicExponent":  tc.publicExponent,
						"PrivateExponent": tc.privateExponent,
					},
				}

				_, err := NewDNSSECSigner(k)
				if err == nil {
					t.Fatal("NewDNSSECSigner() did not return an error")
				}
				if !errorContains(err, tc.want) {
					t.Errorf("NewDNSSECSigner() error = %v, want %q", err, tc.want)
				}
			})
		}
	})
}

func TestNewDNSSECSignerRSAPrimeMismatch(t *testing.T) {
	for _, algorithm := range []uint8{5, 7, 8, 10} {
		t.Run(algorithmName(algorithm), func(t *testing.T) {
			// The primes are a key pair only as a pair: their order in the file
			// does not matter, but a prime that is not one of the two is a key
			// that cannot be the key of the modulus it is given with.
			k := dnssecKeyFromTestKey(t, newVerifyTestKey(t, algorithm))
			swapped := &DNSSECKey{
				Name:          k.Name,
				Flags:         k.Flags,
				Protocol:      k.Protocol,
				Algorithm:     k.Algorithm,
				PublicKey:     append([]byte(nil), k.PublicKey...),
				PrivateParams: clonePrivateParams(k.PrivateParams),
			}
			swapped.PrivateParams["Prime1"], swapped.PrivateParams["Prime2"] =
				k.PrivateParams["Prime2"], k.PrivateParams["Prime1"]

			signer, err := NewDNSSECSigner(swapped)
			if err != nil {
				t.Fatalf("NewDNSSECSigner() with the primes in the other order error = %v", err)
			}
			assertDNSSECSigner(t, algorithm, signer, k.PublicKey, true)

			wrongPrime := &DNSSECKey{
				Name:          k.Name,
				Flags:         k.Flags,
				Protocol:      k.Protocol,
				Algorithm:     k.Algorithm,
				PublicKey:     append([]byte(nil), k.PublicKey...),
				PrivateParams: clonePrivateParams(k.PrivateParams),
			}
			wrongPrime.PrivateParams["Prime1"] = []byte{2}
			if _, err := NewDNSSECSigner(wrongPrime); err == nil {
				t.Error("NewDNSSECSigner() with a prime that is not one of the two did not return an error")
			}

			wrongExponent := &DNSSECKey{
				Name:          k.Name,
				Flags:         k.Flags,
				Protocol:      k.Protocol,
				Algorithm:     k.Algorithm,
				PublicKey:     append([]byte(nil), k.PublicKey...),
				PrivateParams: clonePrivateParams(k.PrivateParams),
			}
			d := new(big.Int).SetBytes(k.PrivateParams["PrivateExponent"])
			d.Add(d, big.NewInt(1))
			wrongExponent.PrivateParams["PrivateExponent"] = d.Bytes()
			if _, err := NewDNSSECSigner(wrongExponent); err == nil {
				t.Error("NewDNSSECSigner() with a private exponent that is not the key's own did not return an error")
			}
		})
	}
}

func TestNewDNSSECSignerIgnoresRSACRTParameters(t *testing.T) {
	// A .private file holds no Exponent1, Exponent2 or Coefficient: they are
	// computed from the primes when a key is used, so private parameters under
	// those names are not private key material and do not change the key.
	key := newVerifyTestKey(t, 8)
	signer, err := NewDNSSECSigner(dnssecKeyFromTestKey(t, key))
	if err != nil {
		t.Fatalf("NewDNSSECSigner() error = %v", err)
	}

	carrying := dnssecKeyFromTestKey(t, key)
	carrying.PrivateParams["Exponent1"] = []byte{1}
	carrying.PrivateParams["Exponent2"] = big.NewInt(65537).Bytes()
	carrying.PrivateParams["Coefficient"] = []byte{0, 9}
	other, err := NewDNSSECSigner(carrying)
	if err != nil {
		t.Fatalf("NewDNSSECSigner() error = %v", err)
	}

	// A private key is a private key: a signature is what it is used for, and
	// the same key signs the same bytes the same way.
	rrset := buildVerifyTestRRSet(t)
	name := testDomainName(t, "example.com.")
	first, err := SignRRSet(&rrset, signer, 8, 12345, name, testInception, testExpiration)
	if err != nil {
		t.Fatalf("SignRRSet() error = %v", err)
	}
	second, err := SignRRSet(&rrset, other, 8, 12345, name, testInception, testExpiration)
	if err != nil {
		t.Fatalf("SignRRSet() error = %v", err)
	}
	if !bytes.Equal(first.Signature, second.Signature) {
		t.Error("the signature differs: private parameters under the names of computed values were used as key material")
	}
}
