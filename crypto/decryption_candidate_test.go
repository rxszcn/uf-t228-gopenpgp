package crypto

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

// multiCandidateTestMaterial bundles a message version with the material needed
// to exercise the session key candidate traversal and the decryption fallback chain.
type multiCandidateTestMaterial struct {
	name           string
	pgp            *PGPHandle
	sessionKey     *SessionKey
	keyRingPublic  *KeyRing
	keyRingPrivate *KeyRing
}

// multiCandidateTestMaterials returns test material for a v4 (SEIPDv1) and a
// v6 (SEIPDv2) message. The session keys are created explicitly for the respective
// version, so that the tests do not depend on the profile defaults.
func multiCandidateTestMaterials(t *testing.T) []*multiCandidateTestMaterial {
	t.Helper()

	materials := make([]*multiCandidateTestMaterial, 0, 2)
	for _, testCase := range []struct {
		name      string
		profile   *profile.Custom
		sessionV6 bool
	}{
		{name: "v4", profile: profile.RFC4880(), sessionV6: false},
		{name: "v6", profile: profile.RFC9580(), sessionV6: true},
	} {
		pgpHandle := PGPWithProfile(testCase.profile)
		pgpHandle.defaultTime = NewConstantClock(testTime)

		token, err := RandomToken(32)
		if err != nil {
			t.Fatalf("Expected no error while generating session key token, got: %v", err)
		}
		sessionKey := NewSessionKeyFromTokenWithAead(token, constants.AES256, testCase.sessionV6)

		key, err := pgpHandle.KeyGeneration().
			AddUserId("test", "test@test.test").
			New().
			GenerateKey()
		if err != nil {
			t.Fatalf("Expected no error while generating key, got: %v", err)
		}
		publicKey, err := key.ToPublic()
		if err != nil {
			t.Fatalf("Expected no error while extracting public key, got: %v", err)
		}
		publicKeyRing, err := NewKeyRing(publicKey)
		if err != nil {
			t.Fatalf("Expected no error while creating public key ring, got: %v", err)
		}
		privateKeyRing, err := NewKeyRing(key)
		if err != nil {
			t.Fatalf("Expected no error while creating private key ring, got: %v", err)
		}

		materials = append(materials, &multiCandidateTestMaterial{
			name:           testCase.name,
			pgp:            pgpHandle,
			sessionKey:     sessionKey,
			keyRingPublic:  publicKeyRing,
			keyRingPrivate: privateKeyRing,
		})
	}
	return materials
}

// wrongSessionKey returns a copy of the session key with a corrupted key, i.e. a
// candidate that has the right algorithm and length but does not decrypt the message.
func wrongSessionKey(t *testing.T, sessionKey *SessionKey) *SessionKey {
	t.Helper()

	wrongKey := make([]byte, len(sessionKey.Key))
	copy(wrongKey, sessionKey.Key)
	wrongKey[0] ^= 0xff
	return NewSessionKeyFromTokenWithAead(wrongKey, sessionKey.Algo, sessionKey.IsV6())
}

// encryptWithSessionKey encrypts the message with the given session key, without
// recipients, i.e. the message can only be decrypted with the session key.
func encryptWithSessionKey(t *testing.T, material *multiCandidateTestMaterial, sessionKey *SessionKey) []byte {
	t.Helper()

	encHandle, err := material.pgp.Encryption().SessionKey(sessionKey).New()
	if err != nil {
		t.Fatalf("Expected no error while creating encryption handle, got: %v", err)
	}
	pgpMessage, err := encHandle.Encrypt([]byte(testMessageString))
	if err != nil {
		t.Fatalf("Expected no error while encrypting, got: %v", err)
	}
	return pgpMessage.Bytes()
}

// encryptToRecipientWithSessionKey encrypts the message towards the recipient key
// using the given session key, i.e. the message can be decrypted with the private
// key as well as with the session key.
func encryptToRecipientWithSessionKey(t *testing.T, material *multiCandidateTestMaterial, sessionKey *SessionKey) []byte {
	t.Helper()

	encHandle, err := material.pgp.Encryption().
		Recipients(material.keyRingPublic).
		SessionKey(sessionKey).
		New()
	if err != nil {
		t.Fatalf("Expected no error while creating encryption handle, got: %v", err)
	}
	pgpMessage, err := encHandle.Encrypt([]byte(testMessageString))
	if err != nil {
		t.Fatalf("Expected no error while encrypting, got: %v", err)
	}
	return pgpMessage.Bytes()
}

// TestSessionKeyCandidatesAfterWrongCandidate verifies that a wrong session key
// candidate at the front of the candidate list does not prevent the correct
// candidate behind it from decrypting the message. Without rewinding the input
// stream between the candidates, the correct candidate starts parsing in the
// middle of the message and the decryption fails depending on the candidate order.
func TestSessionKeyCandidatesAfterWrongCandidate(t *testing.T) {
	for _, material := range multiCandidateTestMaterials(t) {
		t.Run(material.name, func(t *testing.T) {
			pgpMessage := encryptWithSessionKey(t, material, material.sessionKey)

			decHandle, err := material.pgp.Decryption().
				SessionKeys([]*SessionKey{
					wrongSessionKey(t, material.sessionKey),
					material.sessionKey,
				}).
				New()
			if err != nil {
				t.Fatalf("Expected no error while creating decryption handle, got: %v", err)
			}
			decResult, err := decHandle.Decrypt(pgpMessage, Bytes)
			if err != nil {
				t.Fatalf("Expected no error while decrypting with the correct candidate, got: %v", err)
			}
			if !bytes.Equal(decResult.Bytes(), []byte(testMessageString)) {
				t.Fatalf("Expected plaintext %q, got %q", testMessageString, decResult.Bytes())
			}
			if !bytes.Equal(decResult.SessionKey().Key, material.sessionKey.Key) {
				t.Fatal("Expected the decrypted session key to be the correct candidate")
			}
		})
	}
}

// TestSessionKeyCandidateFallbackToPrivateKey verifies that a wrong session key
// candidate which consumed part of the input stream does not prevent the fallback
// to decryption with the private key.
func TestSessionKeyCandidateFallbackToPrivateKey(t *testing.T) {
	for _, material := range multiCandidateTestMaterials(t) {
		t.Run(material.name, func(t *testing.T) {
			pgpMessage := encryptToRecipientWithSessionKey(t, material, material.sessionKey)

			decHandle, err := material.pgp.Decryption().
				SessionKey(wrongSessionKey(t, material.sessionKey)).
				DecryptionKeys(material.keyRingPrivate).
				New()
			if err != nil {
				t.Fatalf("Expected no error while creating decryption handle, got: %v", err)
			}
			decResult, err := decHandle.Decrypt(pgpMessage, Bytes)
			if err != nil {
				t.Fatalf("Expected no error while decrypting with the private key fallback, got: %v", err)
			}
			if !bytes.Equal(decResult.Bytes(), []byte(testMessageString)) {
				t.Fatalf("Expected plaintext %q, got %q", testMessageString, decResult.Bytes())
			}
		})
	}
}

// TestWrongSessionKeyCandidateAloneFails verifies that a wrong session key is
// still rejected if it is the only available decryption material.
func TestWrongSessionKeyCandidateAloneFails(t *testing.T) {
	for _, material := range multiCandidateTestMaterials(t) {
		t.Run(material.name, func(t *testing.T) {
			pgpMessage := encryptWithSessionKey(t, material, material.sessionKey)

			decHandle, err := material.pgp.Decryption().
				SessionKey(wrongSessionKey(t, material.sessionKey)).
				New()
			if err != nil {
				t.Fatalf("Expected no error while creating decryption handle, got: %v", err)
			}
			if _, err = decHandle.Decrypt(pgpMessage, Bytes); err == nil {
				t.Fatal("Expected an error while decrypting with a wrong session key")
			}
		})
	}
}

// TestPasswordCandidatesAfterWrongPassword verifies the same property for the
// password candidate traversal, which shares the input stream handling.
func TestPasswordCandidatesAfterWrongPassword(t *testing.T) {
	for _, material := range multiCandidateTestMaterials(t) {
		t.Run(material.name, func(t *testing.T) {
			encHandle, err := material.pgp.Encryption().Password(password).New()
			if err != nil {
				t.Fatalf("Expected no error while creating encryption handle, got: %v", err)
			}
			pgpMessage, err := encHandle.Encrypt([]byte(testMessageString))
			if err != nil {
				t.Fatalf("Expected no error while encrypting, got: %v", err)
			}

			decHandle, err := material.pgp.Decryption().
				Passwords([][]byte{wrongPassword, password}).
				New()
			if err != nil {
				t.Fatalf("Expected no error while creating decryption handle, got: %v", err)
			}
			decResult, err := decHandle.Decrypt(pgpMessage.Bytes(), Bytes)
			if err != nil {
				t.Fatalf("Expected no error while decrypting with the correct password, got: %v", err)
			}
			if !bytes.Equal(decResult.Bytes(), []byte(testMessageString)) {
				t.Fatalf("Expected plaintext %q, got %q", testMessageString, decResult.Bytes())
			}
		})
	}
}

// TestSessionKeyCandidatesForDetachedSignature verifies that the candidate
// traversal of the data message and of the encrypted detached signature do not
// interfere, i.e. that both streams are rewound per candidate.
func TestSessionKeyCandidatesForDetachedSignature(t *testing.T) {
	for _, material := range multiCandidateTestMaterials(t) {
		t.Run(material.name, func(t *testing.T) {
			encHandle, err := material.pgp.Encryption().
				SessionKey(material.sessionKey).
				SigningKeys(material.keyRingPrivate).
				DetachedSignature().
				New()
			if err != nil {
				t.Fatalf("Expected no error while creating encryption handle, got: %v", err)
			}
			var keyPackets, ciphertext, signature bytes.Buffer
			messageWriter, err := encHandle.EncryptingWriter(
				NewPGPSplitWriter(&keyPackets, &ciphertext, &signature),
				Bytes,
			)
			if err != nil {
				t.Fatalf("Expected no error while creating message writer, got: %v", err)
			}
			if _, err = messageWriter.Write([]byte(testMessageString)); err != nil {
				t.Fatalf("Expected no error while writing, got: %v", err)
			}
			if err = messageWriter.Close(); err != nil {
				t.Fatalf("Expected no error while closing, got: %v", err)
			}

			decHandle, err := material.pgp.Decryption().
				SessionKeys([]*SessionKey{
					wrongSessionKey(t, material.sessionKey),
					material.sessionKey,
				}).
				VerificationKeys(material.keyRingPublic).
				New()
			if err != nil {
				t.Fatalf("Expected no error while creating decryption handle, got: %v", err)
			}
			splitReader := NewPGPSplitReader(
				bytes.NewReader(ciphertext.Bytes()),
				bytes.NewReader(signature.Bytes()),
			)
			decryptedReader, err := decHandle.DecryptingReader(splitReader, Bytes)
			if err != nil {
				t.Fatalf("Expected no error while decrypting and verifying, got: %v", err)
			}
			decResult, err := decryptedReader.ReadAllAndVerifySignature()
			if err != nil {
				t.Fatalf("Expected no error while reading and verifying, got: %v", err)
			}
			if !bytes.Equal(decResult.Bytes(), []byte(testMessageString)) {
				t.Fatalf("Expected plaintext %q, got %q", testMessageString, decResult.Bytes())
			}
			if err = decResult.SignatureError(); err != nil {
				t.Fatalf("Expected no signature error, got: %v", err)
			}
		})
	}
}
