package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/internal"
)

type pgpSplitReader struct {
	encMessage, encSignature Reader
}

// pgpSplitReader implements the PGPSplitReader interface

func (mw *pgpSplitReader) Read(b []byte) (int, error) {
	return mw.encMessage.Read(b)
}

func (mw *pgpSplitReader) Signature() Reader {
	return mw.encSignature
}

func NewPGPSplitReader(pgpMessage Reader, pgpEncryptedSignature Reader) *pgpSplitReader {
	return &pgpSplitReader{
		encMessage:   pgpMessage,
		encSignature: pgpEncryptedSignature,
	}
}

// rewindReader resets a resettable input stream to its beginning.
func rewindReader(reader *internal.ResetReader) error {
	if _, err := reader.Reset(); err != nil {
		// Should not happen, since buffering is only disabled after a successful
		// decryption that is not retried anymore.
		return fmt.Errorf("gopenpgp: buffer reset failed: %w", err)
	}
	return nil
}

// verifyDecryptedCompletely reads the whole decrypted message, which triggers
// the integrity check of the encrypted data packet (MDC for SEIPD v1, AEAD tag
// for SEIPD v2) and the parsing of all trailing packets. It returns an error if
// the data packet was not decrypted correctly, i.e. if the session key or
// password was wrong. Signature verification errors are not reported here.
func verifyDecryptedCompletely(md *openpgp.MessageDetails) error {
	_, err := io.Copy(io.Discard, md.UnverifiedBody)
	return err
}

// decryptStream decrypts the stream either with the secret keys or a password.
// The message reader has to be resettable, so that the password candidates can
// be tried one after another, each starting at the beginning of the message.
func (dh *decryptionHandle) decryptStream(encryptedMessage *internal.ResetReader) (plainMessage *VerifyDataReader, err error) {
	var entries openpgp.EntityList

	config := dh.decryptionConfig(dh.clock().Unix())
	if dh.DecryptionKeyRing != nil {
		entries = dh.DecryptionKeyRing.entities
	}

	if dh.VerifyKeyRing != nil {
		entries = append(entries, dh.VerifyKeyRing.entities...)
	}

	if dh.VerificationContext != nil {
		config.KnownNotations = map[string]bool{constants.SignatureContextName: true}
	}

	var messageDetails *openpgp.MessageDetails
	if dh.DecryptionKeyRing != nil {
		// Private key based decryption
		messageDetails, err = openpgp.ReadMessage(encryptedMessage, entries, nil, config)
		if err != nil {
			return nil, fmt.Errorf("gopenpgp: decrypting message with private keys failed: %w", err)
		}
	} else {
		// Password based decryption
		var foundPassword = false
		// Same argument as for the session key candidates above: a wrong password
		// is only reliably detected when the decrypted data has been read to the
		// end, so the password has to be verified completely before it is selected
		// if another password candidate could still be tried.
		verifyCompletely := len(dh.Passwords) > 1
		for i, password := range dh.Passwords {
			if i > 0 {
				// Every candidate has to start at the beginning of the message,
				// because the previous candidate consumed its headers.
				if err := rewindReader(encryptedMessage); err != nil {
					return nil, err
				}
			}
			prompt := createPasswordPrompt(password)
			messageDetails, err = openpgp.ReadMessage(encryptedMessage, entries, prompt, config)
			if err != nil {
				continue
			}
			if verifyCompletely {
				if err = verifyDecryptedCompletely(messageDetails); err != nil {
					continue
				}
				// The password is correct; open the message once more to read the
				// plaintext as a stream.
				if err := rewindReader(encryptedMessage); err != nil {
					return nil, err
				}
				messageDetails, err = openpgp.ReadMessage(encryptedMessage, entries, createPasswordPrompt(password), config)
				if err != nil {
					return nil, fmt.Errorf("gopenpgp: decrypting message with password failed: %w", err)
				}
			}
			foundPassword = true
			break
		}
		if !foundPassword {
			// Parsing errors when reading the message are most likely caused by incorrect password, but we cannot know for sure
			return nil, errors.New("gopenpgp: error in reading password protected message: wrong password or malformed message")
		}
	}

	// Add utf8 sanitizer if signature has type packet.SigTypeText
	internalReader := messageDetails.UnverifiedBody
	if messageDetails.IsSigned &&
		!dh.DisableAutomaticTextSanitize &&
		len(messageDetails.SignatureCandidates) > 0 &&
		messageDetails.SignatureCandidates[len(messageDetails.SignatureCandidates)-1].SigType == packet.SigTypeText {
		// TODO: This currently assumes that only one type of signature
		// can be present.
		internalReader = internal.NewSanitizeReader(internalReader)
	}
	return &VerifyDataReader{
		messageDetails,
		internalReader,
		dh.VerifyKeyRing,
		config.Time().Unix(),
		dh.DisableVerifyTimeCheck,
		false,
		dh.VerificationContext,
	}, nil
}

func (dh *decryptionHandle) decryptStreamWithSession(dataPacketReader *internal.ResetReader) (plainMessage *VerifyDataReader, err error) {
	messageDetails, verifyTime, err := dh.decryptStreamWithSessionAndParse(dataPacketReader)
	if err != nil {
		return nil, fmt.Errorf("gopenpgp: error in reading message: %w", err)
	}

	// Add utf8 sanitizer if signature has type packet.SigTypeText
	internalReader := messageDetails.UnverifiedBody
	if messageDetails.IsSigned &&
		!dh.DisableAutomaticTextSanitize &&
		len(messageDetails.SignatureCandidates) > 0 &&
		messageDetails.SignatureCandidates[len(messageDetails.SignatureCandidates)-1].SigType == packet.SigTypeText {
		// TODO: This currently assumes that only one type of signature
		// can be present.
		internalReader = internal.NewSanitizeReader(internalReader)
	}
	return &VerifyDataReader{
		messageDetails,
		internalReader,
		dh.VerifyKeyRing,
		verifyTime,
		dh.DisableVerifyTimeCheck,
		false,
		dh.VerificationContext,
	}, err
}

// decryptStreamWithSessionAndParse tries the configured session key candidates
// one after another. Every attempt starts at the beginning of the message stream:
// an attempt consumes the packet headers (and part of the ciphertext) of the
// message, so the stream has to be rewound before the next candidate is tried.
// The first attempt that decrypts the data packet *and* yields a parseable
// message is selected; only then buffering is disabled so that the plaintext
// can be read as a stream.
func (dh *decryptionHandle) decryptStreamWithSessionAndParse(messageReader *internal.ResetReader) (*openpgp.MessageDetails, int64, error) {
	var keyring openpgp.EntityList
	var decrypted io.ReadCloser
	var selectedSessionKey *SessionKey
	var md *openpgp.MessageDetails
	var err error

	if dh.VerifyKeyRing != nil {
		keyring = append(keyring, dh.VerifyKeyRing.entities...)
	}
	if dh.DecryptionKeyRing != nil {
		keyring = append(keyring, dh.DecryptionKeyRing.entities...)
	}

	config := dh.decryptionConfig(dh.clock().Unix())
	checkPacketSequence := false
	config.CheckPacketSequence = &checkPacketSequence

	if dh.VerificationContext != nil {
		config.KnownNotations = map[string]bool{constants.SignatureContextName: true}
	}

	// Try the session key candidates. The stream is rewound before every
	// attempt, because a failed attempt may have consumed the stream headers.
	//
	// Opening the data packet does not prove that the session key is correct:
	// the integrity check of SEIPD v1 (MDC) and v2 (AEAD tag) is only performed
	// once the decrypted data has been read to the end. If another candidate or
	// another decryption method could still be tried, a candidate whose garbage
	// plaintext happens to parse as a valid packet would be selected and would
	// hide the correct one. Therefore the candidate is verified completely
	// before it is selected in that case, and reopened afterwards for streaming.
	verifyCompletely := len(dh.SessionKeys) > 1 || dh.DecryptionKeyRing != nil || len(dh.Passwords) > 0
	for i, sessionKeyCandidate := range dh.SessionKeys {
		if i > 0 {
			// Every candidate has to start at the beginning of the message,
			// because the previous candidate consumed its headers.
			if err := rewindReader(messageReader); err != nil {
				return nil, 0, err
			}
		}
		decrypted, err = decryptStreamWithSessionKey(sessionKeyCandidate, messageReader)
		if err != nil {
			continue
		}
		// A wrong session key is not detected while opening the packet stream in
		// all cases, in particular not for SEIPD v1. Parsing the decrypted
		// packets detects such a candidate, before it is selected.
		md, err = openpgp.ReadMessage(decrypted, keyring, nil, config)
		if err != nil {
			_ = decrypted.Close()
			decrypted = nil
			continue
		}
		if verifyCompletely {
			if err = verifyDecryptedCompletely(md); err != nil {
				_ = decrypted.Close()
				decrypted = nil
				continue
			}
			// Reopen the selected candidate, so that the plaintext can still be
			// read as a stream by the caller.
			if err = rewindReader(messageReader); err != nil {
				return nil, 0, err
			}
			decrypted, err = decryptStreamWithSessionKey(sessionKeyCandidate, messageReader)
			if err != nil {
				continue
			}
			md, err = openpgp.ReadMessage(decrypted, keyring, nil, config)
			if err != nil {
				_ = decrypted.Close()
				decrypted = nil
				continue
			}
		}
		selectedSessionKey = sessionKeyCandidate
		break
	}
	if selectedSessionKey == nil {
		if err == nil {
			err = errors.New("gopenpgp: no session key candidates provided")
		}
		return nil, 0, fmt.Errorf("gopenpgp: unable to decrypt message with session key: %w", err)
	}

	md.SessionKey = selectedSessionKey.Key
	md.UnverifiedBody = checkReader{decrypted, md.UnverifiedBody}
	return md, config.Time().Unix(), nil
}

func decryptStreamWithSessionKey(sessionKey *SessionKey, messageReader io.Reader) (io.ReadCloser, error) {
	var decrypted io.ReadCloser
	// Read symmetrically encrypted data packet
Loop:
	for {
		packets := packet.NewReader(messageReader)
		p, err := packets.Next()
		if err != nil {
			return nil, fmt.Errorf("gopenpgp: unable to read symmetric packet: %w", err)
		}

		// Decrypt data packet
		switch p := p.(type) {
		case *packet.EncryptedKey, *packet.SymmetricKeyEncrypted:
			// Ignore potential key packets
			continue
		case *packet.SymmetricallyEncrypted, *packet.AEADEncrypted:
			if symPacket, ok := p.(*packet.SymmetricallyEncrypted); ok {
				if !symPacket.IntegrityProtected {
					return nil, errors.New("gopenpgp: message is not authenticated")
				}
			}
			var dc packet.CipherFunction
			if sessionKey.hasAlgorithm() {
				dc, err = sessionKey.GetCipherFunc()
				if err != nil {
					return nil, fmt.Errorf("gopenpgp: unable to decrypt with session key: %w", err)
				}
			}
			encryptedDataPacket, isDataPacket := p.(packet.EncryptedDataPacket)
			if !isDataPacket {
				return nil, fmt.Errorf("gopenpgp: unknown data packet: %w", err)
			}
			decrypted, err = encryptedDataPacket.Decrypt(dc, sessionKey.Key)
			if err != nil {
				return nil, fmt.Errorf("gopenpgp: unable to decrypt symmetric packet: %w", err)
			}
			break Loop
		default:
			return nil, errors.New("gopenpgp: invalid packet type")
		}
	}
	return decrypted, nil
}

func (dh *decryptionHandle) decryptStreamAndVerifyDetached(encryptedData, encryptedSignature *internal.ResetReader, isPlaintextSignature bool) (plainMessage *VerifyDataReader, err error) {
	verifyTime := dh.clock().Unix()
	var mdData *openpgp.MessageDetails
	var signature io.Reader = encryptedSignature
	// Decrypt both messages. The signature stream is rewound by the caller's
	// decryption attempts, just like the data stream, so each method always starts
	// at the beginning of the respective input.
	if len(dh.SessionKeys) > 0 {
		// Decrypt with session key.
		mdData, _, err = dh.decryptStreamWithSessionAndParse(encryptedData)
		if err != nil {
			return nil, fmt.Errorf("gopenpgp: error in reading data message: %w", err)
		}
		if !isPlaintextSignature {
			// Decrypting reader for the encrypted signature
			mdSig, _, err := dh.decryptStreamWithSessionAndParse(encryptedSignature)
			if err != nil {
				return nil, fmt.Errorf("gopenpgp: error in reading detached signature message: %w", err)
			}
			signature = mdSig.UnverifiedBody
		}
	} else {
		// Password or private keys
		config := dh.decryptionConfig(verifyTime)
		var entries openpgp.EntityList
		if dh.DecryptionKeyRing != nil {
			entries = append(entries, dh.DecryptionKeyRing.entities...)
		}
		// Decrypting reader for the encrypted data
		var selectedPassword []byte
		if len(dh.Passwords) > 0 {
			// Same argument as in decryptStream: a wrong password is only
			// reliably detected when the decrypted data has been read to the end,
			// so a password has to be verified completely before it is selected if
			// another password candidate could still be tried.
			verifyCompletely := len(dh.Passwords) > 1
			for i, passwordCandidate := range dh.Passwords {
				if i > 0 {
					// Every candidate has to start at the beginning of the message,
					// because the previous candidate consumed its headers.
					if err := rewindReader(encryptedData); err != nil {
						return nil, err
					}
				}
				mdData, err = openpgp.ReadMessage(encryptedData, entries, createPasswordPrompt(passwordCandidate), config)
				if err != nil {
					continue
				}
				if verifyCompletely {
					if err = verifyDecryptedCompletely(mdData); err != nil {
						continue
					}
					// The password is correct; open the message once more to read
					// the plaintext as a stream.
					if err := rewindReader(encryptedData); err != nil {
						return nil, err
					}
					mdData, err = openpgp.ReadMessage(encryptedData, entries, createPasswordPrompt(passwordCandidate), config)
					if err != nil {
						return nil, fmt.Errorf("gopenpgp: decrypting message with password failed: %w", err)
					}
				}
				selectedPassword = passwordCandidate
				break
			}
			if selectedPassword == nil {
				return nil, fmt.Errorf("gopenpgp: error in reading data message: no password matched: %w", err)
			}
		} else {
			mdData, err = openpgp.ReadMessage(encryptedData, entries, nil, config)
			if err != nil {
				return nil, fmt.Errorf("gopenpgp: error in reading data message: %w", err)
			}
		}

		if !isPlaintextSignature {
			// Decrypting reader for the encrypted signature
			prompt := createPasswordPrompt(selectedPassword)
			noCheckPacketSequence := false
			config.CheckPacketSequence = &noCheckPacketSequence
			mdSig, err := openpgp.ReadMessage(encryptedSignature, entries, prompt, config)
			if err != nil {
				return nil, fmt.Errorf("gopenpgp: error in reading detached signature message: %w", err)
			}
			signature = mdSig.UnverifiedBody
		}
	}

	config := dh.decryptionConfig(verifyTime)

	// Verifying reader that wraps the decryption readers to verify the signature
	sigVerifyReader, err := verifyingDetachedReader(
		mdData.UnverifiedBody,
		signature,
		dh.VerifyKeyRing,
		dh.VerificationContext,
		dh.DisableVerifyTimeCheck,
		dh.DisableAutomaticTextSanitize,
		config,
		NewConstantClock(verifyTime),
	)
	if err != nil {
		return nil, err
	}
	// Update message details with information from the data of the pgp message
	sigVerifyReader.details.LiteralData = mdData.LiteralData
	sigVerifyReader.details.SessionKey = mdData.SessionKey
	return sigVerifyReader, nil
}

func getSignaturePacket(sig []byte) (*packet.Signature, error) {
	p, err := packet.Read(bytes.NewReader(sig))
	if err != nil {
		return nil, err
	}
	sigPacket, ok := p.(*packet.Signature)
	if !ok {
		return nil, fmt.Errorf("gopenpgp: invalid signature packet: %w", err)
	}
	return sigPacket, nil
}

func createPasswordPrompt(password []byte) func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	if password == nil {
		return nil
	}
	firstTimeCalled := true
	return func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if firstTimeCalled {
			firstTimeCalled = false
			return password, nil
		}
		// Re-prompt still occurs if SKESK pasrsing fails (i.e. when decrypted cipher algo is invalid).
		// For most (but not all) cases, inputting a wrong passwords is expected to trigger this error.
		return nil, errors.New("gopenpgp: wrong password in symmetric decryption")
	}
}

func (dh *decryptionHandle) decryptionConfig(configTime int64) *packet.Config {
	config := dh.profile.EncryptionConfig()

	// Check intended recipients in signatures.
	checkIntendedRecipients := !dh.DisableIntendedRecipients
	config.CheckIntendedRecipients = &checkIntendedRecipients

	// Check for valid packet sequence
	checkPacketSequence := !dh.DisableStrictMessageParsing
	config.CheckPacketSequence = &checkPacketSequence

	// Allow message decryption of PGP messages with no integrity tag.
	config.InsecureAllowUnauthenticatedMessages = dh.InsecureDisableUnauthenticatedMessagesCheck

	// Allow message decryption with signature keys.
	if dh.InsecureAllowDecryptionWithSigningKeys {
		config.InsecureAllowDecryptionWithSigningKeys = dh.InsecureAllowDecryptionWithSigningKeys
	}

	// Should the session key be returned.
	config.CacheSessionKey = dh.RetrieveSessionKey

	// Set max decompression size if set.
	if dh.MaxDecompressedSize != 0 {
		config.MaxDecompressedMessageSize = &dh.MaxDecompressedSize
	}

	// Set time.
	config.Time = NewConstantClock(configTime)
	return config
}
