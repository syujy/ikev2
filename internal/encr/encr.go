package encr

import (
	"errors"
	"ike/internal/logger"
	"ike/internal/types"
	"ike/message"

	"github.com/sirupsen/logrus"
)

var encrLog *logrus.Entry
var encrString map[uint16]func(uint16, uint16, []byte) string

var encrTypes map[string]ENCRType
var encrKTypes map[string]ENCRKType

func init() {
	// Log
	encrLog = logger.ENCRLog

	// ENCR String
	encrString = make(map[uint16]func(uint16, uint16, []byte) string)
	encrString[types.ENCR_AES_CBC] = toString_ENCR_AES_CBC

	// ENCR Types
	encrTypes = make(map[string]ENCRType)

	encrTypes[String_ENCR_AES_CBC_128] = &ENCR_AES_CBC{
		keyLength: 16,
	}
	encrTypes[String_ENCR_AES_CBC_192] = &ENCR_AES_CBC{
		keyLength: 24,
	}
	encrTypes[String_ENCR_AES_CBC_256] = &ENCR_AES_CBC{
		keyLength: 32,
	}

	// Default Priority
	priority := []string{
		String_ENCR_AES_CBC_128,
		String_ENCR_AES_CBC_192,
		String_ENCR_AES_CBC_256,
	}

	// Set Priority
	for i, s := range priority {
		if encrType, ok := encrTypes[s]; ok {
			encrType.setPriority(uint32(i))
		} else {
			encrLog.Error("No such ENCR implementation")
			panic("IKE ENCR failed to init.")
		}
	}

	// ENCR Kernel Types
	encrKTypes = make(map[string]ENCRKType)

	encrKTypes[String_ENCR_AES_CBC_128] = &ENCR_AES_CBC{
		keyLength: 16,
	}
	encrKTypes[String_ENCR_AES_CBC_192] = &ENCR_AES_CBC{
		keyLength: 24,
	}
	encrKTypes[String_ENCR_AES_CBC_256] = &ENCR_AES_CBC{
		keyLength: 32,
	}

	// ENCR Kernel Priority same as above
	// Set Priority
	for i, s := range priority {
		if encrKType, ok := encrKTypes[s]; ok {
			encrKType.setPriority(uint32(i))
		} else {
			encrLog.Error("No such ENCR implementation")
			panic("IKE ENCR failed to init.")
		}
	}

}

func SetPriority(algolist []string) error {
	// check implemented
	for _, algo := range algolist {
		if _, ok := encrTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for i, algo := range algolist {
		encrTypes[algo].setPriority(uint32(i))
	}
	return nil
}

func SetKPriority(algolist []string) error {
	// check implemented
	for _, algo := range algolist {
		if _, ok := encrKTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for i, algo := range algolist {
		encrKTypes[algo].setPriority(uint32(i))
	}
	return nil
}

func StrToType(algo string) ENCRType {
	if t, ok := encrTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToKType(algo string) ENCRKType {
	if t, ok := encrKTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) ENCRType {
	if f, ok := encrString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if encrType, ok := encrTypes[s]; ok {
				return encrType
			} else {
				return nil
			}
		} else {
			return nil
		}
	} else {
		return nil
	}
}

func ToTransform(encrType ENCRType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = types.TypeEncryptionAlgorithm
	t.TransformID = encrType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = encrType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = 1 // TV
	}
	return t
}

func DecodeTransformChildSA(transform *message.Transform) ENCRKType {
	if f, ok := encrString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if encrKType, ok := encrKTypes[s]; ok {
				return encrKType
			} else {
				return nil
			}
		} else {
			return nil
		}
	} else {
		return nil
	}
}

func ToTransformChildSA(encrKType ENCRKType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = types.TypeEncryptionAlgorithm
	t.TransformID = encrKType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = encrKType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = 1 // TV
	}
	return t
}

type ENCRType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	Init(key []byte) types.IKECrypto
}

type ENCRKType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	XFRMString() string
}

/* Archive for future use
type XFRMEncryptionAlgorithmType uint16

func (xfrmEncryptionAlgorithmType XFRMEncryptionAlgorithmType) String() string {
	switch xfrmEncryptionAlgorithmType {
	case message.ENCR_DES:
		return "cbc(des)"
	case message.ENCR_3DES:
		return "cbc(des3_ede)"
	case message.ENCR_CAST:
		return "cbc(cast5)"
	case message.ENCR_BLOWFISH:
		return "cbc(blowfish)"
	case message.ENCR_NULL:
		return "ecb(cipher_null)"
	case message.ENCR_AES_CBC:
		return "cbc(aes)"
	case message.ENCR_AES_CTR:
		return "rfc3686(ctr(aes))"
	default:
		return ""
	}
}
*/

/*
// Encryption Algorithm
func EncryptMessage(key []byte, originData []byte, algorithmType uint16) ([]byte, error) {
	switch algorithmType {
	case message.ENCR_AES_CBC:
		// padding message
		originData = PKCS7Padding(originData, aes.BlockSize)
		originData[len(originData)-1]--

		block, err := aes.NewCipher(key)
		if err != nil {
			secLog.Errorf("Error occur when create new cipher: %+v", err)
			return nil, errors.New("Create cipher failed")
		}

		cipherText := make([]byte, aes.BlockSize+len(originData))
		initializationVector := cipherText[:aes.BlockSize]

		_, err = io.ReadFull(rand.Reader, initializationVector)
		if err != nil {
			secLog.Errorf("Read random failed: %+v", err)
			return nil, errors.New("Read random initialization vector failed")
		}

		cbcBlockMode := cipher.NewCBCEncrypter(block, initializationVector)
		cbcBlockMode.CryptBlocks(cipherText[aes.BlockSize:], originData)

		return cipherText, nil
	default:
		secLog.Errorf("Unsupported encryption algorithm: %d", algorithmType)
		return nil, errors.New("Unsupported algorithm")
	}
}

func DecryptMessage(key []byte, cipherText []byte, algorithmType uint16) ([]byte, error) {
	switch algorithmType {
	case message.ENCR_AES_CBC:
		if len(cipherText) < aes.BlockSize {
			secLog.Error("Length of cipher text is too short to decrypt")
			return nil, errors.New("Cipher text is too short")
		}

		initializationVector := cipherText[:aes.BlockSize]
		encryptedMessage := cipherText[aes.BlockSize:]

		if len(encryptedMessage)%aes.BlockSize != 0 {
			secLog.Error("Cipher text is not a multiple of block size")
			return nil, errors.New("Cipher text length error")
		}

		plainText := make([]byte, len(encryptedMessage))

		block, err := aes.NewCipher(key)
		if err != nil {
			secLog.Errorf("Error occur when create new cipher: %+v", err)
			return nil, errors.New("Create cipher failed")
		}
		cbcBlockMode := cipher.NewCBCDecrypter(block, initializationVector)
		cbcBlockMode.CryptBlocks(plainText, encryptedMessage)

		secLog.Tracef("Decrypted content:\n%s", hex.Dump(plainText))

		padding := int(plainText[len(plainText)-1]) + 1
		plainText = plainText[:len(plainText)-padding]

		secLog.Tracef("Decrypted content with out padding:\n%s", hex.Dump(plainText))

		return plainText, nil
	default:
		secLog.Errorf("Unsupported encryption algorithm: %d", algorithmType)
		return nil, errors.New("Unsupported algorithm")
	}
}
*/
