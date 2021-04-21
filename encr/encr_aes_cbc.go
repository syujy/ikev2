package encr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"bitbucket.org/_syujy/ike/internal/lib"
	types "bitbucket.org/_syujy/ike/types"
)

const (
	String_ENCR_AES_CBC_128 string = "ENCR_AES_CBC_128"
	String_ENCR_AES_CBC_192 string = "ENCR_AES_CBC_192"
	String_ENCR_AES_CBC_256 string = "ENCR_AES_CBC_256"
)

func toString_ENCR_AES_CBC(attrType uint16, intValue uint16, bytesValue []byte) string {
	if attrType == types.AttributeTypeKeyLength {
		switch intValue {
		case 128:
			return String_ENCR_AES_CBC_128
		case 192:
			return String_ENCR_AES_CBC_192
		case 256:
			return String_ENCR_AES_CBC_256
		default:
			return ""
		}
	} else {
		return ""
	}
}

var _ ENCRType = &ENCR_AES_CBC{}
var _ ENCRKType = &ENCR_AES_CBC{}

type ENCR_AES_CBC struct {
	priority  uint32
	keyLength int
}

func (t *ENCR_AES_CBC) transformID() uint16 {
	return types.ENCR_AES_CBC
}

func (t *ENCR_AES_CBC) getAttribute() (bool, uint16, uint16, []byte) {
	return true, types.AttributeTypeKeyLength, uint16(t.keyLength * 8), nil
}

func (t *ENCR_AES_CBC) setPriority(priority uint32) {
	t.priority = priority
}

func (t *ENCR_AES_CBC) Priority() uint32 {
	return t.priority
}

func (t *ENCR_AES_CBC) GetKeyLength() int {
	return t.keyLength
}

func (t *ENCR_AES_CBC) Init(key []byte) (IKECrypto, error) {
	var err error
	encr := new(ENCR_AES_CBC_Crypto)
	if len(key) != t.keyLength {
		return nil, errors.New("Key length not matched")
	}
	if encr.block, err = aes.NewCipher(key); err != nil {
		return nil, fmt.Errorf("Error occur when create new cipher: %+v", err)
	} else {
		return encr, nil
	}
}

func (t *ENCR_AES_CBC) XFRMString() string {
	return "cbc(aes)"
}

var _ IKECrypto = &ENCR_AES_CBC_Crypto{}

type ENCR_AES_CBC_Crypto struct {
	block cipher.Block
}

func (encr *ENCR_AES_CBC_Crypto) Encrypt(plainText []byte) ([]byte, error) {
	// Padding message
	plainText = lib.PKCS7Padding(plainText, aes.BlockSize)
	plainText[len(plainText)-1]--

	// Slice
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	initializationVector := cipherText[:aes.BlockSize]

	// IV
	_, err := io.ReadFull(rand.Reader, initializationVector)
	if err != nil {
		return nil, fmt.Errorf("Read random initialization vector failed: %+v", err)
	}

	// Encryption
	cbcBlockMode := cipher.NewCBCEncrypter(encr.block, initializationVector)
	cbcBlockMode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return cipherText, nil
}

func (encr *ENCR_AES_CBC_Crypto) Decrypt(cipherText []byte) ([]byte, error) {
	// Check
	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("Cipher text is too short")
	}

	initializationVector := cipherText[:aes.BlockSize]
	encryptedMessage := cipherText[aes.BlockSize:]

	if len(encryptedMessage)%aes.BlockSize != 0 {
		return nil, errors.New("Cipher text is not a multiple of block size")
	}

	// Slice
	plainText := make([]byte, len(encryptedMessage))

	// Decryption
	cbcBlockMode := cipher.NewCBCDecrypter(encr.block, initializationVector)
	cbcBlockMode.CryptBlocks(plainText, encryptedMessage)

	// Remove padding
	padding := int(plainText[len(plainText)-1]) + 1
	plainText = plainText[:len(plainText)-padding]

	return plainText, nil
}
