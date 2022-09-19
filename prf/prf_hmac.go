package prf

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"hash"

	"github.com/syujy/ikev2/types"
)

const (
	String_PRF_HMAC_MD5  string = "PRF_HMAC_MD5"
	String_PRF_HMAC_SHA1 string = "PRF_HMAC_SHA1"
)

var _ PRFType = &PRF_HMAC{}

type PRF_HMAC struct {
	transformID  uint16
	priority     uint32
	keyLength    int
	outputLength int
	hashFunc     func() hash.Hash
}

func (t *PRF_HMAC) TransformID() uint16 {
	return t.transformID
}

func (t *PRF_HMAC) GetAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *PRF_HMAC) SetPriority(priority uint32) {
	t.priority = priority
}

func (t *PRF_HMAC) Priority() uint32 {
	return t.priority
}

func (t *PRF_HMAC) GetKeyLength() int {
	return t.keyLength
}

func (t *PRF_HMAC) GetOutputLength() int {
	return t.outputLength
}

func (t *PRF_HMAC) Init(key []byte) hash.Hash {
	return hmac.New(t.hashFunc, key)
}

// PRF_HMAC_MD5
func toString_PRF_HMAC_MD5(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_PRF_HMAC_MD5
}

func NewType_PRF_HMAC_MD5() *PRF_HMAC {
	return &PRF_HMAC{
		transformID:  types.PRF_HMAC_MD5,
		keyLength:    16,
		outputLength: 16,
		hashFunc:     md5.New,
	}
}

// PRF_HMAC_SHA1
func toString_PRF_HMAC_SHA1(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_PRF_HMAC_SHA1
}

func NewType_PRF_HMAC_SHA1() *PRF_HMAC {
	return &PRF_HMAC{
		transformID:  types.PRF_HMAC_SHA1,
		keyLength:    20,
		outputLength: 20,
		hashFunc:     sha1.New,
	}
}
