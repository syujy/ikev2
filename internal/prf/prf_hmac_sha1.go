package prf

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"
	"ike/internal/types"
)

const String_PRF_HMAC_SHA1 string = "PRF_HMAC_SHA1"

func toString_PRF_HMAC_SHA1(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_PRF_HMAC_SHA1
}

var _ PRFType = &PRF_HMAC_SHA1{}

type PRF_HMAC_SHA1 struct {
	priority     uint32
	keyLength    int
	outputLength int
}

func (t *PRF_HMAC_SHA1) transformID() uint16 {
	return types.PRF_HMAC_SHA1
}

func (t *PRF_HMAC_SHA1) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *PRF_HMAC_SHA1) setPriority(priority uint32) {
	t.priority = priority
}

func (t *PRF_HMAC_SHA1) Priority() uint32 {
	return t.priority
}

func (t *PRF_HMAC_SHA1) GetKeyLength() int {
	return t.keyLength
}

func (t *PRF_HMAC_SHA1) GetOutputLength() int {
	return t.outputLength
}

func (t *PRF_HMAC_SHA1) Init(key []byte) hash.Hash {
	return hmac.New(sha1.New, key)
}
