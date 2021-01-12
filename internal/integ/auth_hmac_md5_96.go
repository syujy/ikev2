package integ

import (
	"crypto/hmac"
	"crypto/md5"
	"hash"
	"ike/types"
)

const string_AUTH_HMAC_MD5_96 string = "AUTH_HMAC_MD5_96"

func toString_AUTH_HMAC_MD5_96(attrType uint16, intValue uint16, bytesValue []byte) string {
	return string_AUTH_HMAC_MD5_96
}

var _ INTEGType = &AUTH_HMAC_MD5_96{}
var _ INTEGKType = &AUTH_HMAC_MD5_96{}

type AUTH_HMAC_MD5_96 struct {
	priority     uint32
	keyLength    int
	outputLength int
}

func (t *AUTH_HMAC_MD5_96) transformID() uint16 {
	return types.AUTH_HMAC_MD5_96
}

func (t *AUTH_HMAC_MD5_96) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *AUTH_HMAC_MD5_96) setPriority(priority uint32) {
	t.priority = priority
}

func (t *AUTH_HMAC_MD5_96) Priority() uint32 {
	return t.priority
}

func (t *AUTH_HMAC_MD5_96) GetKeyLength() int {
	return t.keyLength
}

func (t *AUTH_HMAC_MD5_96) GetOutputLength() int {
	return t.outputLength
}

func (t *AUTH_HMAC_MD5_96) Init(key []byte) hash.Hash {
	if len(key) == 16 {
		return hmac.New(md5.New, key)
	} else {
		return nil
	}
}

func (t *AUTH_HMAC_MD5_96) XFRMString() string {
	return "hmac(md5)"
}
