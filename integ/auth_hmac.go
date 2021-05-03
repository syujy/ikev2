package integ

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"hash"

	"bitbucket.org/_syujy/ike/types"
)

const (
	String_AUTH_HMAC_MD5_96  string = "AUTH_HMAC_MD5_96"
	String_AUTH_HMAC_SHA1_96 string = "AUTH_HMAC_SHA1_96"
)

var _ INTEGType = &AUTH_HMAC{}
var _ INTEGKType = &AUTH_HMAC{}

type AUTH_HMAC struct {
	transformID  uint16
	priority     uint32
	keyLength    int
	outputLength int
	hashFunc     func() hash.Hash
	xfrmString   string
}

func (t *AUTH_HMAC) TransformID() uint16 {
	return t.transformID
}

func (t *AUTH_HMAC) GetAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *AUTH_HMAC) SetPriority(priority uint32) {
	t.priority = priority
}

func (t *AUTH_HMAC) Priority() uint32 {
	return t.priority
}

func (t *AUTH_HMAC) GetKeyLength() int {
	return t.keyLength
}

func (t *AUTH_HMAC) GetOutputLength() int {
	return t.outputLength
}

func (t *AUTH_HMAC) Init(key []byte) hash.Hash {
	if len(key) == t.keyLength {
		return hmac.New(t.hashFunc, key)
	} else {
		return nil
	}
}

func (t *AUTH_HMAC) XFRMString() string {
	return t.xfrmString
}

// AUTH_HMAC_MD5_96
func toString_AUTH_HMAC_MD5_96(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_AUTH_HMAC_MD5_96
}

func NewType_AUTH_HMAC_MD5_96() *AUTH_HMAC {
	return &AUTH_HMAC{
		transformID:  types.AUTH_HMAC_MD5_96,
		keyLength:    16,
		outputLength: 12,
		hashFunc:     md5.New,
		xfrmString:   "hmac(md5)",
	}
}

// AUTH_HMAC_SHA1_96
func toString_AUTH_HMAC_SHA1_96(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_AUTH_HMAC_SHA1_96
}

func NewType_AUTH_HMAC_SHA1_96() *AUTH_HMAC {
	return &AUTH_HMAC{
		transformID:  types.AUTH_HMAC_SHA1_96,
		keyLength:    20,
		outputLength: 12,
		hashFunc:     sha1.New,
		xfrmString:   "hmac(sha1)",
	}
}
