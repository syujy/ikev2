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
	hashFunc     func([]byte) hash.Hash
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
		return new_HMAC_MD5_96(key)
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
		hashFunc:     new_HMAC_MD5_96,
		xfrmString:   "hmac(md5)",
	}
}

type digest_HMAC_MD5_96 struct {
	hash.Hash
}

func (d *digest_HMAC_MD5_96) Sum(b []byte) []byte {
	return d.Hash.Sum(b)[:len(b)+12]
}

func (d *digest_HMAC_MD5_96) Size() int {
	return 12
}

func new_HMAC_MD5_96(key []byte) hash.Hash {
	return &digest_HMAC_MD5_96{
		Hash: hmac.New(md5.New, key),
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
		hashFunc:     new_HMAC_SHA1_96,
		xfrmString:   "hmac(sha1)",
	}
}

type digest_HMAC_SHA1_96 struct {
	hash.Hash
}

func (d *digest_HMAC_SHA1_96) Sum(b []byte) []byte {
	return d.Hash.Sum(b)[:len(b)+12]
}

func (d *digest_HMAC_SHA1_96) Size() int {
	return 12
}

func new_HMAC_SHA1_96(key []byte) hash.Hash {
	return &digest_HMAC_SHA1_96{
		Hash: hmac.New(sha1.New, key),
	}
}
