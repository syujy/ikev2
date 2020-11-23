package prf

import (
	"errors"
	"hash"

	"ike/internal/logger"
	"ike/internal/types"
	"ike/message"

	"github.com/sirupsen/logrus"
)

var prfLog *logrus.Entry
var prfString map[uint16]func(uint16, uint16, []byte) string
var prfTypes map[string]PRFType

func init() {
	// Log
	prfLog = logger.PRFLog

	// PRF String
	prfString = make(map[uint16]func(uint16, uint16, []byte) string)
	prfString[types.PRF_HMAC_MD5] = toString_PRF_HMAC_MD5
	prfString[types.PRF_HMAC_SHA1] = toString_PRF_HMAC_SHA1

	// PRF Types
	prfTypes = make(map[string]PRFType)

	prfTypes[String_PRF_HMAC_MD5] = &PRF_HMAC_MD5{
		keyLength:    16,
		outputLength: 16,
	}
	prfTypes[String_PRF_HMAC_SHA1] = &PRF_HMAC_SHA1{
		keyLength:    20,
		outputLength: 20,
	}

	// Default Priority
	priority := []string{
		String_PRF_HMAC_MD5,
		String_PRF_HMAC_SHA1,
	}

	// Set Priority
	for i, s := range priority {
		if prfType, ok := prfTypes[s]; ok {
			prfType.setPriority(uint32(i))
		} else {
			prfLog.Error("No such PRF implementation")
			panic("IKE PRF failed to init.")
		}
	}
}

func SetPriority(algolist []string) error {
	// check implemented
	for _, algo := range algolist {
		if _, ok := prfTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for i, algo := range algolist {
		prfTypes[algo].setPriority(uint32(i))
	}
	return nil
}

func StrToType(algo string) PRFType {
	if t, ok := prfTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) PRFType {
	if f, ok := prfString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if prfType, ok := prfTypes[s]; ok {
				return prfType
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

func ToTransform(prfType PRFType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = types.TypePseudorandomFunction
	t.TransformID = prfType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = prfType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = 1 // TV
	}
	return t
}

type PRFType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	GetOutputLength() int
	Init(key []byte) hash.Hash
}

/*
// Pseudorandom Funciton
func NewPseudorandomFunction(key []byte, algorithmType uint16) hash.Hash {
	switch algorithmType {
	case message.PRF_HMAC_MD5:
		return hmac.New(md5.New, key)
	case message.PRF_HMAC_SHA1:
		return hmac.New(sha1.New, key)
	default:
		secLog.Errorf("Unsupported pseudo random function: %d", algorithmType)
		return nil
	}
}
*/
