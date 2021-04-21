package prf

import (
	"errors"
	"hash"

	"bitbucket.org/_syujy/ike/message"
	"bitbucket.org/_syujy/ike/types"
)

var prfString map[uint16]func(uint16, uint16, []byte) string
var prfTypes map[string]PRFType
var prfTrans map[string]*message.Transform

func init() {
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
			panic("IKE PRF failed to init. Error: No such PRF implementation.")
		}
	}

	// PRF Transforms
	prfTrans = make(map[string]*message.Transform)
	// Set prfTrans
	for s, t := range prfTypes {
		prfTrans[s] = ToTransform(t)
	}
}

func SetPriority(algolist map[string]uint32) error {
	// check implemented
	for algo := range algolist {
		if _, ok := prfTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for algo, priority := range algolist {
		prfTypes[algo].setPriority(uint32(priority))
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

func StrToTransform(algo string) *message.Transform {
	if t, ok := prfTrans[algo]; ok {
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
	if prfType == nil {
		return nil
	}
	t := new(message.Transform)
	t.TransformType = types.TypePseudorandomFunction
	t.TransformID = prfType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = prfType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = types.AttributeFormatUseTV
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
