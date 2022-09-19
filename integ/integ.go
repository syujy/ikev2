package integ

import (
	"errors"
	"hash"

	"github.com/syujy/ikev2/message"
	"github.com/syujy/ikev2/types"
)

var integString map[uint16]func(uint16, uint16, []byte) string
var integTypes map[string]INTEGType
var integKTypes map[string]INTEGKType
var integTrans map[string]*message.Transform
var integKTrans map[string]*message.Transform

func init() {
	// INTEG String
	integString = make(map[uint16]func(uint16, uint16, []byte) string)
	integString[types.AUTH_HMAC_MD5_96] = toString_AUTH_HMAC_MD5_96
	integString[types.AUTH_HMAC_SHA1_96] = toString_AUTH_HMAC_SHA1_96

	// INTEG Types
	integTypes = make(map[string]INTEGType)

	integTypes[String_AUTH_HMAC_MD5_96] = NewType_AUTH_HMAC_MD5_96()
	integTypes[String_AUTH_HMAC_SHA1_96] = NewType_AUTH_HMAC_SHA1_96()

	// Default Priority
	priority := []string{
		String_AUTH_HMAC_MD5_96,
		String_AUTH_HMAC_SHA1_96,
	}

	// Set Priority
	for i, s := range priority {
		if integType, ok := integTypes[s]; ok {
			integType.SetPriority(uint32(i))
		} else {
			panic("IKE INTEG failed to init. Error: No such INTEG implementation.")
		}
	}

	// INTEG Kernel Types
	integKTypes = make(map[string]INTEGKType)

	integKTypes[String_AUTH_HMAC_MD5_96] = NewType_AUTH_HMAC_MD5_96()
	integKTypes[String_AUTH_HMAC_SHA1_96] = NewType_AUTH_HMAC_SHA1_96()

	// INTEG Kernel Priority same as above
	// Set Priority
	for i, s := range priority {
		if integKType, ok := integKTypes[s]; ok {
			integKType.SetPriority(uint32(i))
		} else {
			panic("IKE INTEG failed to init. Error: No such INTEG implementation.")
		}
	}

	// INTEG Transforms
	integTrans = make(map[string]*message.Transform)
	// Set integTrans
	for s, t := range integTypes {
		integTrans[s] = ToTransform(t)
	}

	// INTEG Kernel Transforms
	integKTrans = make(map[string]*message.Transform)
	// Set integKTrans
	for s, t := range integKTypes {
		integKTrans[s] = ToTransformChildSA(t)
	}
}

func SetPriority(algolist map[string]uint32) error {
	// check implemented
	for algo := range algolist {
		if _, ok := integTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for algo, priority := range algolist {
		integTypes[algo].SetPriority(uint32(priority))
	}
	return nil
}

func SetKPriority(algolist []string) error {
	// check implemented
	for _, algo := range algolist {
		if _, ok := integKTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for i, algo := range algolist {
		integKTypes[algo].SetPriority(uint32(i))
	}
	return nil
}

func StrToType(algo string) INTEGType {
	if t, ok := integTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToTransform(algo string) *message.Transform {
	if t, ok := integTrans[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToKType(algo string) INTEGKType {
	if t, ok := integKTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToKTransform(algo string) *message.Transform {
	if t, ok := integKTrans[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) INTEGType {
	if f, ok := integString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if integType, ok := integTypes[s]; ok {
				return integType
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

func ToTransform(integType INTEGType) *message.Transform {
	if integType == nil {
		return nil
	}
	t := new(message.Transform)
	t.TransformType = types.TypeIntegrityAlgorithm
	t.TransformID = integType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = integType.GetAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = 1 // TV
	}
	return t
}

func DecodeTransformChildSA(transform *message.Transform) INTEGKType {
	if f, ok := integString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if integKType, ok := integKTypes[s]; ok {
				return integKType
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

func ToTransformChildSA(integKType INTEGKType) *message.Transform {
	if integKType == nil {
		return nil
	}
	t := new(message.Transform)
	t.TransformType = types.TypeIntegrityAlgorithm
	t.TransformID = integKType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = integKType.GetAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = types.AttributeFormatUseTV
	}
	return t
}

type INTEGType interface {
	TransformID() uint16
	GetAttribute() (bool, uint16, uint16, []byte)
	SetPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	GetOutputLength() int
	Init(key []byte) hash.Hash
}

type INTEGKType interface {
	TransformID() uint16
	GetAttribute() (bool, uint16, uint16, []byte)
	SetPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	XFRMString() string
}

/* Archive for future use
type XFRMIntegrityAlgorithmType uint16

func (xfrmIntegrityAlgorithmType XFRMIntegrityAlgorithmType) String() string {
	switch xfrmIntegrityAlgorithmType {
	case message.AUTH_HMAC_MD5_96:
		return "hmac(md5)"
	case message.AUTH_HMAC_SHA1_96:
		return "hmac(sha1)"
	case message.AUTH_AES_XCBC_96:
		return "xcbc(aes)"
	default:
		return ""
	}
}
*/
