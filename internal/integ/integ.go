package integ

import (
	"errors"
	"hash"

	"ike/internal/logger"
	"ike/message"
	"ike/types"

	"github.com/sirupsen/logrus"
)

var integLog *logrus.Entry
var integString map[uint16]func(uint16, uint16, []byte) string

var integTypes map[string]INTEGType
var integKTypes map[string]INTEGKType

func init() {
	// Log
	integLog = logger.INTEGLog

	// INTEG String
	integString = make(map[uint16]func(uint16, uint16, []byte) string)
	integString[types.AUTH_HMAC_MD5_96] = toString_AUTH_HMAC_MD5_96
	integString[types.AUTH_HMAC_SHA1_96] = toString_AUTH_HMAC_SHA1_96

	// INTEG Types
	integTypes = make(map[string]INTEGType)

	integTypes[string_AUTH_HMAC_MD5_96] = &AUTH_HMAC_MD5_96{
		keyLength:    16,
		outputLength: 12,
	}
	integTypes[string_AUTH_HMAC_SHA1_96] = &AUTH_HMAC_SHA1_96{
		keyLength:    20,
		outputLength: 12,
	}

	// Default Priority
	priority := []string{
		string_AUTH_HMAC_MD5_96,
		string_AUTH_HMAC_SHA1_96,
	}

	// Set Priority
	for i, s := range priority {
		if integType, ok := integTypes[s]; ok {
			integType.setPriority(uint32(i))
		} else {
			integLog.Error("No such INTEG implementation")
			panic("IKE INTEG failed to init.")
		}
	}

	// INTEG Kernel Types
	integKTypes = make(map[string]INTEGKType)

	integKTypes[string_AUTH_HMAC_MD5_96] = &AUTH_HMAC_MD5_96{
		keyLength:    16,
		outputLength: 12,
	}
	integKTypes[string_AUTH_HMAC_SHA1_96] = &AUTH_HMAC_SHA1_96{
		keyLength:    20,
		outputLength: 12,
	}

	// INTEG Kernel Priority same as above
	// Set Priority
	for i, s := range priority {
		if integKType, ok := integKTypes[s]; ok {
			integKType.setPriority(uint32(i))
		} else {
			integLog.Error("No such INTEG implementation")
			panic("IKE INTEG failed to init.")
		}
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
		integTypes[algo].setPriority(uint32(priority))
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
		integKTypes[algo].setPriority(uint32(i))
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

func StrToKType(algo string) INTEGKType {
	if t, ok := integKTypes[algo]; ok {
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
	t := new(message.Transform)
	t.TransformType = types.TypeIntegrityAlgorithm
	t.TransformID = integType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = integType.getAttribute()
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
	t := new(message.Transform)
	t.TransformType = types.TypeIntegrityAlgorithm
	t.TransformID = integKType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = integKType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = types.AttributeFormatUseTV
	}
	return t
}

type INTEGType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	GetOutputLength() int
	Init(key []byte) hash.Hash
}

type INTEGKType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
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
