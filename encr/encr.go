package encr

import (
	"fmt"

	"github.com/syujy/ikev2/message"
	"github.com/syujy/ikev2/types"
)

var encrString map[uint16]func(uint16, uint16, []byte) string
var encrTypes map[string]ENCRType
var encrKTypes map[string]ENCRKType
var encrTrans map[string]*message.Transform
var encrKTrans map[string]*message.Transform

func init() {
	// ENCR String
	encrString = make(map[uint16]func(uint16, uint16, []byte) string)
	encrString[types.ENCR_AES_CBC] = toString_ENCR_AES_CBC

	// ENCR Types
	encrTypes = make(map[string]ENCRType)

	encrTypes[String_ENCR_AES_CBC_128] = NewType_ENCR_AES_CBC_128()
	encrTypes[String_ENCR_AES_CBC_192] = NewType_ENCR_AES_CBC_192()
	encrTypes[String_ENCR_AES_CBC_256] = NewType_ENCR_AES_CBC_256()

	// Default Priority
	priority := []string{
		String_ENCR_AES_CBC_128,
		String_ENCR_AES_CBC_192,
		String_ENCR_AES_CBC_256,
	}

	// Set Priority
	for i, s := range priority {
		if encrType, ok := encrTypes[s]; ok {
			encrType.SetPriority(uint32(i))
		} else {
			panic("IKE ENCR failed to init. Error: No such ENCR implementation.")
		}
	}

	// ENCR Kernel Types
	encrKTypes = make(map[string]ENCRKType)

	encrKTypes[String_ENCR_AES_CBC_128] = NewType_ENCR_AES_CBC_128()
	encrKTypes[String_ENCR_AES_CBC_192] = NewType_ENCR_AES_CBC_192()
	encrKTypes[String_ENCR_AES_CBC_256] = NewType_ENCR_AES_CBC_256()

	// ENCR Kernel Priority same as above
	// Set Priority
	for i, s := range priority {
		if encrKType, ok := encrKTypes[s]; ok {
			encrKType.SetPriority(uint32(i))
		} else {
			panic("IKE ENCR failed to init. Error: No such ENCR implementation.")
		}
	}

	// ENCR Transforms
	encrTrans = make(map[string]*message.Transform)
	// Set encrTrans
	for s, t := range encrTypes {
		encrTrans[s] = ToTransform(t)
	}

	// ENCR Kernel Transforms
	encrKTrans = make(map[string]*message.Transform)
	// Set encrKTrans
	for s, t := range encrKTypes {
		encrKTrans[s] = ToTransformChildSA(t)
	}
}

func SetPriority(algolist []string) error {
	// check implemented
	for _, algo := range algolist {
		if _, ok := encrTypes[algo]; !ok {
			return fmt.Errorf("No such implementation: %s", algo)
		}
	}
	// set priority
	for i, algo := range algolist {
		encrTypes[algo].SetPriority(uint32(i))
	}
	return nil
}

func SetKPriority(algolist map[string]uint32) error {
	// check implemented
	for algo := range algolist {
		if _, ok := encrKTypes[algo]; !ok {
			return fmt.Errorf("No such implementation: %s", algo)
		}
	}
	// set priority
	for algo, priority := range algolist {
		encrKTypes[algo].SetPriority(uint32(priority))
	}
	return nil
}

func StrToType(algo string) ENCRType {
	if t, ok := encrTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToTransform(algo string) *message.Transform {
	if t, ok := encrTrans[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToKType(algo string) ENCRKType {
	if t, ok := encrKTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToKTransform(algo string) *message.Transform {
	if t, ok := encrKTrans[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) ENCRType {
	if f, ok := encrString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if encrType, ok := encrTypes[s]; ok {
				return encrType
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

func ToTransform(encrType ENCRType) *message.Transform {
	if encrType == nil {
		return nil
	}
	t := new(message.Transform)
	t.TransformType = types.TypeEncryptionAlgorithm
	t.TransformID = encrType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = encrType.GetAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = types.AttributeFormatUseTV
	}
	return t
}

func DecodeTransformChildSA(transform *message.Transform) ENCRKType {
	if f, ok := encrString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if encrKType, ok := encrKTypes[s]; ok {
				return encrKType
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

func ToTransformChildSA(encrKType ENCRKType) *message.Transform {
	if encrKType == nil {
		return nil
	}
	t := new(message.Transform)
	t.TransformType = types.TypeEncryptionAlgorithm
	t.TransformID = encrKType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = encrKType.GetAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = 1 // TV
	}
	return t
}

type ENCRType interface {
	TransformID() uint16
	GetAttribute() (bool, uint16, uint16, []byte)
	SetPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	Init(key []byte) (types.IKECrypto, error)
}

type ENCRKType interface {
	TransformID() uint16
	GetAttribute() (bool, uint16, uint16, []byte)
	SetPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	XFRMString() string
}

/* Archive for future use
type XFRMEncryptionAlgorithmType uint16

func (xfrmEncryptionAlgorithmType XFRMEncryptionAlgorithmType) String() string {
	switch xfrmEncryptionAlgorithmType {
	case message.ENCR_DES:
		return "cbc(des)"
	case message.ENCR_3DES:
		return "cbc(des3_ede)"
	case message.ENCR_CAST:
		return "cbc(cast5)"
	case message.ENCR_BLOWFISH:
		return "cbc(blowfish)"
	case message.ENCR_NULL:
		return "ecb(cipher_null)"
	case message.ENCR_AES_CBC:
		return "cbc(aes)"
	case message.ENCR_AES_CTR:
		return "rfc3686(ctr(aes))"
	default:
		return ""
	}
}
*/
