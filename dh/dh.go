package dh

import (
	"fmt"
	"math/big"

	"github.com/syujy/ikev2/message"
	"github.com/syujy/ikev2/types"
)

var dhString map[uint16]func(uint16, uint16, []byte) string
var dhTypes map[string]DHType
var dhTrans map[string]*message.Transform

func init() {
	// DH String
	dhString = make(map[uint16]func(uint16, uint16, []byte) string)
	dhString[types.DH_1024_BIT_MODP] = toString_DH_1024_BIT_MODP
	dhString[types.DH_2048_BIT_MODP] = toString_DH_2048_BIT_MODP

	// DH Types
	dhTypes = make(map[string]DHType)

	// Group 2: DH_1024_BIT_MODP
	if dhType, err := NewType_DH_1024_BIT_MODP(); err != nil {
		panic(fmt.Errorf("IKE Diffie Hellman Group failed to init: %+v", err))
	} else {
		dhTypes[String_DH_1024_BIT_MODP] = dhType
	}

	// Group 14: DH_2048_BIT_MODP
	if dhType, err := NewType_DH_2048_BIT_MODP(); err != nil {
		panic(fmt.Errorf("IKE Diffie Hellman Group failed to init: %+v", err))
	} else {
		dhTypes[String_DH_2048_BIT_MODP] = dhType
	}

	// Default Priority
	priority := []string{
		String_DH_1024_BIT_MODP,
		String_DH_2048_BIT_MODP,
	}

	// Set Priority
	for i, s := range priority {
		if dhType, ok := dhTypes[s]; ok {
			dhType.SetPriority(uint32(i))
		} else {
			panic("IKE Diffie Hellman Group failed to init. Error: No such DH group implementation.")
		}
	}

	// DH Transforms
	dhTrans = make(map[string]*message.Transform)
	// Set dhTrans
	for s, t := range dhTypes {
		dhTrans[s] = ToTransform(t)
	}
}

func SetPriority(algolist map[string]uint32) error {
	// check implemented
	for algo := range algolist {
		if _, ok := dhTypes[algo]; !ok {
			return fmt.Errorf("No such implementation: %s", algo)
		}
	}
	// set priority
	for algo, priority := range algolist {
		dhTypes[algo].SetPriority(uint32(priority))
	}
	return nil
}

func GetType(group uint16) DHType {
	if f, ok := dhString[group]; ok {
		return dhTypes[f(0, 0, nil)]
	} else {
		return nil
	}
}

func StrToType(algo string) DHType {
	if t, ok := dhTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToTransform(algo string) *message.Transform {
	if t, ok := dhTrans[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) DHType {
	if f, ok := dhString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if dhType, ok := dhTypes[s]; ok {
				return dhType
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

func ToTransform(dhType DHType) *message.Transform {
	if dhType == nil {
		return nil
	}
	t := new(message.Transform)
	t.TransformType = types.TypeDiffieHellmanGroup
	t.TransformID = dhType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = dhType.GetAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = types.AttributeFormatUseTV
	}
	return t
}

type DHType interface {
	TransformID() uint16
	GetAttribute() (bool, uint16, uint16, []byte)
	SetPriority(uint32)
	Priority() uint32
	GetSharedKey(secret, peerPublicValue *big.Int) []byte
	GetPublicValue(secret *big.Int) []byte
}
