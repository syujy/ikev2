package dh

import (
	"fmt"
	"math/big"

	"bitbucket.org/_syujy/ike/message"
	"bitbucket.org/_syujy/ike/types"
)

var dhString map[uint16]func(uint16, uint16, []byte) string
var dhTypes map[string]DHType

func init() {
	// DH String
	dhString = make(map[uint16]func(uint16, uint16, []byte) string)
	dhString[types.DH_1024_BIT_MODP] = toString_DH_1024_BIT_MODP
	dhString[types.DH_2048_BIT_MODP] = toString_DH_2048_BIT_MODP

	// DH Types
	dhTypes = make(map[string]DHType)

	var factor, generator *big.Int

	// Group 2: DH_1024_BIT_MODP
	factor, ok := new(big.Int).SetString(group2PrimeString, 16)
	if !ok {
		panic("IKE Diffie Hellman Group failed to init. Error: Setting big number.")
	}
	generator = new(big.Int).SetUint64(group2Generator)
	dhTypes[String_DH_1024_BIT_MODP] = &DH_1024_BIT_MODP{
		factor:            factor,
		generator:         generator,
		factorBytesLength: len(factor.Bytes()),
	}

	// Group 14: DH_2048_BIT_MODP
	factor, ok = new(big.Int).SetString(group14PrimeString, 16)
	if !ok {
		panic("IKE Diffie Hellman Group failed to init. Error: Setting big number.")
	}
	generator = new(big.Int).SetUint64(group14Generator)
	dhTypes[String_DH_2048_BIT_MODP] = &DH_2048_BIT_MODP{
		factor:            factor,
		generator:         generator,
		factorBytesLength: len(factor.Bytes()),
	}

	// Default Priority
	priority := []string{
		String_DH_1024_BIT_MODP,
		String_DH_2048_BIT_MODP,
	}

	// Set Priority
	for i, s := range priority {
		if dhType, ok := dhTypes[s]; ok {
			dhType.setPriority(uint32(i))
		} else {
			panic("IKE Diffie Hellman Group failed to init. Error: No such DH group implementation.")
		}
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
		dhTypes[algo].setPriority(uint32(priority))
	}
	return nil
}

func StrToType(algo string) DHType {
	if t, ok := dhTypes[algo]; ok {
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
	t.TransformID = dhType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = dhType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = types.AttributeFormatUseTV
	}
	return t
}

type DHType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	GetSharedKey(secret, peerPublicValue *big.Int) []byte
	GetPublicValue(secret *big.Int) []byte
}
