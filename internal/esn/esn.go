package esn

import (
	"errors"
	"ike/internal/logger"
	"ike/internal/types"
	"ike/message"

	"github.com/sirupsen/logrus"
)

var esnLog *logrus.Entry
var esnString map[uint16]func(uint16, uint16, []byte) string
var esnTypes map[string]ESNType

func init() {
	// Log
	esnLog = logger.ESNLog

	// ESN String
	esnString = make(map[uint16]func(uint16, uint16, []byte) string)
	esnString[types.ESN_ENABLE] = toString_ESN_ENABLE
	esnString[types.ESN_DISABLE] = toString_ESN_DISABLE

	// ESN Types
	esnTypes = make(map[string]ESNType)

	esnTypes[String_ESN_ENABLE] = &ESN_ENABLE{}
	esnTypes[String_ESN_DISABLE] = &ESN_DISABLE{}

	// Default Priority
	priority := []string{
		String_ESN_DISABLE,
		String_ESN_ENABLE,
	}

	// Set Priority
	for i, s := range priority {
		if esnType, ok := esnTypes[s]; ok {
			esnType.setPriority(uint32(i))
		} else {
			esnLog.Error("No such ESN implementation")
			panic("IKE ESN failed to init.")
		}
	}
}

func SetPriority(algolist []string) error {
	// check implemented
	for _, algo := range algolist {
		if _, ok := esnTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for i, algo := range algolist {
		esnTypes[algo].setPriority(uint32(i))
	}
	return nil
}

func StrToType(algo string) ESNType {
	if t, ok := esnTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) ESNType {
	if f, ok := esnString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if esnType, ok := esnTypes[s]; ok {
				return esnType
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

func ToTransform(esnType ESNType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = types.TypeExtendedSequenceNumbers
	t.TransformID = esnType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = esnType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = 1 // TV
	}
	return t
}

type ESNType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	Init() bool
}
