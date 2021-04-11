package esn

import (
	"errors"

	"bitbucket.org/_syujy/ike/internal/logger"
	"bitbucket.org/_syujy/ike/message"
	"bitbucket.org/_syujy/ike/types"

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

	esnTypes[string_ESN_ENABLE] = &ESN_ENABLE{}
	esnTypes[string_ESN_DISABLE] = &ESN_DISABLE{}

	// Default Priority
	priority := []string{
		string_ESN_ENABLE,
		string_ESN_DISABLE,
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

func SetPriority(algolist map[string]uint32) error {
	// check implemented
	for algo := range algolist {
		if _, ok := esnTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for algo, priority := range algolist {
		esnTypes[algo].setPriority(uint32(priority))
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
		t.AttributeFormat = types.AttributeFormatUseTV
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
