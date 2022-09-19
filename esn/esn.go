package esn

import (
	"errors"

	"github.com/syujy/ikev2/message"
	"github.com/syujy/ikev2/types"
)

var esnString map[uint16]func(uint16, uint16, []byte) string
var esnTypes map[string]ESNType
var esnTrans map[string]*message.Transform

func init() {
	// ESN String
	esnString = make(map[uint16]func(uint16, uint16, []byte) string)
	esnString[types.ESN_ENABLE] = toString_ESN_ENABLE
	esnString[types.ESN_DISABLE] = toString_ESN_DISABLE

	// ESN Types
	esnTypes = make(map[string]ESNType)

	esnTypes[String_ESN_ENABLE] = NewType_ESN_ENABLE()
	esnTypes[String_ESN_DISABLE] = NewType_ESN_DISABLE()

	// Default Priority
	priority := []string{
		String_ESN_ENABLE,
		String_ESN_DISABLE,
	}

	// Set Priority
	for i, s := range priority {
		if esnType, ok := esnTypes[s]; ok {
			esnType.SetPriority(uint32(i))
		} else {
			panic("IKE ESN failed to init. Error: No such ESN implementation.")
		}
	}

	// ESN Transforms
	esnTrans = make(map[string]*message.Transform)
	// Set esnTrans
	for s, t := range esnTypes {
		esnTrans[s] = ToTransform(t)
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
		esnTypes[algo].SetPriority(uint32(priority))
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

func StrToTransform(algo string) *message.Transform {
	if t, ok := esnTrans[algo]; ok {
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
	if esnType == nil {
		return nil
	}
	t := new(message.Transform)
	t.TransformType = types.TypeExtendedSequenceNumbers
	t.TransformID = esnType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = esnType.GetAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = types.AttributeFormatUseTV
	}
	return t
}

type ESNType interface {
	TransformID() uint16
	GetAttribute() (bool, uint16, uint16, []byte)
	SetPriority(uint32)
	Priority() uint32
	Init() bool
}

const (
	String_ESN_ENABLE  string = "ESN_ENABLE"
	String_ESN_DISABLE string = "ESN_DISABLE"
)

var _ ESNType = &ESN{}

type ESN struct {
	transformID uint16
	enabled     bool
	priority    uint32
}

func (t *ESN) TransformID() uint16 {
	return t.transformID
}

func (t *ESN) GetAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *ESN) SetPriority(priority uint32) {
	t.priority = priority
}

func (t *ESN) Priority() uint32 {
	return t.priority
}

func (t *ESN) Init() bool {
	return t.enabled
}

// ESN_ENABLE
func toString_ESN_ENABLE(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_ESN_ENABLE
}

func NewType_ESN_ENABLE() *ESN {
	return &ESN{
		transformID: types.ESN_ENABLE,
		enabled:     true,
	}
}

// ESN_DISABLE
func toString_ESN_DISABLE(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_ESN_DISABLE
}

func NewType_ESN_DISABLE() *ESN {
	return &ESN{
		transformID: types.ESN_DISABLE,
		enabled:     false,
	}
}
