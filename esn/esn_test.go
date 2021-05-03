package esn

import (
	"bytes"
	"testing"

	"bitbucket.org/_syujy/ike/message"
	"bitbucket.org/_syujy/ike/types"
)

func TestStrToType(t *testing.T) {
	// Test StrToType return a type
	esnType := StrToType("ESN_ENABLE")
	if esnType == nil {
		t.Fatal("Get type ESN_ENABLE failed")
	}
	esnType = StrToType("ESN_DISABLE")
	if esnType == nil {
		t.Fatal("Get type ESN_DIABLE failed")
	}
	// Test StrToType return a nil
	esnType = StrToType("ENABLE")
	if esnType != nil {
		t.Fatal("Get a type object with an undefined type string")
	}
}

func TestStrToTransform(t *testing.T) {
	// Test StrToTransform return a transform
	esnTran := StrToTransform("ESN_ENABLE")
	if esnTran == nil {
		t.Fatal("Get transform ESN_ENABLE failed")
	}
	esnTran = StrToTransform("ESN_DISABLE")
	if esnTran == nil {
		t.Fatal("Get transform ESN_DIABLE failed")
	}
	// Test StrToTransform return a nil
	esnTran = StrToTransform("ENABLE")
	if esnTran != nil {
		t.Fatal("Get a transform with an undefined type string")
	}
}

func TestSetPriority(t *testing.T) {
	// Test SetPriority set priority correctly
	esnTypeOff := StrToType("ESN_DISABLE") // will be set to priority 1
	esnTypeOn := StrToType("ESN_ENABLE")   // will be set to priority 0

	algolist := map[string]uint32{
		"ESN_DISABLE": 1,
		"ESN_ENABLE":  0,
	}
	err := SetPriority(algolist)
	if err != nil {
		t.Fatalf("Error: %+v", err)
	}
	if esnTypeOff.Priority() != 1 {
		t.Fatal("Type ESN_DISABLE priority != 1")
	}
	if esnTypeOn.Priority() != 0 {
		t.Fatal("Type ESN_ENABLE priority != 0")
	}
	// Test SetPriority set with an error returned
	algolist["ESN_DISABLE"] = 0
	algolist["ESN_ENABLE"] = 1
	algolist["ENABLE"] = 0
	err = SetPriority(algolist)
	if err == nil {
		t.Fatal("SetPriority() reported not failed when fed with an incorrect algolist")
	} else {
		t.Logf("SetPriority reported error: %+v. This behavior is correct.", err)
	}
	if esnTypeOff.Priority() != 1 {
		t.Fatal("Type ESN_DISABLE priority != 1")
	}
	if esnTypeOn.Priority() != 0 {
		t.Fatal("Type ESN_ENABLE priority != 0")
	}
}

func TestToTransform(t *testing.T) {
	// Prepare correct structure
	correctTransform := &message.Transform{
		TransformType:    types.TypeExtendedSequenceNumbers,
		TransformID:      types.ESN_ENABLE,
		AttributePresent: false,
		// don't care, init to zero value by golang
	}
	esnType := StrToType("ESN_ENABLE")
	transform := ToTransform(esnType)
	if transform.TransformType != correctTransform.TransformType {
		t.Fatal("Transform Type not matched")
	}
	if transform.TransformID != correctTransform.TransformID {
		t.Fatal("Transform ID not matched")
	}
	if transform.AttributePresent != correctTransform.AttributePresent {
		t.Fatal("Attribute Present not matched")
	}
	if correctTransform.AttributePresent {
		if transform.AttributeFormat != correctTransform.AttributeFormat {
			t.Fatal("Attribute Format not matched")
		}
		if transform.AttributeType != correctTransform.AttributeType {
			t.Fatal("Attribute Type not matched")
		}
		if correctTransform.AttributeFormat == types.AttributeFormatUseTLV {
			if !bytes.Equal(transform.VariableLengthAttributeValue, correctTransform.VariableLengthAttributeValue) {
				t.Fatal("Variable Length Attribute Value not matched")
			}
		} else {
			if transform.AttributeValue != correctTransform.AttributeValue {
				t.Fatal("Attribute Value not matched")
			}
		}
	}
}

func TestDecodeTransform(t *testing.T) {
	// Target type
	tESNType := StrToType("ESN_DISABLE")
	// Test transform
	transform := &message.Transform{
		TransformType:    types.TypeExtendedSequenceNumbers,
		TransformID:      types.ESN_DISABLE,
		AttributePresent: false,
		// don't care, init to zero value by golang
	}
	esnType := DecodeTransform(transform)
	if esnType != tESNType {
		t.Fatal("Returned type not matched")
	}
}

// Interfaces implementation tests
func TestESN_ENABLE(t *testing.T) {
	// Get type using StrToType
	esnType := StrToType(String_ESN_ENABLE)
	esnEnable := esnType.(*ESN)

	// transformID()
	if esnType.TransformID() != types.ESN_ENABLE {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := esnType.GetAttribute()
	if attrPresent != false {
		t.Fatal("Attribute Present not correct")
	}
	if attrType != 0 {
		t.Fatal("Attribute Type not correct")
	}
	if attrValue != 0 {
		t.Fatal("Attribute Value not correct")
	}
	if byteAttrValue != nil {
		t.Fatal("Variable Length Attribute Value not correct")
	}
	// setPriority()
	originPriority := esnEnable.priority
	esnType.SetPriority(0)
	if esnEnable.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	esnType.SetPriority(originPriority)
	if esnEnable.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if esnType.Priority() != esnEnable.priority {
		t.Fatal("Priority returned an error number")
	}
	// Init()
	if esnType.Init() != true {
		t.Fatal("Init returned an error value")
	}
}

func TestESN_DISABLE(t *testing.T) {
	// Get type using StrToType
	esnType := StrToType(String_ESN_DISABLE)
	esnDisable := esnType.(*ESN)

	// transformID()
	if esnType.TransformID() != types.ESN_DISABLE {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := esnType.GetAttribute()
	if attrPresent != false {
		t.Fatal("Attribute Present not correct")
	}
	if attrType != 0 {
		t.Fatal("Attribute Type not correct")
	}
	if attrValue != 0 {
		t.Fatal("Attribute Value not correct")
	}
	if byteAttrValue != nil {
		t.Fatal("Variable Length Attribute Value not correct")
	}
	// setPriority()
	originPriority := esnDisable.priority
	esnType.SetPriority(0)
	if esnDisable.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	esnType.SetPriority(originPriority)
	if esnDisable.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if esnType.Priority() != esnDisable.priority {
		t.Fatal("Priority returned an error number")
	}
	// Init()
	if esnType.Init() != false {
		t.Fatal("Init returned an error value")
	}
}
