package prf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"ike/message"
	"ike/types"
)

func TestStrToType(t *testing.T) {
	// Test StrToType return a type
	prfType := StrToType("PRF_HMAC_MD5")
	if prfType == nil {
		t.Fatal("Get type PRF_HMAC_MD5 failed")
	}
	prfType = StrToType("PRF_HMAC_SHA1")
	if prfType == nil {
		t.Fatal("Get type PRF_HMAC_SHA1 failed")
	}
	// Test StrToType return a nil
	prfType = StrToType("HMAC_MD5")
	if prfType != nil {
		t.Fatal("Get a type object with an undefined type string")
	}
}

func TestSetPriority(t *testing.T) {
	// Test SetPriority set priority correctly
	prfTypehmacmd5 := StrToType("PRF_HMAC_MD5")   // will be set to priority 1
	prfTypehmacsha1 := StrToType("PRF_HMAC_SHA1") // will be set to priority 0

	algolist := map[string]uint32{
		"PRF_HMAC_MD5":  1,
		"PRF_HMAC_SHA1": 0,
	}
	err := SetPriority(algolist)
	if err != nil {
		t.Fatalf("Error: %+v", err)
	}
	if prfTypehmacmd5.Priority() != 1 {
		t.Fatal("Type PRF_HMAC_MD5 priority != 1")
	}
	if prfTypehmacsha1.Priority() != 0 {
		t.Fatal("Type PRF_HMAC_SHA1 priority != 0")
	}
	// Test SetPriority set with an error returned
	algolist["PRF_HMAC_MD5"] = 0
	algolist["PRF_HMAC_SHA1"] = 1
	algolist["HMAC_MD5"] = 0
	err = SetPriority(algolist)
	if err == nil {
		t.Fatal("SetPriority() reported not failed when fed with an incorrect algolist")
	} else {
		t.Logf("SetPriority reported error: %+v. This behavior is correct.", err)
	}
	if prfTypehmacmd5.Priority() != 1 {
		t.Fatal("Type PRF_HMAC_MD5 priority != 1")
	}
	if prfTypehmacsha1.Priority() != 0 {
		t.Fatal("Type PRF_HMAC_SHA1 priority != 0")
	}
}

func TestToTransform(t *testing.T) {
	// Prepare correct structure
	correctTransform := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_MD5,
		AttributePresent: false,
		// don't care, init to zero value by golang
	}
	prfType := StrToType("PRF_HMAC_MD5")
	transform := ToTransform(prfType)
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
	tPRFType := StrToType("PRF_HMAC_MD5")
	// Test transform
	transform := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_MD5,
		AttributePresent: false,
	}
	prfType := DecodeTransform(transform)
	if prfType != tPRFType {
		t.Fatal("Returned type not matched")
	}
}

// Interfaces implementation tests
func TestPRF_HMAC_MD5(t *testing.T) {
	// Get type using StrToType
	prfType := StrToType(string_PRF_HMAC_MD5)
	prfHMACMD5 := prfType.(*PRF_HMAC_MD5)

	// transformID()
	if prfType.transformID() != types.PRF_HMAC_MD5 {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := prfType.getAttribute()
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
	originPriority := prfHMACMD5.priority
	prfType.setPriority(0)
	if prfHMACMD5.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	prfType.setPriority(originPriority)
	if prfHMACMD5.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if prfType.Priority() != prfHMACMD5.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if prfType.GetKeyLength() != 16 {
		t.Fatal("GetKeyLength returned an error number")
	}
	// GetOutputLength()
	if prfType.GetOutputLength() != 16 {
		t.Fatal("GetOutputLength returned an error number")
	}

	// Init() and its encrypt/decrypt function
	// Test data is generated from openssl
	data := []byte("hello")
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}
	output := []byte{0x04, 0x9c, 0x0b, 0xae, 0x0a, 0x24, 0xbb, 0x61, 0x27, 0xa6, 0x54, 0x8b, 0xa0, 0xfb, 0x68, 0xaa}

	h := prfType.Init(key)
	_, _ = h.Write(data)
	sum := h.Sum(nil)

	if !bytes.Equal(sum, output) {
		t.Fatalf("Hash function's sum value not equal to openssl's\n%s%s", hex.Dump(output), hex.Dump(sum))
	}
}

func TestPRF_HMAC_SHA1(t *testing.T) {
	// Get type using StrToType
	prfType := StrToType(string_PRF_HMAC_SHA1)
	prfHMACSHA1 := prfType.(*PRF_HMAC_SHA1)

	// transformID()
	if prfType.transformID() != types.PRF_HMAC_SHA1 {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := prfType.getAttribute()
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
	originPriority := prfHMACSHA1.priority
	prfType.setPriority(0)
	if prfHMACSHA1.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	prfType.setPriority(originPriority)
	if prfHMACSHA1.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if prfType.Priority() != prfHMACSHA1.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if prfType.GetKeyLength() != 20 {
		t.Fatal("GetKeyLength returned an error number")
	}
	// GetOutputLength()
	if prfType.GetOutputLength() != 20 {
		t.Fatal("GetOutputLength returned an error number")
	}

	// Init() and its encrypt/decrypt function
	// Test data is generated from openssl
	data := []byte("hello")
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	output := []byte{0xed, 0x2d, 0x81, 0x6f, 0xf5, 0x64, 0x6f, 0x44, 0x86, 0xee, 0xd4, 0xd0, 0x62, 0xdb, 0x9e, 0x5a, 0xf0, 0x73, 0x95, 0x2e}

	h := prfType.Init(key)
	_, _ = h.Write(data)
	sum := h.Sum(nil)

	if !bytes.Equal(sum, output) {
		t.Fatalf("Hash function's sum value not equal to openssl's\n%s%s", hex.Dump(output), hex.Dump(sum))
	}
}
