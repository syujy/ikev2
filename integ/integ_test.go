package integ

import (
	"bytes"
	"encoding/hex"
	"testing"

	"bitbucket.org/_syujy/ike/message"
	"bitbucket.org/_syujy/ike/types"
)

func TestStrToType(t *testing.T) {
	// Test StrToType return a type
	integType := StrToType("AUTH_HMAC_MD5_96")
	if integType == nil {
		t.Fatal("Get type AUTH_HMAC_MD5_96 failed")
	}
	integType = StrToType("AUTH_HMAC_SHA1_96")
	if integType == nil {
		t.Fatal("Get type AUTH_HMAC_SHA1_96 failed")
	}
	// Test StrToType return a nil
	integType = StrToType("HMAC_MD5_96")
	if integType != nil {
		t.Fatal("Get a type object with an undefined type string")
	}
}

func TestStrToKType(t *testing.T) {
	// Test StrToType return a type
	integType := StrToKType("AUTH_HMAC_MD5_96")
	if integType == nil {
		t.Fatal("Get type AUTH_HMAC_MD5_96 failed")
	}
	integType = StrToKType("AUTH_HMAC_SHA1_96")
	if integType == nil {
		t.Fatal("Get type AUTH_HMAC_SHA1_96 failed")
	}
	// Test StrToType return a nil
	integType = StrToKType("HMAC_MD5_96")
	if integType != nil {
		t.Fatal("Get a type object with an undefined type string")
	}
}

func TestSetPriority(t *testing.T) {
	// Test SetPriority set priority correctly
	integTypehmacmd596 := StrToType("AUTH_HMAC_MD5_96")   // will be set to priority 1
	integTypehmacsha196 := StrToType("AUTH_HMAC_SHA1_96") // will be set to priority 0

	algolist := map[string]uint32{
		"AUTH_HMAC_MD5_96":  1,
		"AUTH_HMAC_SHA1_96": 0,
	}
	err := SetPriority(algolist)
	if err != nil {
		t.Fatalf("Error: %+v", err)
	}
	if integTypehmacmd596.Priority() != 1 {
		t.Fatal("Type AUTH_HMAC_MD5_96 priority != 1")
	}
	if integTypehmacsha196.Priority() != 0 {
		t.Fatal("Type AUTH_HMAC_SHA1_96 priority != 0")
	}
	// Test SetPriority set with an error returned
	algolist["AUTH_HMAC_MD5_96"] = 0
	algolist["AUTH_HMAC_SHA1_96"] = 1
	algolist["HMAC_MD5_96"] = 0
	err = SetPriority(algolist)
	if err == nil {
		t.Fatal("SetPriority() reported not failed when fed with an incorrect algolist")
	} else {
		t.Logf("SetPriority reported error: %+v. This behavior is correct.", err)
	}
	if integTypehmacmd596.Priority() != 1 {
		t.Fatal("Type AUTH_HMAC_MD5_96 priority != 1")
	}
	if integTypehmacsha196.Priority() != 0 {
		t.Fatal("Type AUTH_HMAC_SHA1_96 priority != 0")
	}
}

func TestSetKPriority(t *testing.T) {
	// Test SetPriority set priority correctly
	integTypeKhmacmd596 := StrToKType("AUTH_HMAC_MD5_96")   // will be set to priority 1
	integTypeKhmacsha196 := StrToKType("AUTH_HMAC_SHA1_96") // will be set to priority 0

	algolist := []string{
		"AUTH_HMAC_SHA1_96",
		"AUTH_HMAC_MD5_96",
	}
	err := SetKPriority(algolist)
	if err != nil {
		t.Fatalf("Error: %+v", err)
	}
	if integTypeKhmacmd596.Priority() != 1 {
		t.Fatal("Type AUTH_HMAC_MD5_96 priority != 1")
	}
	if integTypeKhmacsha196.Priority() != 0 {
		t.Fatal("Type AUTH_HMAC_SHA1_96 priority != 0")
	}
	// Test SetPriority set with an error returned
	algolist[0], algolist[1] = algolist[1], algolist[0]
	algolist = append(algolist, "HMAC_MD5_96")
	err = SetKPriority(algolist)
	if err == nil {
		t.Fatal("SetPriority() reported not failed when feeded with an incorrect algolist")
	} else {
		t.Logf("SetPriority reported error: %+v. This behavior is correct.", err)
	}
	if integTypeKhmacmd596.Priority() != 1 {
		t.Fatal("Type AUTH_HMAC_MD5_96 priority != 1")
	}
	if integTypeKhmacsha196.Priority() != 0 {
		t.Fatal("Type AUTH_HMAC_SHA1_96 priority != 0")
	}
}

func TestToTransform(t *testing.T) {
	// Prepare correct structure
	correctTransform := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_MD5_96,
		AttributePresent: false,
		// don't care, init to zero value by golang
	}
	integType := StrToType("AUTH_HMAC_MD5_96")
	transform := ToTransform(integType)
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

func TestToTransformChildSA(t *testing.T) {
	// Prepare correct structure
	correctTransform := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_MD5_96,
		AttributePresent: false,
		// don't care, init to zero value by golang
	}
	integType := StrToKType("AUTH_HMAC_MD5_96")
	transform := ToTransformChildSA(integType)
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
	tINTEGType := StrToType("AUTH_HMAC_MD5_96")
	// Test transform
	transform := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_MD5_96,
		AttributePresent: false,
	}
	integType := DecodeTransform(transform)
	if integType != tINTEGType {
		t.Fatal("Returned type not matched")
	}
}

func TestDecodeTransformChildSA(t *testing.T) {
	// Target type
	tINTEGType := StrToKType("ENCR_AES_CBC_256")
	// Test transform
	transform := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   256,
	}
	integType := DecodeTransformChildSA(transform)
	if integType != tINTEGType {
		t.Fatal("Returned type not matched")
	}
}

// Interfaces implementation tests
func TestAUTH_HMAC_MD5_96(t *testing.T) {
	// Get type using StrToType
	integType := StrToType(String_AUTH_HMAC_MD5_96)
	integKType := StrToKType(String_AUTH_HMAC_MD5_96)
	integHMACMD596 := integType.(*AUTH_HMAC_MD5_96)
	integKHMACMD596 := integKType.(*AUTH_HMAC_MD5_96)

	// IKE Type
	// transformID()
	if integType.transformID() != types.AUTH_HMAC_MD5_96 {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := integType.getAttribute()
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
	originPriority := integHMACMD596.priority
	integType.setPriority(0)
	if integHMACMD596.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	integType.setPriority(originPriority)
	if integHMACMD596.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if integType.Priority() != integHMACMD596.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if integType.GetKeyLength() != 16 {
		t.Fatal("GetKeyLength returned an error number")
	}
	// GetOutputLength()
	if integType.GetOutputLength() != 12 {
		t.Fatal("GetOutputLength returned an error number")
	}

	// Init() and its encrypt/decrypt function
	// Test data is generated from openssl
	data := []byte("hello")
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}
	output := []byte{0x04, 0x9c, 0x0b, 0xae, 0x0a, 0x24, 0xbb, 0x61, 0x27, 0xa6, 0x54, 0x8b, 0xa0, 0xfb, 0x68, 0xaa}

	h := integType.Init(key)
	_, _ = h.Write(data)
	sum := h.Sum(nil)

	if !bytes.Equal(sum, output) {
		t.Fatalf("Hash function's sum value not equal to openssl's\n%s%s", hex.Dump(output), hex.Dump(sum))
	}

	// Kernel Type
	// transformID()
	if integKType.transformID() != types.AUTH_HMAC_MD5_96 {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue = integKType.getAttribute()
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
	originPriority = integKHMACMD596.priority
	integKType.setPriority(0)
	if integKHMACMD596.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	integKType.setPriority(originPriority)
	if integKHMACMD596.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if integKType.Priority() != integKHMACMD596.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if integKType.GetKeyLength() != 16 {
		t.Fatal("GetKeyLength returned an error number")
	}
	// XFRMString()
	if integKType.XFRMString() != "hmac(md5)" {
		t.Fatal("XFRMString() returned an error string")
	}
}

func TestAUTH_HMAC_SHA1_96(t *testing.T) {
	// Get type using StrToType
	integType := StrToType(String_AUTH_HMAC_SHA1_96)
	integKType := StrToKType(String_AUTH_HMAC_SHA1_96)
	integHMACSHA196 := integType.(*AUTH_HMAC_SHA1_96)
	integKHMACSHA196 := integKType.(*AUTH_HMAC_SHA1_96)

	// IKE Type
	// transformID()
	if integType.transformID() != types.AUTH_HMAC_SHA1_96 {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := integType.getAttribute()
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
	originPriority := integHMACSHA196.priority
	integType.setPriority(0)
	if integHMACSHA196.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	integType.setPriority(originPriority)
	if integHMACSHA196.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if integType.Priority() != integHMACSHA196.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if integType.GetKeyLength() != 20 {
		t.Fatal("GetKeyLength returned an error number")
	}
	// GetOutputLength()
	if integType.GetOutputLength() != 12 {
		t.Fatal("GetOutputLength returned an error number")
	}

	// Init() and its encrypt/decrypt function
	// Test data is generated from openssl
	data := []byte("hello")
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	output := []byte{0xed, 0x2d, 0x81, 0x6f, 0xf5, 0x64, 0x6f, 0x44, 0x86, 0xee, 0xd4, 0xd0, 0x62, 0xdb, 0x9e, 0x5a, 0xf0, 0x73, 0x95, 0x2e}

	h := integType.Init(key)
	_, _ = h.Write(data)
	sum := h.Sum(nil)

	if !bytes.Equal(sum, output) {
		t.Fatalf("Hash function's sum value not equal to openssl's\n%s%s", hex.Dump(output), hex.Dump(sum))
	}

	// Kernel Type
	// transformID()
	if integKType.transformID() != types.AUTH_HMAC_SHA1_96 {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue = integKType.getAttribute()
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
	originPriority = integKHMACSHA196.priority
	integKType.setPriority(0)
	if integKHMACSHA196.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	integKType.setPriority(originPriority)
	if integKHMACSHA196.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if integKType.Priority() != integKHMACSHA196.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if integKType.GetKeyLength() != 20 {
		t.Fatal("GetKeyLength returned an error number")
	}
	// XFRMString()
	if integKType.XFRMString() != "hmac(sha1)" {
		t.Fatal("XFRMString() returned an error string")
	}
}
