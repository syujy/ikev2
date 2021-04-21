package encr

import (
	"bytes"
	"testing"

	"bitbucket.org/_syujy/ike/message"
	"bitbucket.org/_syujy/ike/types"
)

func TestStrToType(t *testing.T) {
	// Test StrToType return a type
	encrType := StrToType("ENCR_AES_CBC_128")
	if encrType == nil {
		t.Fatal("Get type ENCR_AES_CBC_128 failed")
	}
	encrType = StrToType("ENCR_AES_CBC_192")
	if encrType == nil {
		t.Fatal("Get type ENCR_AES_CBC_192 failed")
	}
	encrType = StrToType("ENCR_AES_CBC_256")
	if encrType == nil {
		t.Fatal("Get type ENCR_AES_CBC_256 failed")
	}
	// Test StrToType return a nil
	encrType = StrToType("AES_CBC_128")
	if encrType != nil {
		t.Fatal("Get a type object with an undefined type string")
	}
}

func TestStrToTransform(t *testing.T) {
	// Test StrToTransform return a transform
	encrTran := StrToTransform("ENCR_AES_CBC_128")
	if encrTran == nil {
		t.Fatal("Get transform ENCR_AES_CBC_128 failed")
	}
	encrTran = StrToTransform("ENCR_AES_CBC_192")
	if encrTran == nil {
		t.Fatal("Get transform ENCR_AES_CBC_192 failed")
	}
	encrTran = StrToTransform("ENCR_AES_CBC_256")
	if encrTran == nil {
		t.Fatal("Get transform ENCR_AES_CBC_256 failed")
	}
	// Test StrToTransform return a nil
	encrTran = StrToTransform("AES_CBC_128")
	if encrTran != nil {
		t.Fatal("Get a transform with an undefined type string")
	}
}

func TestStrToKType(t *testing.T) {
	// Test StrToKType return a type
	encrType := StrToKType("ENCR_AES_CBC_128")
	if encrType == nil {
		t.Fatal("Get type ENCR_AES_CBC_128 failed")
	}
	encrType = StrToKType("ENCR_AES_CBC_192")
	if encrType == nil {
		t.Fatal("Get type ENCR_AES_CBC_192 failed")
	}
	encrType = StrToKType("ENCR_AES_CBC_256")
	if encrType == nil {
		t.Fatal("Get type ENCR_AES_CBC_256 failed")
	}
	// Test StrToKType return a nil
	encrType = StrToKType("AES_CBC_128")
	if encrType != nil {
		t.Fatal("Get a type object with an undefined type string")
	}
}

func TestStrToKTransform(t *testing.T) {
	// Test StrToKTransform return a transform
	encrTran := StrToKTransform("ENCR_AES_CBC_128")
	if encrTran == nil {
		t.Fatal("Get transform ENCR_AES_CBC_128 failed")
	}
	encrTran = StrToKTransform("ENCR_AES_CBC_192")
	if encrTran == nil {
		t.Fatal("Get transform ENCR_AES_CBC_192 failed")
	}
	encrTran = StrToKTransform("ENCR_AES_CBC_256")
	if encrTran == nil {
		t.Fatal("Get transform ENCR_AES_CBC_256 failed")
	}
	// Test StrToKTransform return a nil
	encrTran = StrToKTransform("AES_CBC_128")
	if encrTran != nil {
		t.Fatal("Get a transform with an undefined type string")
	}
}

func TestSetPriority(t *testing.T) {
	// Test SetPriority set priority correctly
	encrTypeaescbc128 := StrToType("ENCR_AES_CBC_128") // will be set to priority 1
	encrTypeaescbc192 := StrToType("ENCR_AES_CBC_192") // will be set to priority 2
	encrTypeaescbc256 := StrToType("ENCR_AES_CBC_256") // will be set to priority 0

	algolist := []string{
		"ENCR_AES_CBC_256",
		"ENCR_AES_CBC_128",
		"ENCR_AES_CBC_192",
	}
	err := SetPriority(algolist)
	if err != nil {
		t.Fatalf("Error: %+v", err)
	}
	if encrTypeaescbc128.Priority() != 1 {
		t.Fatal("Type ENCR_AES_CBC_128 priority != 1")
	}
	if encrTypeaescbc192.Priority() != 2 {
		t.Fatal("Type ENCR_AES_CBC_192 priority != 2")
	}
	if encrTypeaescbc256.Priority() != 0 {
		t.Fatal("Type ENCR_AES_CBC_256 priority != 0")
	}
	// Test SetPriority set with an error returned
	algolist[0], algolist[1] = algolist[1], algolist[0]
	algolist = append(algolist, "AES_CBC_128")
	err = SetPriority(algolist)
	if err == nil {
		t.Fatal("SetPriority() reported not failed when fed with an incorrect algolist")
	} else {
		t.Logf("SetPriority reported error: %+v. This behavior is correct.", err)
	}
	if encrTypeaescbc128.Priority() != 1 {
		t.Fatal("Type ENCR_AES_CBC_128 priority != 1")
	}
	if encrTypeaescbc192.Priority() != 2 {
		t.Fatal("Type ENCR_AES_CBC_192 priority != 2")
	}
	if encrTypeaescbc256.Priority() != 0 {
		t.Fatal("Type ENCR_AES_CBC_256 priority != 0")
	}
}

func TestSetKPriority(t *testing.T) {
	// Test SetPriority set priority correctly
	encrTypeaescbc128 := StrToKType("ENCR_AES_CBC_128") // will be set to priority 1
	encrTypeaescbc192 := StrToKType("ENCR_AES_CBC_192") // will be set to priority 2
	encrTypeaescbc256 := StrToKType("ENCR_AES_CBC_256") // will be set to priority 0

	algolist := map[string]uint32{
		"ENCR_AES_CBC_128": 1,
		"ENCR_AES_CBC_192": 2,
		"ENCR_AES_CBC_256": 0,
	}
	err := SetKPriority(algolist)
	if err != nil {
		t.Fatalf("Error: %+v", err)
	}
	if encrTypeaescbc128.Priority() != 1 {
		t.Fatal("Type ENCR_AES_CBC_128 priority != 1")
	}
	if encrTypeaescbc192.Priority() != 2 {
		t.Fatal("Type ENCR_AES_CBC_192 priority != 2")
	}
	if encrTypeaescbc256.Priority() != 0 {
		t.Fatal("Type ENCR_AES_CBC_256 priority != 0")
	}
	// Test SetPriority set with an error returned
	algolist["ENCR_AES_CBC_128"] = 2
	algolist["ENCR_AES_CBC_192"] = 1
	algolist["AES_CBC_128"] = 0
	err = SetKPriority(algolist)
	if err == nil {
		t.Fatal("SetPriority() reported not failed when feeded with an incorrect algolist")
	} else {
		t.Logf("SetPriority reported error: %+v. This behavior is correct.", err)
	}
	if encrTypeaescbc128.Priority() != 1 {
		t.Fatal("Type ENCR_AES_CBC_128 priority != 1")
	}
	if encrTypeaescbc192.Priority() != 2 {
		t.Fatal("Type ENCR_AES_CBC_192 priority != 2")
	}
	if encrTypeaescbc256.Priority() != 0 {
		t.Fatal("Type ENCR_AES_CBC_256 priority != 0")
	}
}

func TestToTransform(t *testing.T) {
	// Prepare correct structure
	correctTransform := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   192,
	}
	encrType := StrToType("ENCR_AES_CBC_192")
	transform := ToTransform(encrType)
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
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   192,
	}
	encrType := StrToKType("ENCR_AES_CBC_192")
	transform := ToTransformChildSA(encrType)
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
	tENCRType := StrToType("ENCR_AES_CBC_256")
	// Test transform
	transform := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   256,
	}
	encrType := DecodeTransform(transform)
	if encrType != tENCRType {
		t.Fatal("Returned type not matched")
	}
}

func TestDecodeTransformChildSA(t *testing.T) {
	// Target type
	tENCRType := StrToKType("ENCR_AES_CBC_256")
	// Test transform
	transform := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   256,
	}
	encrType := DecodeTransformChildSA(transform)
	if encrType != tENCRType {
		t.Fatal("Returned type not matched")
	}
}

// Interfaces implementation tests
func TestENCR_AES_CBC_128(t *testing.T) {
	// Get type using StrToType
	encrType := StrToType(String_ENCR_AES_CBC_128)
	encrKType := StrToKType(String_ENCR_AES_CBC_128)
	encrAESCBC128 := encrType.(*ENCR_AES_CBC)
	encrKAESCBC128 := encrKType.(*ENCR_AES_CBC)

	// IKE Type
	// transformID()
	if encrType.transformID() != types.ENCR_AES_CBC {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := encrType.getAttribute()
	if attrPresent != true {
		t.Fatal("Attribute Present not correct")
	}
	if attrType != types.AttributeTypeKeyLength {
		t.Fatal("Attribute Type not correct")
	}
	if attrValue != 128 {
		t.Fatal("Attribute Value not correct")
	}
	if byteAttrValue != nil {
		t.Fatal("Variable Length Attribute Value not correct")
	}
	// setPriority()
	originPriority := encrAESCBC128.priority
	encrType.setPriority(0)
	if encrAESCBC128.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	encrType.setPriority(originPriority)
	if encrAESCBC128.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if encrType.Priority() != encrAESCBC128.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if encrType.GetKeyLength() != 16 {
		t.Fatal("GetKeyLength returned an error number")
	}

	// Init() and its encrypt/decrypt function
	// Test data is generated from openssl
	plainText := []byte("Test String....................................................................................................")
	// Cipher text from openssl
	cipherText := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaf, 0x56, 0xc0, 0x5d, 0x7e, 0x0e, 0xee, 0x38, 0x5e, 0xa8, 0xf5, 0xdf, 0xea, 0x29, 0xac, 0x46,
		0x1a, 0x31, 0x35, 0x9d, 0xa9, 0x89, 0x0e, 0x92, 0x0d, 0xe5, 0xe7, 0x7d, 0x8f, 0x12, 0x43, 0x92, 0xc6, 0xc2, 0x38, 0x5c, 0xe5, 0x2e, 0x8e, 0xbf, 0xc9, 0x43, 0x8e, 0x8e, 0xc1, 0x59, 0x5d, 0x6a,
		0xc2, 0x17, 0xab, 0xa9, 0xb5, 0xe9, 0x6c, 0x35, 0xb1, 0x7f, 0xc6, 0x10, 0x6e, 0xc4, 0x9d, 0x14, 0x6d, 0x77, 0xda, 0xa1, 0x8e, 0xc4, 0x56, 0x99, 0x39, 0x27, 0x60, 0xa5, 0xfc, 0x92, 0x68, 0x45,
		0x88, 0x71, 0xf4, 0xd0, 0xff, 0xf2, 0x80, 0xba, 0xe3, 0x33, 0x11, 0x94, 0x87, 0xca, 0x95, 0x0a, 0xac, 0xc6, 0x63, 0x4f, 0xe7, 0xe9, 0xa7, 0x5b, 0x59, 0xa6, 0x4c, 0x37, 0xa6, 0xb0, 0x10, 0x86,
		0x1f, 0xea, 0xc7, 0xbc, 0x1a, 0x3a, 0x3f, 0x6d, 0xb6, 0x10, 0xc0, 0xcf, 0xb6, 0x39, 0x16, 0x00}
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}

	// Object
	// Input an error key
	cryptoObj, err := encrType.Init(append(key, 0x09))
	if cryptoObj != nil || err == nil {
		t.Fatal("Doesn't return nil when fed with a key with mismatched length")
	}
	// Input a correct key
	cryptoObj, err = encrType.Init(key)
	if cryptoObj == nil || err != nil {
		t.Fatal("Cannot init crypto obj with a correct key")
	}

	// Decrypt
	decryptedText, err := cryptoObj.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("Decrypting with error: %s", err)
	}
	if !bytes.Equal(decryptedText, plainText) {
		t.Fatal("Result of decrypting is not correct")
	}

	// Encrypt using decrypted text, then decrypt with the same string
	encryptedText, err := cryptoObj.Encrypt(decryptedText)
	if err != nil {
		t.Fatalf("Encrypting with error: %s", err)
	}
	decryptedText, err = cryptoObj.Decrypt(encryptedText)
	if err != nil {
		t.Fatalf("Decrypting with error: %s", err)
	}
	if !bytes.Equal(decryptedText, plainText) {
		t.Fatal("Result of decrypting is not correct")
	}

	// Kernel Type
	// transformID()
	if encrKType.transformID() != types.ENCR_AES_CBC {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue = encrKType.getAttribute()
	if attrPresent != true {
		t.Fatal("Attribute Present not correct")
	}
	if attrType != types.AttributeTypeKeyLength {
		t.Fatal("Attribute Type not correct")
	}
	if attrValue != 128 {
		t.Fatal("Attribute Value not correct")
	}
	if byteAttrValue != nil {
		t.Fatal("Variable Length Attribute Value not correct")
	}
	// setPriority()
	originPriority = encrKAESCBC128.priority
	encrKType.setPriority(0)
	if encrKAESCBC128.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	encrKType.setPriority(originPriority)
	if encrKAESCBC128.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if encrKType.Priority() != encrKAESCBC128.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if encrKType.GetKeyLength() != 16 {
		t.Fatal("GetKeyLength returned an error number")
	}
	// XFRMString()
	if encrKType.XFRMString() != "cbc(aes)" {
		t.Fatal("XFRMString() returned an error string")
	}
}

func TestENCR_AES_CBC_192(t *testing.T) {
	// Get type using StrToType
	encrType := StrToType(String_ENCR_AES_CBC_192)
	encrKType := StrToKType(String_ENCR_AES_CBC_192)
	encrAESCBC192 := encrType.(*ENCR_AES_CBC)
	encrKAESCBC192 := encrKType.(*ENCR_AES_CBC)

	// IKE Type
	// transformID()
	if encrType.transformID() != types.ENCR_AES_CBC {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := encrType.getAttribute()
	if attrPresent != true {
		t.Fatal("Attribute Present not correct")
	}
	if attrType != types.AttributeTypeKeyLength {
		t.Fatal("Attribute Type not correct")
	}
	if attrValue != 192 {
		t.Fatal("Attribute Value not correct")
	}
	if byteAttrValue != nil {
		t.Fatal("Variable Length Attribute Value not correct")
	}
	// setPriority()
	originPriority := encrAESCBC192.priority
	encrType.setPriority(0)
	if encrAESCBC192.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	encrType.setPriority(originPriority)
	if encrAESCBC192.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if encrType.Priority() != encrAESCBC192.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if encrType.GetKeyLength() != 24 {
		t.Fatal("GetKeyLength returned an error number")
	}

	// Init() and its encrypt/decrypt function
	// Test data is generated from openssl
	plainText := []byte("Test String....................................................................................................")
	// Cipher text from openssl
	cipherText := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xbc, 0xee, 0x48, 0x33, 0x15, 0xfb, 0x01, 0x36, 0x54, 0xa7, 0xb9, 0xd1, 0x38, 0x2b, 0x41, 0x62,
		0x5b, 0x07, 0x05, 0xab, 0xa6, 0xc2, 0x84, 0x6b, 0xcf, 0x2e, 0xcc, 0x76, 0xfd, 0x22, 0x6b, 0x7d, 0x6b, 0x7f, 0x44, 0x92, 0x2a, 0x1d, 0x13, 0x06, 0x35, 0x5c, 0x96, 0xe7, 0x9a, 0x0a, 0x7b, 0x04,
		0x54, 0x8b, 0x9d, 0x58, 0x6f, 0xe0, 0x94, 0x87, 0xe0, 0xdc, 0xbe, 0x10, 0xcc, 0xf4, 0x20, 0xbb, 0x9e, 0xa1, 0x5e, 0x5d, 0x09, 0x4b, 0xe3, 0x17, 0xc8, 0x44, 0xea, 0xd3, 0x2c, 0xad, 0x6b, 0x32,
		0x9e, 0x1f, 0x7e, 0xef, 0x5a, 0xdb, 0xc2, 0xa7, 0x5d, 0x74, 0x1d, 0xf7, 0xdd, 0x3b, 0xa7, 0x4f, 0x12, 0x73, 0xb6, 0x46, 0x30, 0x0e, 0x76, 0xca, 0x1e, 0xc7, 0x1a, 0x7e, 0x94, 0xb9, 0x99, 0x92,
		0x5f, 0x27, 0xaa, 0x8f, 0x9e, 0xac, 0xfe, 0x19, 0xed, 0xe5, 0xf8, 0x46, 0x16, 0xbf, 0x49, 0x77}
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4}

	// Object
	// Input an error key
	cryptoObj, err := encrType.Init(append(key, 0x09))
	if cryptoObj != nil || err == nil {
		t.Fatal("Doesn't return nil when fed with a key with mismatched length")
	}
	// Input a correct key
	cryptoObj, err = encrType.Init(key)
	if cryptoObj == nil || err != nil {
		t.Fatal("Cannot init crypto obj with a correct key")
	}

	// Decrypt
	decryptedText, err := cryptoObj.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("Decrypting with error: %s", err)
	}
	if !bytes.Equal(decryptedText, plainText) {
		t.Fatal("Result of decrypting is not correct")
	}

	// Encrypt using decrypted text, then decrypt with the same string
	encryptedText, err := cryptoObj.Encrypt(decryptedText)
	if err != nil {
		t.Fatalf("Encrypting with error: %s", err)
	}
	decryptedText, err = cryptoObj.Decrypt(encryptedText)
	if err != nil {
		t.Fatalf("Decrypting with error: %s", err)
	}
	if !bytes.Equal(decryptedText, plainText) {
		t.Fatal("Result of decrypting is not correct")
	}

	// Kernel Type
	// transformID()
	if encrKType.transformID() != types.ENCR_AES_CBC {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue = encrKType.getAttribute()
	if attrPresent != true {
		t.Fatal("Attribute Present not correct")
	}
	if attrType != types.AttributeTypeKeyLength {
		t.Fatal("Attribute Type not correct")
	}
	if attrValue != 192 {
		t.Fatal("Attribute Value not correct")
	}
	if byteAttrValue != nil {
		t.Fatal("Variable Length Attribute Value not correct")
	}
	// setPriority()
	originPriority = encrKAESCBC192.priority
	encrKType.setPriority(0)
	if encrKAESCBC192.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	encrKType.setPriority(originPriority)
	if encrKAESCBC192.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if encrKType.Priority() != encrKAESCBC192.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if encrKType.GetKeyLength() != 24 {
		t.Fatal("GetKeyLength returned an error number")
	}
	// XFRMString()
	if encrKType.XFRMString() != "cbc(aes)" {
		t.Fatal("XFRMString() returned an error string")
	}
}

func TestENCR_AES_CBC_256(t *testing.T) {
	// Get type using StrToType
	encrType := StrToType(String_ENCR_AES_CBC_256)
	encrKType := StrToKType(String_ENCR_AES_CBC_256)
	encrAESCBC256 := encrType.(*ENCR_AES_CBC)
	encrKAESCBC256 := encrKType.(*ENCR_AES_CBC)

	// IKE Type
	// transformID()
	if encrType.transformID() != types.ENCR_AES_CBC {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := encrType.getAttribute()
	if attrPresent != true {
		t.Fatal("Attribute Present not correct")
	}
	if attrType != types.AttributeTypeKeyLength {
		t.Fatal("Attribute Type not correct")
	}
	if attrValue != 256 {
		t.Fatal("Attribute Value not correct")
	}
	if byteAttrValue != nil {
		t.Fatal("Variable Length Attribute Value not correct")
	}
	// setPriority()
	originPriority := encrAESCBC256.priority
	encrType.setPriority(0)
	if encrAESCBC256.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	encrType.setPriority(originPriority)
	if encrAESCBC256.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if encrType.Priority() != encrAESCBC256.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if encrType.GetKeyLength() != 32 {
		t.Fatal("GetKeyLength returned an error number")
	}

	// Init() and its encrypt/decrypt function
	// Test data is generated from openssl
	plainText := []byte("Test String....................................................................................................")
	// Cipher text from openssl
	cipherText := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x18, 0xd8, 0x51, 0x04, 0x67, 0x9c, 0xc6, 0xbc, 0xde, 0x75, 0xdd, 0x5c, 0xfe, 0x8e, 0xe6, 0xf1,
		0xa6, 0x7d, 0x24, 0xff, 0x3a, 0x97, 0xcd, 0x98, 0x02, 0x76, 0xac, 0xf5, 0x23, 0x54, 0x51, 0xb7, 0x83, 0xa4, 0xeb, 0xaa, 0xfa, 0x96, 0xf6, 0x38, 0xcb, 0x38, 0x73, 0x54, 0x91, 0xfb, 0xa7, 0xcd,
		0x8c, 0x63, 0xd8, 0xd4, 0xd3, 0xed, 0xc0, 0x3c, 0x89, 0x12, 0xc2, 0x41, 0x3b, 0x29, 0x65, 0xc1, 0xba, 0x1f, 0xcd, 0x91, 0xce, 0x81, 0xb1, 0x26, 0x2c, 0x6a, 0x1a, 0x47, 0x1a, 0x52, 0xc7, 0xc2,
		0xb3, 0xf2, 0x1e, 0xf5, 0x81, 0xf8, 0x38, 0x10, 0x46, 0x94, 0xff, 0xdb, 0x17, 0xdc, 0xac, 0x0b, 0x01, 0xba, 0x37, 0xd1, 0xaf, 0x72, 0xc5, 0xb5, 0x34, 0x5a, 0xc8, 0xc3, 0xa1, 0xbd, 0x95, 0xab,
		0xfb, 0xed, 0xb5, 0xec, 0x97, 0xeb, 0x2a, 0xec, 0x25, 0x89, 0xea, 0xd9, 0x6a, 0x3e, 0x9c, 0x31}
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2}

	// Object
	// Input an error key
	cryptoObj, err := encrType.Init(append(key, 0x09))
	if cryptoObj != nil || err == nil {
		t.Fatal("Doesn't return nil when fed with a key with mismatched length")
	}
	// Input a correct key
	cryptoObj, err = encrType.Init(key)
	if cryptoObj == nil || err != nil {
		t.Fatal("Cannot init crypto obj with a correct key")
	}

	// Decrypt
	decryptedText, err := cryptoObj.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("Decrypting with error: %s", err)
	}
	if !bytes.Equal(decryptedText, plainText) {
		t.Fatal("Result of decrypting is not correct")
	}

	// Encrypt using decrypted text, then decrypt with the same string
	encryptedText, err := cryptoObj.Encrypt(decryptedText)
	if err != nil {
		t.Fatalf("Encrypting with error: %s", err)
	}
	decryptedText, err = cryptoObj.Decrypt(encryptedText)
	if err != nil {
		t.Fatalf("Decrypting with error: %s", err)
	}
	if !bytes.Equal(decryptedText, plainText) {
		t.Fatal("Result of decrypting is not correct")
	}

	// Kernel Type
	// transformID()
	if encrKType.transformID() != types.ENCR_AES_CBC {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue = encrKType.getAttribute()
	if attrPresent != true {
		t.Fatal("Attribute Present not correct")
	}
	if attrType != types.AttributeTypeKeyLength {
		t.Fatal("Attribute Type not correct")
	}
	if attrValue != 256 {
		t.Fatal("Attribute Value not correct")
	}
	if byteAttrValue != nil {
		t.Fatal("Variable Length Attribute Value not correct")
	}
	// setPriority()
	originPriority = encrKAESCBC256.priority
	encrKType.setPriority(0)
	if encrKAESCBC256.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	encrKType.setPriority(originPriority)
	if encrKAESCBC256.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if encrKType.Priority() != encrKAESCBC256.priority {
		t.Fatal("Priority returned an error number")
	}
	// GetKeyLength()
	if encrKType.GetKeyLength() != 32 {
		t.Fatal("GetKeyLength returned an error number")
	}
	// XFRMString()
	if encrKType.XFRMString() != "cbc(aes)" {
		t.Fatal("XFRMString() returned an error string")
	}
}
