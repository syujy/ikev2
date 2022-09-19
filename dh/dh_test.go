package dh

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/syujy/ikev2/message"
	"github.com/syujy/ikev2/types"
)

func TestStrToType(t *testing.T) {
	// Test StrToType return a type
	dhType := StrToType("DH_1024_BIT_MODP")
	if dhType == nil {
		t.Fatal("Get type DH_1024_BIT_MODP failed")
	}
	dhType = StrToType("DH_2048_BIT_MODP")
	if dhType == nil {
		t.Fatal("Get type DH_2048_BIT_MODP failed")
	}
	// Test StrToType return a nil
	dhType = StrToType("1024_BIT_MODP")
	if dhType != nil {
		t.Fatal("Get a type object with an undefined type string")
	}
}

func TestStrToTransform(t *testing.T) {
	// Test StrToTransform return a transform
	dhTran := StrToTransform("DH_1024_BIT_MODP")
	if dhTran == nil {
		t.Fatal("Get transform DH_1024_BIT_MODP failed")
	}
	dhTran = StrToTransform("DH_2048_BIT_MODP")
	if dhTran == nil {
		t.Fatal("Get trandform DH_2048_BIT_MODP failed")
	}
	// Test StrToTransform return a nil
	dhTran = StrToTransform("1024_BIT_MODP")
	if dhTran != nil {
		t.Fatal("Get a transform with an undefined type string")
	}
}

func TestSetPriority(t *testing.T) {
	// Test SetPriority set priority correctly
	dhType1024 := StrToType("DH_1024_BIT_MODP") // will be set to priority 1
	dhType2048 := StrToType("DH_2048_BIT_MODP") // will be set to priority 0

	algolist := map[string]uint32{
		"DH_1024_BIT_MODP": 1,
		"DH_2048_BIT_MODP": 0,
	}
	err := SetPriority(algolist)
	if err != nil {
		t.Fatalf("Error: %+v", err)
	}
	if dhType1024.Priority() != 1 {
		t.Fatal("Type DH_1024_BIT_MODP priority != 1")
	}
	if dhType2048.Priority() != 0 {
		t.Fatal("Type DH_2048_BIT_MODP priority != 0")
	}
	// Test SetPriority set with an error returned
	algolist["DH_1024_BIT_MODP"] = 0
	algolist["DH_2048_BIT_MODP"] = 1
	algolist["1024_BIT_MODP"] = 0
	err = SetPriority(algolist)
	if err == nil {
		t.Fatal("SetPriority() reported not failed when fed with an incorrect algolist")
	} else {
		t.Logf("SetPriority reported error: %+v. This behavior is correct.", err)
	}
	if dhType1024.Priority() != 1 {
		t.Fatal("Type DH_1024_BIT_MODP priority != 1")
	}
	if dhType2048.Priority() != 0 {
		t.Fatal("Type DH_2048_BIT_MODP priority != 0")
	}
}

func TestToTransform(t *testing.T) {
	// Prepare correct structure
	correctTransform := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_1024_BIT_MODP,
		AttributePresent: false,
		// don't care, init to zero value by golang
	}
	dhType := StrToType("DH_1024_BIT_MODP")
	transform := ToTransform(dhType)
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
	tDHType := StrToType("DH_1024_BIT_MODP")
	// Test transform
	transform := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_1024_BIT_MODP,
		AttributePresent: false,
		// don't care, init to zero value by golang
	}
	dhType := DecodeTransform(transform)
	if dhType != tDHType {
		t.Fatal("Returned type not matched")
	}
}

// Interfaces implementation tests
func TestDH_1024_BIT_MODP(t *testing.T) {
	// Get type using StrToType
	dhType := StrToType(String_DH_1024_BIT_MODP)
	dh1024modpgroup := dhType.(*DH_MODP)

	// transformID()
	if dhType.TransformID() != types.DH_1024_BIT_MODP {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := dhType.GetAttribute()
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
	originPriority := dh1024modpgroup.priority
	dhType.SetPriority(0)
	if dh1024modpgroup.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	dhType.SetPriority(originPriority)
	if dh1024modpgroup.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if dhType.Priority() != dh1024modpgroup.priority {
		t.Fatal("Priority returned an error number")
	}

	// GetSharedKey() and GetPublicValue()
	// Test data is generated from openssl
	xA := "74b4d136d6df216eeca01e54123aa5ecf9313c60828df993edc55ed18511" +
		"7204b7222982c948bc41ead31a6412f541f043081765d5789cf98e4ab1a2" +
		"bb2ced08b57c4401567e27956d5dfda9856ac623f8e67464d544bea31a49" +
		"d11e17e2cf8559801ee15fc425c13e2666225fb44c721beb539a9955e546" +
		"9a10213587f52ec4"
	yA := "65048613291fb9e9bc4677a941c5476e4a352954d20f276f74ccc3bbfe10" +
		"e65e87d01de2e926ed8b9a505fd38ab048136f92661c77cc681f65b8ddb9" +
		"74c3f62b15b7c7ddab751dd758f3e659ac514ae8e502edd567e48467bbd1" +
		"5a037ac5c10413c4c6fa944f7a686cbad4a0038e17788ca7e8df7210d1a8" +
		"05ec13dc7cb063f3"
	xB := "4e88c3728af429b3c67047e9e3fd7b0240a1cd5bee3714b93b49d6251c2d" +
		"9c8317d2971e7673acebb64255cd8be8a122031c0d9bcdfae66b8a6e2630" +
		"239eea402658846c4d6b87ab62ba6197ad52e38681672479aa933e953e98" +
		"79c9274d1aec856957a5e19cd52112d89342839c383fc0bae9a97462a72f" +
		"1bbc46ce74617a0c"
	yB := "2eb8e52e0bbadaef8d0c0ed0b3dd6172df897b2bb410b4352a7f4a8e25a9" +
		"57d4d613846a281891e18a28ec7e524ce32e51a015ac024ba57c713abda0" +
		"bc21674ed348b14834b3c440cafe0df0143b9b7b5d7d9bd432f97a2670cb" +
		"dae27ca54ac83f5d343e5f20e5be7797f5d9f586e3111af2b1daeae16892" +
		"67d42437d5d78914"
	Z := "b5aa0846c23f369fddf03ba857eeb9ea90abf4012e2d09fa671b1b171e30326c" +
		"8a788befd24588428d82fcb50b67e1a0f63e873e9044b6d0759bdc0ba4ea8616" +
		"430af34c3e6cca069fd2bcece49e32535dee0f4467fee36314d8d86de993f943" +
		"fc461c1631cbe457a4432f3467de98638a47d8d1fb65f32a93a69df7224f2d08"

	secretA, ok := new(big.Int).SetString(xA, 16)
	if !ok {
		t.Fatal("Set secret A failed")
	}
	publicA, ok := new(big.Int).SetString(yA, 16)
	if !ok {
		t.Fatal("Set public A failed")
	}
	secretB, ok := new(big.Int).SetString(xB, 16)
	if !ok {
		t.Fatal("Set secret B failed")
	}
	publicB, ok := new(big.Int).SetString(yB, 16)
	if !ok {
		t.Fatal("Set public B failed")
	}
	sharedKey, ok := new(big.Int).SetString(Z, 16)
	if !ok {
		t.Fatal("Set shared key failed")
	}

	pa := new(big.Int).SetBytes(dhType.GetPublicValue(secretA))
	if publicA.Cmp(pa) != 0 {
		t.Fatal("GetPublicValue() error when calculating public value of A")
	}
	pb := new(big.Int).SetBytes(dhType.GetPublicValue(secretB))
	if publicB.Cmp(pb) != 0 {
		t.Fatal("GetPublicValue() error when calculating public value of B")
	}

	sharedKeyAB := new(big.Int).SetBytes(dhType.GetSharedKey(secretA, publicB))
	if sharedKey.Cmp(sharedKeyAB) != 0 {
		t.Fatal("GetSharedKey() error when calculating shared key with secret A and public B")
	}
	sharedKeyBA := new(big.Int).SetBytes(dhType.GetSharedKey(secretB, publicA))
	if sharedKey.Cmp(sharedKeyBA) != 0 {
		t.Fatal("GetSharedKey() error when calculating shared key with secret B and public A")
	}
}

func TestDH_2048_BIT_MODP(t *testing.T) {
	// Get type using StrToType
	dhType := StrToType(String_DH_2048_BIT_MODP)
	dh2048modpgroup := dhType.(*DH_MODP)

	// transformID()
	if dhType.TransformID() != types.DH_2048_BIT_MODP {
		t.Fatal("Transform ID not correct")
	}
	// getAttribute()
	attrPresent, attrType, attrValue, byteAttrValue := dhType.GetAttribute()
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
	originPriority := dh2048modpgroup.priority
	dhType.SetPriority(0)
	if dh2048modpgroup.priority != 0 {
		t.Fatal("Set Priority failed")
	}
	dhType.SetPriority(originPriority)
	if dh2048modpgroup.priority != originPriority {
		t.Fatal("Set Priority failed")
	}
	// Priority()
	if dhType.Priority() != dh2048modpgroup.priority {
		t.Fatal("Priority returned an error number")
	}

	// GetSharedKey() and GetPublicValue()
	// Test data is generated from openssl
	xA := "6a65ebe8acbfc990cd37a86403d75f488849fe5de2f31495f33d5b9abc57" +
		"7f85e64a62c287b20200d3dc0ba6a9305368fe5a124fe3d46f20013991dd" +
		"4e9ddc8233701318591d54a9471140785e88c4fe47e5d942aef43d2eead2" +
		"b30015cbcf661777f2cb03cb3a1f1fb308110efad177044b914909dcd3b2" +
		"7f44da3f99e94ddd2d22e7c4ff50f2e8e03373c208e871f3ded2e4812d76" +
		"be03b0909d943df7c8ddb7f5e274a7f8ffe0bfc30a0e66a7979df22427ab" +
		"ef29da1896a4516aee32f620e90183f8453f0c464c00519ea2efcd6a8104" +
		"e81c1b653c2e0af6b08197e84179cf04a7e4773511008e66f13632922810" +
		"039008a7e3518157c4af9367749c234e"
	yA := "0080c5ffc42a3aeaab1c00b857af7ee20e8167f5a317e175aff434c2316e" +
		"b23291926be89c70a4ca9e8bb277946717d1f6dc23dd96bc4a3aecde7838" +
		"3bea0fd53d2b8e9d61869a8971a4bdc8fe6cfb656256c4e264c89245cdad" +
		"b9f5137331381b5c035e1d1f2de2862a212528af6834d132ab85379e6ec5" +
		"85678a740c1b82a7d497d3e8cc63923bbfea90e52c1366d55492a846083f" +
		"6fb0dea2f022654dd3a9c5dca54554f519312e0152457324b2144599139c" +
		"6afd34c069001373c73b09f9a2cb4691e5b6e9f5b138d8ee42ecc29696a3" +
		"f10ccbd8e370807a04dfba34f20f4e020924becac49423c362180a6125da" +
		"53322a54b6b6b0510be8ba8dd093fe73"
	xB := "7248afc863db56281396aed5c3ec0d04edda17ea224987aca7cc37d9b35d" +
		"432c74480f65f808e1d2f3b53d1deea622e8dee19a478127971f0abcb946" +
		"45d8aa4ebc6de11f6aa28e61a67009551c1956599a3309be85556d7a144d" +
		"774adaf56a1dddc0b83835729ea562c27db7d3993ea5db3212e2ede66260" +
		"6614f7182152ba9e645b7a1699ace5a21e9b286cc2a74f54c3225c443f0e" +
		"70ac47a40f65ac98dd8b35526502a25801f4f5223dcd65121fe6d6a394a3" +
		"01948580f499866c688b7dc568116f23637f21e48280b80908ba5baf9ba9" +
		"b24afe69da16430c462ceacc6cbfeb15265ee23802a67a0cd36c4e567122" +
		"996acf5bd8fae936fd0cb563a8c698f9"
	yB := "00dfda49c5aa12671f3ffe97eb8b56f623f470d0e2bfbefa73ebb8e72b5a" +
		"68dd1c90698bd08de626d56ebd469638d6e2e7c63565283a532c9ebaed7d" +
		"385519a668d965653912b1a975cfc0e7ea0f12920f177d7d7aecef9cb5d3" +
		"62271c18d065f23c49053fec0de3451d7248f193949f6c02db38343c0993" +
		"01a0d0352188666b3abbd83078af89523aa4c43881de0447d0a479d64e81" +
		"fcfd76d1fbc7fffc86d8c4951ab1f13fead56a159f541a1a821af6c8bca7" +
		"8bec49553e951e36bb307d7327bca3ae03f084a2ef4c0981197306fd87f4" +
		"feae0828931e31b060d395187034037fd23a456e0d42b8eee63dedb67567" +
		"aeb57ed75b01b2636a1543541c12ca934e"
	Z := "785d0924a020241db7a84d9a14eab1f8ba2425eb0238f87ccd1498afceb7097f" +
		"81242407713d8cce0e886541eebdf4f0f4035ddd9ebe889c1f09bba0f628e62f" +
		"49604d82e1af1c242e37c8bbd4effcfc3b6e6c9e2de2215d39369a77bf63572e" +
		"644259eee7700e7166f6bda02307aec6fb548302f09ccb83a24f5f4f641b1c72" +
		"4609ccbf5eb0ad23df170298311159766e5c6b24c48f28ee00f40ee2383913ee" +
		"55b599b9f82e5479f51c8bbf9cdc9bf69ca91c700b964686b8aec0defda23c0b" +
		"f0a52c7cd23d226179ccecd46e8d0a2586389e7910712b929f2c35c4c9ce80e5" +
		"493dbceca363874de18e8162838b4dfdcbf43cbb33d0bfb02ede66e92b662988"

	secretA, ok := new(big.Int).SetString(xA, 16)
	if !ok {
		t.Fatal("Set secret A failed")
	}
	publicA, ok := new(big.Int).SetString(yA, 16)
	if !ok {
		t.Fatal("Set public A failed")
	}
	secretB, ok := new(big.Int).SetString(xB, 16)
	if !ok {
		t.Fatal("Set secret B failed")
	}
	publicB, ok := new(big.Int).SetString(yB, 16)
	if !ok {
		t.Fatal("Set public B failed")
	}
	sharedKey, ok := new(big.Int).SetString(Z, 16)
	if !ok {
		t.Fatal("Set shared key failed")
	}

	pa := new(big.Int).SetBytes(dhType.GetPublicValue(secretA))
	if publicA.Cmp(pa) != 0 {
		t.Fatal("GetPublicValue() error when calculating public value of A")
	}
	pb := new(big.Int).SetBytes(dhType.GetPublicValue(secretB))
	if publicB.Cmp(pb) != 0 {
		t.Fatal("GetPublicValue() error when calculating public value of B")
	}

	sharedKeyAB := new(big.Int).SetBytes(dhType.GetSharedKey(secretA, publicB))
	if sharedKey.Cmp(sharedKeyAB) != 0 {
		t.Fatal("GetSharedKey() error when calculating shared key with secret A and public B")
	}
	sharedKeyBA := new(big.Int).SetBytes(dhType.GetSharedKey(secretB, publicA))
	if sharedKey.Cmp(sharedKeyBA) != 0 {
		t.Fatal("GetSharedKey() error when calculating shared key with secret B and public A")
	}
}
