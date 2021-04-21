package dh

import (
	"math/big"

	"bitbucket.org/_syujy/ike/types"
)

const (
	String_DH_1024_BIT_MODP string = "DH_1024_BIT_MODP"
	// Parameters
	group2PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE65381FFFFFFFFFFFFFFFF"
	group2Generator = 2
)

func toString_DH_1024_BIT_MODP(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_DH_1024_BIT_MODP
}

var _ DHType = &DH_1024_BIT_MODP{}

type DH_1024_BIT_MODP struct {
	priority          uint32
	factor            *big.Int
	generator         *big.Int
	factorBytesLength int
}

func (t *DH_1024_BIT_MODP) transformID() uint16 {
	return types.DH_1024_BIT_MODP
}

func (t *DH_1024_BIT_MODP) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *DH_1024_BIT_MODP) setPriority(priority uint32) {
	t.priority = priority
}

func (t *DH_1024_BIT_MODP) Priority() uint32 {
	return t.priority
}

func (t *DH_1024_BIT_MODP) GetSharedKey(secret, peerPublicValue *big.Int) []byte {
	sharedKey := new(big.Int).Exp(peerPublicValue, secret, t.factor).Bytes()
	prependZero := make([]byte, t.factorBytesLength-len(sharedKey))
	sharedKey = append(prependZero, sharedKey...)
	return sharedKey
}

func (t *DH_1024_BIT_MODP) GetPublicValue(secret *big.Int) []byte {
	localPublicValue := new(big.Int).Exp(t.generator, secret, t.factor).Bytes()
	prependZero := make([]byte, t.factorBytesLength-len(localPublicValue))
	localPublicValue = append(prependZero, localPublicValue...)
	return localPublicValue
}
