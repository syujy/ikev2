package dh

import (
	"ike/internal/types"
	"math/big"
)

const String_DH_1024_BIT_MODP string = "DH_1024_BIT_MODP"

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
