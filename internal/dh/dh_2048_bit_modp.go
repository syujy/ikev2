package dh

import (
	"math/big"

	"bitbucket.org/_syujy/ike/types"
)

const (
	string_DH_2048_BIT_MODP string = "DH_2048_BIT_MODP"
	// Parameters
	Group14PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE45B3DC2007CB8A163BF05" +
		"98DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB" +
		"9ED529077096966D670C354E4ABC9804" +
		"F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28F" +
		"B5C55DF06F4C52C9DE2BCBF695581718" +
		"3995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	Group14Generator = 2
)

func toString_DH_2048_BIT_MODP(attrType uint16, intValue uint16, bytesValue []byte) string {
	return string_DH_2048_BIT_MODP
}

var _ DHType = &DH_2048_BIT_MODP{}

type DH_2048_BIT_MODP struct {
	priority          uint32
	factor            *big.Int
	generator         *big.Int
	factorBytesLength int
}

func (t *DH_2048_BIT_MODP) transformID() uint16 {
	return types.DH_2048_BIT_MODP
}

func (t *DH_2048_BIT_MODP) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *DH_2048_BIT_MODP) setPriority(priority uint32) {
	t.priority = priority
}

func (t *DH_2048_BIT_MODP) Priority() uint32 {
	return t.priority
}

func (t *DH_2048_BIT_MODP) GetSharedKey(secret, peerPublicValue *big.Int) []byte {
	sharedKey := new(big.Int).Exp(peerPublicValue, secret, t.factor).Bytes()
	prependZero := make([]byte, t.factorBytesLength-len(sharedKey))
	sharedKey = append(prependZero, sharedKey...)
	return sharedKey
}

func (t *DH_2048_BIT_MODP) GetPublicValue(secret *big.Int) []byte {
	localPublicValue := new(big.Int).Exp(t.generator, secret, t.factor).Bytes()
	prependZero := make([]byte, t.factorBytesLength-len(localPublicValue))
	localPublicValue = append(prependZero, localPublicValue...)
	return localPublicValue
}
