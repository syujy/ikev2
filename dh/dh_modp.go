package dh

import (
	"errors"
	"math/big"

	"bitbucket.org/_syujy/ike/types"
)

const (
	String_DH_1024_BIT_MODP string = "DH_1024_BIT_MODP"
	String_DH_2048_BIT_MODP string = "DH_2048_BIT_MODP"
)

var _ DHType = &DH_MODP{}

type DH_MODP struct {
	transformID       uint16
	priority          uint32
	factor            *big.Int
	generator         *big.Int
	factorBytesLength int
}

func (t *DH_MODP) TransformID() uint16 {
	return t.transformID
}

func (t *DH_MODP) GetAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *DH_MODP) SetPriority(priority uint32) {
	t.priority = priority
}

func (t *DH_MODP) Priority() uint32 {
	return t.priority
}

func (t *DH_MODP) GetSharedKey(secret, peerPublicValue *big.Int) []byte {
	sharedKey := new(big.Int).Exp(peerPublicValue, secret, t.factor).Bytes()
	prependZero := make([]byte, t.factorBytesLength-len(sharedKey))
	sharedKey = append(prependZero, sharedKey...)
	return sharedKey
}

func (t *DH_MODP) GetPublicValue(secret *big.Int) []byte {
	localPublicValue := new(big.Int).Exp(t.generator, secret, t.factor).Bytes()
	prependZero := make([]byte, t.factorBytesLength-len(localPublicValue))
	localPublicValue = append(prependZero, localPublicValue...)
	return localPublicValue
}

// DH_1024_BIT_MODP
func toString_DH_1024_BIT_MODP(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_DH_1024_BIT_MODP
}

func NewType_DH_1024_BIT_MODP() (*DH_MODP, error) {
	var group2PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE65381FFFFFFFFFFFFFFFF"
	var group2Generator uint64 = 2

	factor, ok := new(big.Int).SetString(group2PrimeString, 16)
	if !ok {
		return nil, errors.New("Setting big number: Group 2.")
	}
	generator := new(big.Int).SetUint64(group2Generator)

	dhType := &DH_MODP{
		transformID:       types.DH_1024_BIT_MODP,
		factor:            factor,
		generator:         generator,
		factorBytesLength: len(group2PrimeString),
	}

	return dhType, nil
}

// DH_2048_BIT_MODP
func toString_DH_2048_BIT_MODP(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_DH_2048_BIT_MODP
}

func NewType_DH_2048_BIT_MODP() (*DH_MODP, error) {
	var group14PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
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
	var group14Generator uint64 = 2

	factor, ok := new(big.Int).SetString(group14PrimeString, 16)
	if !ok {
		return nil, errors.New("Setting big number: Group 14.")
	}
	generator := new(big.Int).SetUint64(group14Generator)

	dhType := &DH_MODP{
		transformID:       types.DH_2048_BIT_MODP,
		factor:            factor,
		generator:         generator,
		factorBytesLength: len(group14PrimeString),
	}

	return dhType, nil
}
