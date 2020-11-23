package dh

import (
	"errors"
	"math/big"

	"ike/internal/logger"
	"ike/internal/types"
	"ike/message"

	"github.com/sirupsen/logrus"
)

var dhLog *logrus.Entry
var dhString map[uint16]func(uint16, uint16, []byte) string
var dhTypes map[string]DHType

func init() {
	// Log
	dhLog = logger.DHLog

	// DH String
	dhString = make(map[uint16]func(uint16, uint16, []byte) string)
	dhString[types.DH_1024_BIT_MODP] = toString_DH_1024_BIT_MODP
	dhString[types.DH_2048_BIT_MODP] = toString_DH_2048_BIT_MODP

	// DH Types
	dhTypes = make(map[string]DHType)

	var factor, generator *big.Int

	// Group 2: DH_1024_BIT_MODP
	factor, ok := new(big.Int).SetString(Group2PrimeString, 16)
	if !ok {
		dhLog.Error("Error occurs when setting big number")
		panic("IKE Diffie Hellman Group failed to init.")
	}
	generator = new(big.Int).SetUint64(Group2Generator)
	dhTypes[String_DH_1024_BIT_MODP] = &DH_1024_BIT_MODP{
		factor:            factor,
		generator:         generator,
		factorBytesLength: len(factor.Bytes()),
	}

	// Group 14: DH_2048_BIT_MODP
	factor, ok = new(big.Int).SetString(Group14PrimeString, 16)
	if !ok {
		dhLog.Error("Error occurs when setting big number")
		panic("IKE Diffie Hellman Group failed to init.")
	}
	generator = new(big.Int).SetUint64(Group14Generator)
	dhTypes[String_DH_2048_BIT_MODP] = &DH_2048_BIT_MODP{
		factor:            factor,
		generator:         generator,
		factorBytesLength: len(factor.Bytes()),
	}

	// Default Priority
	priority := []string{
		String_DH_1024_BIT_MODP,
		String_DH_2048_BIT_MODP,
	}

	// Set Priority
	for i, s := range priority {
		if dhType, ok := dhTypes[s]; ok {
			dhType.setPriority(uint32(i))
		} else {
			dhLog.Error("No such DH group implementation")
			panic("IKE Diffie Hellman Group failed to init.")
		}
	}
}

// Definition of Diffie-Hellman groups
// The strength supplied by group 1 may not be sufficient for typical usage
const (
	// Group 2
	Group2PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE65381FFFFFFFFFFFFFFFF"
	Group2Generator = 2

	// Group 14
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

func SetPriority(algolist []string) error {
	// check implemented
	for _, algo := range algolist {
		if _, ok := dhTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for i, algo := range algolist {
		dhTypes[algo].setPriority(uint32(i))
	}
	return nil
}

func StrToType(algo string) DHType {
	if t, ok := dhTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) DHType {
	if f, ok := dhString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if dhType, ok := dhTypes[s]; ok {
				return dhType
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

func ToTransform(dhType DHType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = types.TypeDiffieHellmanGroup
	t.TransformID = dhType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = dhType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = 1 // TV
	}
	return t
}

type DHType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	GetSharedKey(secret, peerPublicValue *big.Int) []byte
	GetPublicValue(secret *big.Int) []byte
}

/*
func CalculateDiffieHellmanMaterials(secret *big.Int, peerPublicValue []byte,
	dhGroupNumber uint16) ([]byte, []byte) {
	if calc, ok := calculator[dhGroupNumber]; ok {
		return calc(secret, peerPublicValue)
	} else {
		secLog.Errorf("Unsupported Diffie-Hellman group: %d", dhGroupNumber)
		return nil, nil
	}
}
*/
