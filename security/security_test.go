package security

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"bitbucket.org/_syujy/ike/internal/dh"
	"bitbucket.org/_syujy/ike/internal/encr"
	"bitbucket.org/_syujy/ike/internal/esn"
	"bitbucket.org/_syujy/ike/internal/integ"
	"bitbucket.org/_syujy/ike/internal/prf"
	"bitbucket.org/_syujy/ike/message"
	"bitbucket.org/_syujy/ike/types"
)

func TestGenerateRandomNumber(t *testing.T) {
	// Test multiple go routines call function simultaneously
	// create 100 go routines
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			num := GenerateRandomNumber()
			if num == nil {
				fmt.Print("Generate random number failed.")
			} else {
				fmt.Printf("Random number: %v\n", num)
				wg.Done()
			}
		}(&wg)
	}
	wg.Wait()
}

func TestGenerateRandomUint8(t *testing.T) {
	// Test multiple go routines call function simultaneously
	// create 100 go routines
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			num, err := GenerateRandomUint8()
			if err != nil {
				fmt.Printf("Generate random number failed. Error: %+v", err)
			} else {
				fmt.Printf("Random number: %v\n", num)
				wg.Done()
			}
		}(&wg)
	}
	wg.Wait()
}

func TestConcatenateNonceAndSPI(t *testing.T) {
	correct_result := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	nonce := []byte{0x01, 0x02, 0x03, 0x04}
	ispi := uint64(0x0506070809000102)
	rspi := uint64(0x0304050607080900)
	result := concatenateNonceAndSPI(nonce, ispi, rspi)
	if !bytes.Equal(correct_result, result) {
		t.FailNow()
	}
}

func TestIKESelectProposal(t *testing.T) {
	// Types' pointers
	dhType1 := dh.StrToType("DH_1024_BIT_MODP")
	dhType2 := dh.StrToType("DH_2048_BIT_MODP")
	//encrType1 := encr.StrToType("ENCR_AES_CBC_128")
	//encrType2 := encr.StrToType("ENCR_AES_CBC_192")
	encrType3 := encr.StrToType("ENCR_AES_CBC_256")
	//integType1 := integ.StrToType("AUTH_HMAC_MD5_96")
	integType2 := integ.StrToType("AUTH_HMAC_SHA1_96")
	//prfType1 := prf.StrToType("PRF_HMAC_MD5")
	prfType2 := prf.StrToType("PRF_HMAC_SHA1")

	// Transforms
	t1 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_1024_BIT_MODP,
		AttributePresent: false,
	}
	t2 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_2048_BIT_MODP,
		AttributePresent: false,
	}
	t3 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_1536_BIT_MODP,
		AttributePresent: false,
	}
	t4 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   128,
	}
	t5 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   192,
	}
	t6 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   256,
	}
	t7 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   384,
	}
	t8 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_3DES,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   128,
	}
	t9 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_MD5_96,
		AttributePresent: false,
	}
	t10 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_SHA1_96,
		AttributePresent: false,
	}
	t11 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_DES_MAC,
		AttributePresent: false,
	}
	t12 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_MD5,
		AttributePresent: false,
	}
	t13 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_SHA1,
		AttributePresent: false,
	}
	t14 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_TIGER,
		AttributePresent: false,
	}
	t15 := &message.Transform{
		TransformType:    types.TypeExtendedSequenceNumbers,
		TransformID:      types.ESN_ENABLE,
		AttributePresent: false,
	}

	// Proposal 1
	proposal := new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t3)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t7)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t8)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t9)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t13)

	ikesa := new(IKESA)
	if ikesa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	// Proposal 2
	proposal = new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t1)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t2)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t4)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t5)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t6)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t10)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t11)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t12)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t13)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t14)

	ikesa = new(IKESA)
	if !ikesa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	if ikesa.dhInfo != dhType2 || ikesa.encrInfo != encrType3 ||
		ikesa.integInfo != integType2 || ikesa.prfInfo != prfType2 {
		t.Fatal("SelectProposal selected a false result")
	}

	newPriority := map[string]uint32{
		"DH_1024_BIT_MODP": 1,
		"DH_2048_BIT_MODP": 0,
	}
	if err := dh.SetPriority(newPriority); err != nil {
		t.Fatalf("Set priority failed: %v", err)
	}

	ikesa = new(IKESA)
	if !ikesa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	if ikesa.dhInfo != dhType1 || ikesa.encrInfo != encrType3 ||
		ikesa.integInfo != integType2 || ikesa.prfInfo != prfType2 {
		t.Fatal("SelectProposal selected a false result")
	}

	// reset priority
	newPriority = map[string]uint32{
		"DH_1024_BIT_MODP": 0,
		"DH_2048_BIT_MODP": 1,
	}
	if err := dh.SetPriority(newPriority); err != nil {
		t.Fatalf("Set priority failed: %v", err)
	}

	// Proposal 3
	proposal = new(message.Proposal)

	ikesa = new(IKESA)
	if ikesa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	// Proposal 4
	proposal = new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t2)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t5)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t6)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t9)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t13)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t15)

	ikesa = new(IKESA)
	if ikesa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

}

func TestIKEToProposal(t *testing.T) {
	dhType := dh.StrToType("DH_1024_BIT_MODP")
	encrType := encr.StrToType("ENCR_AES_CBC_256")
	integType := integ.StrToType("AUTH_HMAC_MD5_96")
	prfType := prf.StrToType("PRF_HMAC_SHA1")

	ikesa := IKESA{
		dhInfo:    dhType,
		encrInfo:  encrType,
		integInfo: integType,
		prfInfo:   prfType,
	}

	proposal := ikesa.ToProposal()

	if len(proposal.DiffieHellmanGroup) != 1 ||
		len(proposal.EncryptionAlgorithm) != 1 ||
		len(proposal.IntegrityAlgorithm) != 1 ||
		len(proposal.PseudorandomFunction) != 1 ||
		len(proposal.ExtendedSequenceNumbers) != 0 {
		t.FailNow()
	}
}

func TestIKESetProposal(t *testing.T) {
	dhType := dh.StrToType("DH_1024_BIT_MODP")
	encrType := encr.StrToType("ENCR_AES_CBC_256")
	integType := integ.StrToType("AUTH_HMAC_MD5_96")
	prfType := prf.StrToType("PRF_HMAC_SHA1")

	proposal := new(message.Proposal)

	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, dh.ToTransform(dhType))
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, encr.ToTransform(encrType))
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, integ.ToTransform(integType))
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, prf.ToTransform(prfType))

	ikesa := new(IKESA)

	ikesa.SetProposal(proposal)

	if ikesa.dhInfo == nil ||
		ikesa.encrInfo == nil ||
		ikesa.integInfo == nil ||
		ikesa.prfInfo == nil {
		t.FailNow()
	}
}

func TestChildSelectProposal(t *testing.T) {
	// Types' pointers
	dhType1 := dh.StrToType("DH_1024_BIT_MODP")
	dhType2 := dh.StrToType("DH_2048_BIT_MODP")
	//encrKType1 := encr.StrToKType("ENCR_AES_CBC_128")
	//encrKType2 := encr.StrToKType("ENCR_AES_CBC_192")
	encrKType3 := encr.StrToKType("ENCR_AES_CBC_256")
	//integKType1 := integ.StrToKType("AUTH_HMAC_MD5_96")
	integKType2 := integ.StrToKType("AUTH_HMAC_SHA1_96")
	//prfType1 := prf.StrToType("PRF_HMAC_MD5")
	//prfType2 := prf.StrToType("PRF_HMAC_SHA1")
	//esnType1 := esn.StrToType("ESN_ENABLE")
	esnType2 := esn.StrToType("ESN_DISABLE")

	// Transforms
	t1 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_1024_BIT_MODP,
		AttributePresent: false,
	}
	t2 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_2048_BIT_MODP,
		AttributePresent: false,
	}
	t3 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_1536_BIT_MODP,
		AttributePresent: false,
	}
	t4 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   128,
	}
	t5 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   192,
	}
	t6 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   256,
	}
	t7 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   384,
	}
	t8 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_3DES,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   128,
	}
	t9 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_MD5_96,
		AttributePresent: false,
	}
	t10 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_SHA1_96,
		AttributePresent: false,
	}
	t11 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_DES_MAC,
		AttributePresent: false,
	}
	t12 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_MD5,
		AttributePresent: false,
	}
	t13 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_SHA1,
		AttributePresent: false,
	}
	t14 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_TIGER,
		AttributePresent: false,
	}
	t15 := &message.Transform{
		TransformType:    types.TypeExtendedSequenceNumbers,
		TransformID:      types.ESN_ENABLE,
		AttributePresent: false,
	}
	t16 := &message.Transform{
		TransformType:    types.TypeExtendedSequenceNumbers,
		TransformID:      types.ESN_DISABLE,
		AttributePresent: false,
	}

	// Proposal 1
	proposal := new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t3)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t7)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t8)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t9)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t13)

	childsa := new(ChildSA)
	if childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	// Proposal 2
	proposal = new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t1)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t2)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t4)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t5)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t6)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t10)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t11)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t15)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t16)

	childsa = new(ChildSA)
	if !childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	if childsa.dhInfo != dhType2 || childsa.encrKInfo != encrKType3 ||
		childsa.integKInfo != integKType2 || childsa.esnInfo != esnType2 {
		t.Fatal("SelectProposal selected a false result")
	}

	newPriority := map[string]uint32{
		"DH_1024_BIT_MODP": 1,
		"DH_2048_BIT_MODP": 0,
	}
	if err := dh.SetPriority(newPriority); err != nil {
		t.Fatalf("Set priority failed: %v", err)
	}

	childsa = new(ChildSA)
	if !childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	if childsa.dhInfo != dhType1 || childsa.encrKInfo != encrKType3 ||
		childsa.integKInfo != integKType2 || childsa.esnInfo != esnType2 {
		t.Fatal("SelectProposal selected a false result")
	}

	// reset priority
	newPriority = map[string]uint32{
		"DH_1024_BIT_MODP": 0,
		"DH_2048_BIT_MODP": 1,
	}
	if err := dh.SetPriority(newPriority); err != nil {
		t.Fatalf("Set priority failed: %v", err)
	}

	// Proposal 3
	proposal = new(message.Proposal)

	childsa = new(ChildSA)
	if childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	// Proposal 4
	proposal = new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t2)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t5)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t6)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t9)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t12)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t13)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t14)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t15)

	childsa = new(ChildSA)
	if childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	// Proposal 5
	proposal = new(message.Proposal)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t5)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t6)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t15)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t16)

	childsa = new(ChildSA)
	if !childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	if childsa.dhInfo != nil || childsa.encrKInfo != encrKType3 ||
		childsa.integKInfo != nil || childsa.esnInfo != esnType2 {
		t.Fatal("SelectProposal selected a false result")
	}
}

func TestChildToProposal(t *testing.T) {
	dhType := dh.StrToType("DH_1024_BIT_MODP")
	encrKType := encr.StrToKType("ENCR_AES_CBC_256")
	integKType := integ.StrToKType("AUTH_HMAC_MD5_96")
	esnType := esn.StrToType("ESN_ENABLE")

	childsa := ChildSA{
		dhInfo:     dhType,
		encrKInfo:  encrKType,
		integKInfo: integKType,
		esnInfo:    esnType,
	}

	proposal := childsa.ToProposal()

	if len(proposal.DiffieHellmanGroup) != 1 ||
		len(proposal.EncryptionAlgorithm) != 1 ||
		len(proposal.IntegrityAlgorithm) != 1 ||
		len(proposal.PseudorandomFunction) != 0 ||
		len(proposal.ExtendedSequenceNumbers) != 1 {
		t.FailNow()
	}
}

func TestChildSetProposal(t *testing.T) {
	dhType := dh.StrToType("DH_1024_BIT_MODP")
	encrKType := encr.StrToKType("ENCR_AES_CBC_256")
	integKType := integ.StrToKType("AUTH_HMAC_MD5_96")
	esnType := esn.StrToType("ESN_ENABLE")

	proposal := new(message.Proposal)

	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, dh.ToTransform(dhType))
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, encr.ToTransformChildSA(encrKType))
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, integ.ToTransformChildSA(integKType))
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, esn.ToTransform(esnType))

	childsa := new(ChildSA)

	childsa.SetProposal(proposal)

	if childsa.dhInfo == nil ||
		childsa.encrKInfo == nil ||
		childsa.integKInfo == nil ||
		childsa.esnInfo == nil {
		t.FailNow()
	}
}
