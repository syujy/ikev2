package security

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"strings"

	"github.com/syujy/ikev2/dh"
	"github.com/syujy/ikev2/encr"
	"github.com/syujy/ikev2/esn"
	"github.com/syujy/ikev2/integ"
	"github.com/syujy/ikev2/internal/lib"
	"github.com/syujy/ikev2/message"
	"github.com/syujy/ikev2/prf"
	"github.com/syujy/ikev2/types"

	"github.com/vishvananda/netlink"
)

// General data
var randomNumberMaximum big.Int
var randomNumberMinimum big.Int

func init() {
	// General data
	randomNumberMaximum.SetString(strings.Repeat("F", 512), 16)
	randomNumberMinimum.SetString(strings.Repeat("F", 32), 16)
}

func GenerateRandomNumber() (*big.Int, error) {
	var number *big.Int
	var err error
	for {
		number, err = rand.Int(rand.Reader, &randomNumberMaximum)
		if err != nil {
			return nil, fmt.Errorf("rand.Int() failed: %+v", err)
		} else {
			if number.Cmp(&randomNumberMinimum) == 1 {
				break
			}
		}
	}
	return number, nil
}

func GenerateRandomUint8() (uint8, error) {
	number := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, number)
	if err != nil {
		return 0, fmt.Errorf("Read random failed: %+v", err)
	}
	return uint8(number[0]), nil
}

func concatenateNonceAndSPI(nonce []byte, SPI_initiator uint64, SPI_responder uint64) []byte {
	spi := make([]byte, 8)

	binary.BigEndian.PutUint64(spi, SPI_initiator)
	newSlice := append(nonce, spi...)
	binary.BigEndian.PutUint64(spi, SPI_responder)
	newSlice = append(newSlice, spi...)

	return newSlice
}

type IKESA struct {
	// SPI
	RemoteSPI uint64
	LocalSPI  uint64

	// Role
	Role int

	// IKE SA transform types
	dhInfo    dh.DHType
	encrInfo  encr.ENCRType
	integInfo integ.INTEGType
	prfInfo   prf.PRFType

	// Security objects
	Prf_d   hash.Hash       // used to derive key for child sa
	Integ_i hash.Hash       // used by initiator for integrity checking
	Integ_r hash.Hash       // used by responder for integrity checking
	Encr_i  types.IKECrypto // used by initiator for encrypting
	Encr_r  types.IKECrypto // used by responder for encrypting
	Prf_i   hash.Hash       // used by initiator for IKE authentication
	Prf_r   hash.Hash       // used by responder for IKE authentication

	// NAT detection
	NATT bool

	// Message ID
	MessageID uint32
}

func (ikesa *IKESA) SelectProposal(proposal *message.Proposal) bool {
	for _, transform := range proposal.DiffieHellmanGroup {
		dhType := dh.DecodeTransform(transform)
		if dhType != nil {
			if ikesa.dhInfo == nil {
				ikesa.dhInfo = dhType
			} else {
				if dhType.Priority() > ikesa.dhInfo.Priority() {
					ikesa.dhInfo = dhType
				}
			}
		}
	}
	if ikesa.dhInfo == nil {
		return false // mandatory
	}
	for _, transform := range proposal.EncryptionAlgorithm {
		encrType := encr.DecodeTransform(transform)
		if encrType != nil {
			if ikesa.encrInfo == nil {
				ikesa.encrInfo = encrType
			} else {
				if encrType.Priority() > ikesa.encrInfo.Priority() {
					ikesa.encrInfo = encrType
				}
			}
		}
	}
	if ikesa.encrInfo == nil {
		return false // mandatory
	}
	for _, transform := range proposal.IntegrityAlgorithm {
		integType := integ.DecodeTransform(transform)
		if integType != nil {
			if ikesa.integInfo == nil {
				ikesa.integInfo = integType
			} else {
				if integType.Priority() > ikesa.integInfo.Priority() {
					ikesa.integInfo = integType
				}
			}
		}
	}
	if ikesa.integInfo == nil {
		return false // mandatory
	}
	for _, transform := range proposal.PseudorandomFunction {
		prfType := prf.DecodeTransform(transform)
		if prfType != nil {
			if ikesa.prfInfo == nil {
				ikesa.prfInfo = prfType
			} else {
				if prfType.Priority() > ikesa.prfInfo.Priority() {
					ikesa.prfInfo = prfType
				}
			}
		}
	}
	if ikesa.prfInfo == nil {
		return false // mandatory
	}
	if len(proposal.ExtendedSequenceNumbers) > 0 {
		return false // No ESN
	}
	return true
}

func (ikesa *IKESA) ToProposal() *message.Proposal {
	p := new(message.Proposal)
	p.ProtocolID = types.TypeIKE
	p.DiffieHellmanGroup = append(p.DiffieHellmanGroup, dh.ToTransform(ikesa.dhInfo))
	p.PseudorandomFunction = append(p.PseudorandomFunction, prf.ToTransform(ikesa.prfInfo))
	p.EncryptionAlgorithm = append(p.EncryptionAlgorithm, encr.ToTransform(ikesa.encrInfo))
	p.IntegrityAlgorithm = append(p.IntegrityAlgorithm, integ.ToTransform(ikesa.integInfo))
	return p
}

func (ikesa *IKESA) SetProposal(proposal *message.Proposal) bool {
	if ikesa.dhInfo = dh.DecodeTransform(proposal.DiffieHellmanGroup[0]); ikesa.dhInfo == nil {
		return false
	}
	if ikesa.encrInfo = encr.DecodeTransform(proposal.EncryptionAlgorithm[0]); ikesa.encrInfo == nil {
		return false
	}
	if ikesa.integInfo = integ.DecodeTransform(proposal.IntegrityAlgorithm[0]); ikesa.encrInfo == nil {
		return false
	}
	if ikesa.prfInfo = prf.DecodeTransform(proposal.PseudorandomFunction[0]); ikesa.prfInfo == nil {
		return false
	}
	return true
}

func (ikesa *IKESA) GetDHTransformID() uint16 {
	if ikesa.dhInfo == nil {
		return 0
	} else {
		return ikesa.dhInfo.TransformID()
	}
}

// CalcKEMaterial generates secret and calculate Diffie-Hellman public key
// exchange material.
// Peer public value as parameter, return local public value and shared key.
func (ikesa *IKESA) CalcKEMaterial(peerPublicValue []byte) ([]byte, []byte, error) {
	secret, err := GenerateRandomNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateRandomNumber() failed: %+v", err)
	}
	peerPublicValueBig := new(big.Int).SetBytes(peerPublicValue)
	return ikesa.dhInfo.GetPublicValue(secret), ikesa.dhInfo.GetSharedKey(secret, peerPublicValueBig), nil
}

func (ikesa *IKESA) GenerateKey(concatenatedNonce, dhSharedKey, concatenatedSPI []byte) error {
	// Check parameters
	if ikesa == nil {
		return errors.New("IKE SA is nil")
	}

	// Check if the context contain needed data
	if ikesa.encrInfo == nil {
		return errors.New("No encryption algorithm specified")
	}
	if ikesa.integInfo == nil {
		return errors.New("No integrity algorithm specified")
	}
	if ikesa.prfInfo == nil {
		return errors.New("No pseudorandom function specified")
	}
	if ikesa.dhInfo == nil {
		return errors.New("No Diffie-hellman group algorithm specified")
	}

	if len(concatenatedNonce) == 0 {
		return errors.New("No concatenated nonce data")
	}
	if len(dhSharedKey) == 0 {
		return errors.New("No Diffie-Hellman shared key")
	}

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int

	length_SK_d = ikesa.prfInfo.GetKeyLength()
	length_SK_ai = ikesa.integInfo.GetKeyLength()
	length_SK_ar = length_SK_ai
	length_SK_ei = ikesa.encrInfo.GetKeyLength()
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d

	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	prf := ikesa.prfInfo.Init(concatenatedNonce)
	_, _ = prf.Write(dhSharedKey) // hash.Hash.Write() never return an error

	skeyseed := prf.Sum(nil)
	seed := append(concatenatedNonce, concatenatedSPI...)

	keyStream := lib.PrfPlus(ikesa.prfInfo.Init(skeyseed), seed, totalKeyLength)

	// Assign keys into context
	sk_d := keyStream[:length_SK_d]
	keyStream = keyStream[length_SK_d:]
	sk_ai := keyStream[:length_SK_ai]
	keyStream = keyStream[length_SK_ai:]
	sk_ar := keyStream[:length_SK_ar]
	keyStream = keyStream[length_SK_ar:]
	sk_ei := keyStream[:length_SK_ei]
	keyStream = keyStream[length_SK_ei:]
	sk_er := keyStream[:length_SK_er]
	keyStream = keyStream[length_SK_er:]
	sk_pi := keyStream[:length_SK_pi]
	keyStream = keyStream[length_SK_pi:]
	sk_pr := keyStream[:length_SK_pr]

	// Set security objects
	encri, err := ikesa.encrInfo.Init(sk_ei)
	if err != nil {
		return err
	}
	encrr, err := ikesa.encrInfo.Init(sk_er)
	if err != nil {
		return err
	}
	ikesa.Prf_d = ikesa.prfInfo.Init(sk_d)
	ikesa.Integ_i = ikesa.integInfo.Init(sk_ai)
	ikesa.Integ_r = ikesa.integInfo.Init(sk_ar)
	ikesa.Encr_i = encri
	ikesa.Encr_r = encrr
	ikesa.Prf_i = ikesa.prfInfo.Init(sk_pi)
	ikesa.Prf_r = ikesa.prfInfo.Init(sk_pr)

	return nil
}

func (ikesa *IKESA) VerifyIKEChecksum(data []byte) bool {
	checksumLen := ikesa.integInfo.GetOutputLength()
	if len(data) <= checksumLen {
		return false
	}

	checkedData := data[:len(data)-checksumLen]
	checksum := data[len(data)-checksumLen:]

	// Calculate
	var calculatedChecksum []byte
	if ikesa.Role == types.Role_Initiator {
		ikesa.Integ_r.Reset()
		_, _ = ikesa.Integ_r.Write(checkedData) // hash.Hash.Write() never return an error
		calculatedChecksum = ikesa.Integ_r.Sum(nil)
	} else {
		ikesa.Integ_i.Reset()
		_, _ = ikesa.Integ_i.Write(checkedData) // hash.Hash.Write() never return an error
		calculatedChecksum = ikesa.Integ_i.Sum(nil)
	}

	return hmac.Equal(checksum, calculatedChecksum)
}

func (ikesa *IKESA) CalcIKEChecksum(data []byte) error {
	checksumLen := ikesa.integInfo.GetOutputLength()
	if len(data) <= checksumLen {
		return errors.New("Input data too short")
	}

	checkedData := data[:len(data)-checksumLen]
	checksum := data[len(data)-checksumLen:]

	// Calculate
	var calculatedChecksum []byte
	if ikesa.Role == types.Role_Initiator {
		ikesa.Integ_i.Reset()
		_, _ = ikesa.Integ_i.Write(checkedData) // hash.Hash.Write() never return an error
		calculatedChecksum = ikesa.Integ_i.Sum(nil)
	} else {
		ikesa.Integ_r.Reset()
		_, _ = ikesa.Integ_r.Write(checkedData) // hash.Hash.Write() never return an error
		calculatedChecksum = ikesa.Integ_r.Sum(nil)
	}

	copy(checksum, calculatedChecksum)

	return nil
}

func (ikesa *IKESA) EncryptToSKPayload(data []byte) ([]byte, error) {
	// Encrypt
	var cipherText []byte
	if ikesa.Role == types.Role_Initiator {
		var err error
		if cipherText, err = ikesa.Encr_i.Encrypt(data); err != nil {
			return nil, fmt.Errorf("Encrypt() failed: %+v", err)
		}
	} else {
		var err error
		if cipherText, err = ikesa.Encr_r.Encrypt(data); err != nil {
			return nil, fmt.Errorf("Encrypt() failed: %+v", err)
		}
	}

	// Append checksum field
	checksumField := make([]byte, ikesa.integInfo.GetOutputLength())
	cipherText = append(cipherText, checksumField...)

	return cipherText, nil
}

func (ikesa *IKESA) DecryptSKPayload(data []byte) ([]byte, error) {
	// Delete checksum field
	checksumLen := ikesa.integInfo.GetOutputLength()
	data = data[:len(data)-checksumLen]

	// Decrypt
	var plainText []byte
	if ikesa.Role == types.Role_Initiator {
		var err error
		if plainText, err = ikesa.Encr_r.Decrypt(data); err != nil {
			return nil, fmt.Errorf("Decrypt() failed: %+v", err)
		}
	} else {
		var err error
		if plainText, err = ikesa.Encr_i.Decrypt(data); err != nil {
			return nil, fmt.Errorf("Decrypt() failed: %+v", err)
		}
	}

	return plainText, nil
}

func (ikesa *IKESA) CheckMessageID(mID uint32) bool {
	if ikesa.MessageID == mID {
		ikesa.MessageID++
		return true
	} else {
		return false
	}
}

func (ikesa *IKESA) GetAuth(kn3iwf []byte, signedOctets []byte) []byte {
	authPRF1 := ikesa.prfInfo.Init(kn3iwf)
	_, _ = authPRF1.Write([]byte("Key Pad for IKEv2")) // hash.Hash.Write() never return an error
	authPRF2 := ikesa.prfInfo.Init(authPRF1.Sum(nil))
	_, _ = authPRF2.Write(signedOctets) // hash.Hash.Write() never return an error
	return authPRF2.Sum(nil)
}

type ChildSA struct {
	// SPI
	SPI      uint32
	allocspi bool

	// Mark
	Mark *uint32

	// IP addresses
	RemotePublicIPAddr net.IP
	LocalPublicIPAddr  net.IP

	// Traffic
	IPProto  uint8
	TSLocal  *net.IPNet
	TSRemote *net.IPNet

	// Encapsulate
	EnableEncap bool
	LocalPort   int
	RemotePort  int

	// Child SA transform types
	dhInfo     dh.DHType
	encrKInfo  encr.ENCRKType
	integKInfo integ.INTEGKType
	esnInfo    esn.ESNType

	// Keys
	initiatorToResponderEncrKey  []byte
	responderToInitiatorEncrKey  []byte
	initiatorToResponderIntegKey []byte
	responderToInitiatorIntegKey []byte

	// XFRM contexts
	initiatorToResponderPolicy *netlink.XfrmPolicy
	initiatorToResponderState  *netlink.XfrmState
	responderToInitiatorPolicy *netlink.XfrmPolicy
	responderToInitiatorState  *netlink.XfrmState
}

func (childsa *ChildSA) SelectProposal(proposal *message.Proposal) bool {
	// Check if ESP
	if proposal.ProtocolID != types.TypeESP {
		return false
	}
	// DH is optional
	for _, transform := range proposal.DiffieHellmanGroup {
		dhType := dh.DecodeTransform(transform)
		if dhType != nil {
			if childsa.dhInfo == nil {
				childsa.dhInfo = dhType
			} else {
				if dhType.Priority() > childsa.dhInfo.Priority() {
					childsa.dhInfo = dhType
				}
			}
		}
	}
	for _, transform := range proposal.EncryptionAlgorithm {
		encrKType := encr.DecodeTransformChildSA(transform)
		if encrKType != nil {
			if childsa.encrKInfo == nil {
				childsa.encrKInfo = encrKType
			} else {
				if encrKType.Priority() > childsa.encrKInfo.Priority() {
					childsa.encrKInfo = encrKType
				}
			}
		}
	}
	if childsa.encrKInfo == nil {
		return false // mandatory
	}
	// Integ is optional
	for _, transform := range proposal.IntegrityAlgorithm {
		integKType := integ.DecodeTransformChildSA(transform)
		if integKType != nil {
			if childsa.integKInfo == nil {
				childsa.integKInfo = integKType
			} else {
				if integKType.Priority() > childsa.integKInfo.Priority() {
					childsa.integKInfo = integKType
				}
			}
		}
	}
	for _, transform := range proposal.ExtendedSequenceNumbers {
		esnType := esn.DecodeTransform(transform)
		if esnType != nil {
			if childsa.esnInfo == nil {
				childsa.esnInfo = esnType
			} else {
				if esnType.Priority() > childsa.esnInfo.Priority() {
					childsa.esnInfo = esnType
				}
			}
		}
	}
	if childsa.esnInfo == nil {
		return false // mandatory
	}
	if len(proposal.PseudorandomFunction) > 0 {
		return false // No PRF
	}
	return true
}

func (childsa *ChildSA) ToProposal() *message.Proposal {
	p := new(message.Proposal)
	p.ProtocolID = types.TypeESP
	spi := make([]byte, 4)
	binary.BigEndian.PutUint32(spi, childsa.SPI)
	p.SPI = spi
	if childsa.dhInfo != nil {
		p.DiffieHellmanGroup = append(p.DiffieHellmanGroup, dh.ToTransform(childsa.dhInfo))
	}
	p.EncryptionAlgorithm = append(p.EncryptionAlgorithm, encr.ToTransformChildSA(childsa.encrKInfo))
	if childsa.integKInfo != nil {
		p.IntegrityAlgorithm = append(p.IntegrityAlgorithm, integ.ToTransformChildSA(childsa.integKInfo))
	}
	p.ExtendedSequenceNumbers = append(p.ExtendedSequenceNumbers, esn.ToTransform(childsa.esnInfo))
	return p
}

func (childsa *ChildSA) SetProposal(proposal *message.Proposal) bool {
	if len(proposal.DiffieHellmanGroup) == 1 {
		if childsa.dhInfo = dh.DecodeTransform(proposal.DiffieHellmanGroup[0]); childsa.dhInfo == nil {
			return false
		}
	}
	if childsa.encrKInfo = encr.DecodeTransformChildSA(proposal.EncryptionAlgorithm[0]); childsa.encrKInfo == nil {
		return false
	}
	if len(proposal.IntegrityAlgorithm) == 1 {
		if childsa.integKInfo = integ.DecodeTransformChildSA(proposal.IntegrityAlgorithm[0]); childsa.encrKInfo == nil {
			return false
		}
	}
	if childsa.esnInfo = esn.DecodeTransform(proposal.ExtendedSequenceNumbers[0]); childsa.esnInfo == nil {
		return false
	}
	return true
}

func (childsa *ChildSA) GetDHTransformID() uint16 {
	if childsa.dhInfo == nil {
		return 0
	} else {
		return childsa.dhInfo.TransformID()
	}
}

// CalcKEMaterial generates secret and calculate Diffie-Hellman public key
// exchange material.
// Peer public value as parameter, return local public value and shared key.
func (childsa *ChildSA) CalcKEMaterial(peerPublicValue []byte) ([]byte, []byte, error) {
	secret, err := GenerateRandomNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateRandomNumber() failed: %+v", err)
	}
	peerPublicValueBig := new(big.Int).SetBytes(peerPublicValue)
	return childsa.dhInfo.GetPublicValue(secret), childsa.dhInfo.GetSharedKey(secret, peerPublicValueBig), nil
}

// Key Gen for child SA
func (childsa *ChildSA) GenerateKey(prf hash.Hash, dhSharedKey, concatenatedNonce []byte) error {
	// Check parameters
	if childsa == nil {
		return errors.New("Child SA is nil")
	}

	// Check if the context contain needed data
	if prf == nil {
		return errors.New("No pseudorandom function specified")
	}
	if childsa.encrKInfo == nil {
		return errors.New("No encryption algorithm specified")
	}
	if childsa.esnInfo == nil {
		return errors.New("No ESN present specified")
	}

	// Get key length for encryption and integrity key for IPSec
	var lengthEncrKeyIPSec, lengthIntegKeyIPSec, totalKeyLength int

	lengthEncrKeyIPSec = childsa.encrKInfo.GetKeyLength()
	if childsa.integKInfo != nil {
		lengthIntegKeyIPSec = childsa.integKInfo.GetKeyLength()
	}
	totalKeyLength = (lengthEncrKeyIPSec + lengthIntegKeyIPSec) * 2

	// Generate key for child security association as specified in RFC 7296 section 2.17
	var seed []byte
	if childsa.dhInfo != nil && dhSharedKey != nil {
		seed = append(dhSharedKey, concatenatedNonce...)
	} else {
		seed = concatenatedNonce
	}

	keyStream := lib.PrfPlus(prf, seed, totalKeyLength)

	childsa.initiatorToResponderEncrKey =
		append(childsa.initiatorToResponderEncrKey, keyStream[:lengthEncrKeyIPSec]...)
	keyStream = keyStream[lengthEncrKeyIPSec:]
	if childsa.integKInfo != nil {
		childsa.initiatorToResponderIntegKey =
			append(childsa.initiatorToResponderIntegKey, keyStream[:lengthIntegKeyIPSec]...)
		keyStream = keyStream[lengthIntegKeyIPSec:]
	}
	childsa.responderToInitiatorEncrKey =
		append(childsa.responderToInitiatorEncrKey, keyStream[:lengthEncrKeyIPSec]...)
	keyStream = keyStream[lengthEncrKeyIPSec:]
	if childsa.integKInfo != nil {
		childsa.responderToInitiatorIntegKey =
			append(childsa.responderToInitiatorIntegKey, keyStream[:lengthIntegKeyIPSec]...)
	}

	return nil

}

func (childsa *ChildSA) GenerateXFRMState(role int, allocspi bool) error {
	// Initiator to responder state
	s := new(netlink.XfrmState)
	if role == types.Role_Initiator {
		s.Src = childsa.LocalPublicIPAddr
		s.Dst = childsa.RemotePublicIPAddr
	} else {
		s.Src = childsa.RemotePublicIPAddr
		s.Dst = childsa.LocalPublicIPAddr
	}
	s.Proto = netlink.XFRM_PROTO_ESP
	s.Mode = netlink.XFRM_MODE_TUNNEL
	if childsa.Mark != nil {
		s.Mark = &netlink.XfrmMark{
			Value: uint32(*childsa.Mark),
		}
	}

	if allocspi {
		if s_spi, err := netlink.XfrmStateAllocSpi(s); err != nil {
			return err
		} else {
			s = s_spi
			s.Limits.TimeHard = 0
			childsa.SPI = uint32(s_spi.Spi)
			childsa.allocspi = true
		}
	} else {
		s.Spi = int(childsa.SPI)
		childsa.allocspi = false
	}

	childsa.initiatorToResponderState = s

	// Responder to initiator state
	s = new(netlink.XfrmState)
	*s = *childsa.initiatorToResponderState
	s.Src, s.Dst = s.Dst, s.Src

	childsa.responderToInitiatorState = s

	return nil
}

func (childsa *ChildSA) GenerateXFRMPolicy(role int) error {
	// Initiator to responder policy
	s := childsa.initiatorToResponderState
	if s == nil {
		return errors.New("initiator to responder state is nil")
	}
	p := new(netlink.XfrmPolicy)
	if role == types.Role_Initiator {
		p.Src = childsa.TSLocal
		p.Dst = childsa.TSRemote
		p.Dir = netlink.XFRM_DIR_OUT
	} else {
		p.Src = childsa.TSRemote
		p.Dst = childsa.TSLocal
		p.Dir = netlink.XFRM_DIR_IN
	}
	p.Proto = netlink.Proto(childsa.IPProto)
	if childsa.Mark != nil {
		p.Mark = &netlink.XfrmMark{
			Value: uint32(*childsa.Mark),
		}
	}

	p.Tmpls = []netlink.XfrmPolicyTmpl{
		{
			Src:   s.Src,
			Dst:   s.Dst,
			Proto: s.Proto,
			Mode:  s.Mode,
			Spi:   s.Spi,
		},
	}

	childsa.initiatorToResponderPolicy = p

	// Responder to initiator policy
	s = childsa.responderToInitiatorState
	if s == nil {
		return errors.New("responder to initiator state is nil")
	}
	p = new(netlink.XfrmPolicy)
	*p = *childsa.initiatorToResponderPolicy
	p.Src, p.Dst = p.Dst, p.Src
	p.Dir ^= 1
	p.Tmpls = []netlink.XfrmPolicyTmpl{
		{
			Src:   s.Src,
			Dst:   s.Dst,
			Proto: s.Proto,
			Mode:  s.Mode,
			Spi:   s.Spi,
		},
	}

	childsa.responderToInitiatorPolicy = p

	return nil
}

func (childsa *ChildSA) SetXFRMState(role int) error {
	// Initiator to responder state
	s := childsa.initiatorToResponderState
	if s == nil {
		return errors.New("initiator to responder state is nil")
	}
	if childsa.integKInfo != nil {
		s.Auth = &netlink.XfrmStateAlgo{
			Name: childsa.integKInfo.XFRMString(),
			Key:  childsa.initiatorToResponderIntegKey,
		}
	}
	s.Crypt = &netlink.XfrmStateAlgo{
		Name: childsa.encrKInfo.XFRMString(),
		Key:  childsa.initiatorToResponderEncrKey,
	}
	s.ESN = childsa.esnInfo.Init()
	if childsa.EnableEncap {
		if role == types.Role_Initiator {
			s.Encap = &netlink.XfrmStateEncap{
				Type:    netlink.XFRM_ENCAP_ESPINUDP,
				SrcPort: childsa.LocalPort,
				DstPort: childsa.RemotePort,
			}
		} else {
			s.Encap = &netlink.XfrmStateEncap{
				Type:    netlink.XFRM_ENCAP_ESPINUDP,
				SrcPort: childsa.RemotePort,
				DstPort: childsa.LocalPort,
			}
		}
	}

	// Responder to initiator state
	s = childsa.responderToInitiatorState
	if s == nil {
		return errors.New("responder to initiator state is nil")
	}
	if childsa.integKInfo != nil {
		s.Auth = &netlink.XfrmStateAlgo{
			Name: childsa.integKInfo.XFRMString(),
			Key:  childsa.responderToInitiatorIntegKey,
		}
	}
	s.Crypt = &netlink.XfrmStateAlgo{
		Name: childsa.encrKInfo.XFRMString(),
		Key:  childsa.responderToInitiatorEncrKey,
	}
	s.ESN = childsa.esnInfo.Init()
	if childsa.EnableEncap {
		if role == types.Role_Initiator {
			s.Encap = &netlink.XfrmStateEncap{
				Type:    netlink.XFRM_ENCAP_ESPINUDP,
				SrcPort: childsa.RemotePort,
				DstPort: childsa.LocalPort,
			}
		} else {
			s.Encap = &netlink.XfrmStateEncap{
				Type:    netlink.XFRM_ENCAP_ESPINUDP,
				SrcPort: childsa.LocalPort,
				DstPort: childsa.RemotePort,
			}
		}
	}

	return nil
}

func (childsa *ChildSA) XFRMRuleAdd() error {
	if childsa.allocspi {
		if err := netlink.XfrmStateUpdate(childsa.initiatorToResponderState); err != nil {
			return fmt.Errorf("netlink.XfrmStateUpdate() initiator to responder failed: %+v", err)
		}
	} else {
		if err := netlink.XfrmStateAdd(childsa.initiatorToResponderState); err != nil {
			return fmt.Errorf("netlink.XfrmStateAdd() initiator to responder failed: %+v", err)
		}
	}
	if err := netlink.XfrmPolicyAdd(childsa.initiatorToResponderPolicy); err != nil {
		return fmt.Errorf("netlink.XfrmPolicyAdd() initiator to responder failed: %+v", err)
	}
	if err := netlink.XfrmStateAdd(childsa.responderToInitiatorState); err != nil {
		return fmt.Errorf("netlink.XfrmStateAdd() responder to initiator failed: %+v", err)
	}
	if err := netlink.XfrmPolicyAdd(childsa.responderToInitiatorPolicy); err != nil {
		return fmt.Errorf("netlink.XfrmPolicyAdd() responder to initiator failed: %+v", err)
	}
	return nil
}

func (childsa *ChildSA) XFRMRuleFlush() error {
	if err := netlink.XfrmStateDel(childsa.initiatorToResponderState); err != nil {
		return fmt.Errorf("netlink.XfrmStateDel() initiator to responder failed: %+v", err)
	}
	if err := netlink.XfrmPolicyDel(childsa.initiatorToResponderPolicy); err != nil {
		return fmt.Errorf("netlink.XfrmPolicyDel() initiator to responder failed: %+v", err)
	}
	if err := netlink.XfrmStateDel(childsa.responderToInitiatorState); err != nil {
		return fmt.Errorf("netlink.XfrmStateDel() responder to initiator failed: %+v", err)
	}
	if err := netlink.XfrmPolicyDel(childsa.responderToInitiatorPolicy); err != nil {
		return fmt.Errorf("netlink.XfrmPolicyDel() responder to initiator failed: %+v", err)
	}
	return nil
}

/* Archive for future use
// Certificate
func CompareRootCertificate(certificateEncoding uint8, requestedCertificateAuthorityHash []byte) bool {
	if certificateEncoding != types.X509CertificateSignature {
		secLog.Debugf("Not support certificate type: %d. Reject.", certificateEncoding)
		return false
	}

	n3iwfSelf := context.N3IWFSelf()

	if len(n3iwfSelf.CertificateAuthority) == 0 {
		secLog.Error("Certificate authority in context is empty")
		return false
	}

	return bytes.Equal(n3iwfSelf.CertificateAuthority, requestedCertificateAuthorityHash)
}
*/

/*
func VerifyIKEChecksum(key []byte, originData []byte, checksum []byte, algorithmType uint16) (bool, error) {
	switch algorithmType {
	case message.AUTH_HMAC_MD5_96:
		if len(key) != 16 {
			return false, errors.New("Unmatched input key length")
		}
		integrityFunction := hmac.New(md5.New, key)
		if _, err := integrityFunction.Write(originData); err != nil {
			secLog.Errorf("Hash function write error when verifying IKE checksum: %+v", err)
			return false, errors.New("Hash function write error")
		}
		checksumOfMessage := integrityFunction.Sum(nil)

		secLog.Tracef("Calculated checksum:\n%s\nReceived checksum:\n%s",
			hex.Dump(checksumOfMessage), hex.Dump(checksum))

		return hmac.Equal(checksumOfMessage, checksum), nil
	case message.AUTH_HMAC_SHA1_96:
		if len(key) != 20 {
			return false, errors.New("Unmatched input key length")
		}
		integrityFunction := hmac.New(sha1.New, key)
		if _, err := integrityFunction.Write(originData); err != nil {
			secLog.Errorf("Hash function write error when verifying IKE checksum: %+v", err)
			return false, errors.New("Hash function write error")
		}
		checksumOfMessage := integrityFunction.Sum(nil)[:12]

		secLog.Tracef("Calculated checksum:\n%s\nReceived checksum:\n%s",
			hex.Dump(checksumOfMessage), hex.Dump(checksum))

		return hmac.Equal(checksumOfMessage, checksum), nil
	default:
		secLog.Errorf("Unsupported integrity function: %d", algorithmType)
		return false, errors.New("Unsupported algorithm")
	}
}

// Decrypt
func DecryptProcedure(ikeSecurityAssociation *context.IKESecurityAssociation, ikeMessage *message.IKEMessage,
	encryptedPayload *message.Encrypted) (message.IKEPayloadContainer, error) {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return nil, errors.New("IKE SA is nil")
	}
	if ikeMessage == nil {
		return nil, errors.New("IKE message is nil")
	}
	if encryptedPayload == nil {
		return nil, errors.New("IKE encrypted payload is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.IntegrityAlgorithm == nil {
		return nil, errors.New("No integrity algorithm specified")
	}
	if ikeSecurityAssociation.EncryptionAlgorithm == nil {
		return nil, errors.New("No encryption algorithm specified")
	}

	if len(ikeSecurityAssociation.SK_ai) == 0 {
		return nil, errors.New("No initiator's integrity key")
	}
	if len(ikeSecurityAssociation.SK_ei) == 0 {
		return nil, errors.New("No initiator's encryption key")
	}

	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	checksumLength, ok := getOutputLength(transformIntegrityAlgorithm.TransformType,
		transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent,
		transformIntegrityAlgorithm.AttributeValue)
	if !ok {
		secLog.Error("Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return nil, errors.New("Get key length failed")
	}

	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-checksumLength:]

	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		secLog.Errorln(err)
		secLog.Error("Error occur when encoding for checksum")
		return nil, errors.New("Encoding IKE message failed")
	}

	ok, err = VerifyIKEChecksum(ikeSecurityAssociation.SK_ai,
		ikeMessageData[:len(ikeMessageData)-checksumLength], checksum,
		transformIntegrityAlgorithm.TransformID)
	if err != nil {
		secLog.Errorf("Error occur when verifying checksum: %+v", err)
		return nil, errors.New("Error verify checksum")
	}
	if !ok {
		secLog.Warn("Message checksum failed. Drop the message.")
		return nil, errors.New("Checksum failed, drop.")
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-checksumLength]
	plainText, err := DecryptMessage(ikeSecurityAssociation.SK_ei, encryptedData,
		transformEncryptionAlgorithm.TransformID)
	if err != nil {
		secLog.Errorf("Error occur when decrypting message: %+v", err)
		return nil, errors.New("Error decrypting message")
	}

	var decryptedIKEPayload message.IKEPayloadContainer
	err = decryptedIKEPayload.Decode(encryptedPayload.NextPayload, plainText)
	if err != nil {
		secLog.Errorln(err)
		return nil, errors.New("Decoding decrypted payload failed")
	}

	return decryptedIKEPayload, nil

}

// Encrypt
func EncryptProcedure(ikeSecurityAssociation *context.IKESecurityAssociation,
	ikePayload message.IKEPayloadContainer, responseIKEMessage *message.IKEMessage) error {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return errors.New("IKE SA is nil")
	}
	if len(ikePayload) == 0 {
		return errors.New("No IKE payload to be encrypted")
	}
	if responseIKEMessage == nil {
		return errors.New("Response IKE message is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.IntegrityAlgorithm == nil {
		return errors.New("No integrity algorithm specified")
	}
	if ikeSecurityAssociation.EncryptionAlgorithm == nil {
		return errors.New("No encryption algorithm specified")
	}

	if len(ikeSecurityAssociation.SK_ar) == 0 {
		return errors.New("No responder's integrity key")
	}
	if len(ikeSecurityAssociation.SK_er) == 0 {
		return errors.New("No responder's encryption key")
	}

	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	checksumLength, ok := getOutputLength(transformIntegrityAlgorithm.TransformType,
		transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent,
		transformIntegrityAlgorithm.AttributeValue)
	if !ok {
		secLog.Error("Get key length of an unsupported algorithm. This may imply an unsupported tranform is chosen.")
		return errors.New("Get key length failed")
	}

	// Encrypting
	ikePayloadData, err := ikePayload.Encode()
	if err != nil {
		secLog.Error(err)
		return errors.New("Encoding IKE payload failed.")
	}

	encryptedData, err := EncryptMessage(ikeSecurityAssociation.SK_er, ikePayloadData,
		transformEncryptionAlgorithm.TransformID)
	if err != nil {
		secLog.Errorf("Encrypting data error: %+v", err)
		return errors.New("Error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, checksumLength)...)
	sk := responseIKEMessage.Payloads.BuildEncrypted(ikePayload[0].Type(), encryptedData)

	// Calculate checksum
	responseIKEMessageData, err := responseIKEMessage.Encode()
	if err != nil {
		secLog.Error(err)
		return errors.New("Encoding IKE message error")
	}
	checksumOfMessage, err := CalculateChecksum(ikeSecurityAssociation.SK_ar,
		responseIKEMessageData[:len(responseIKEMessageData)-checksumLength],
		transformIntegrityAlgorithm.TransformID)
	if err != nil {
		secLog.Errorf("Calculating checksum failed: %+v", err)
		return errors.New("Error calculating checksum")
	}
	checksumField := sk.EncryptedData[len(sk.EncryptedData)-checksumLength:]
	copy(checksumField, checksumOfMessage)

	return nil

}

// Get information of algorithm
func getKeyLength(transformType uint8, transformID uint16, attributePresent bool,
	attributeValue uint16) (int, bool) {
	switch transformType {
	case message.TypeEncryptionAlgorithm:
		switch transformID {
		case message.ENCR_DES_IV64:
			return 0, false
		case message.ENCR_DES:
			return 8, true
		case message.ENCR_3DES:
			return 24, true
		case message.ENCR_RC5:
			return 0, false
		case message.ENCR_IDEA:
			return 0, false
		case message.ENCR_CAST:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 16, true
				case 256:
					return 0, false
				default:
					return 0, false
				}
			}
			return 0, false
		case message.ENCR_BLOWFISH: // Blowfish support variable key length
			if attributePresent {
				if attributeValue < 40 {
					return 0, false
				} else if attributeValue > 448 {
					return 0, false
				} else {
					return int(attributeValue / 8), true
				}
			} else {
				return 0, false
			}
		case message.ENCR_3IDEA:
			return 0, false
		case message.ENCR_DES_IV32:
			return 0, false
		case message.ENCR_NULL:
			return 0, true
		case message.ENCR_AES_CBC:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 16, true
				case 192:
					return 24, true
				case 256:
					return 32, true
				default:
					return 0, false
				}
			} else {
				return 0, false
			}
		case message.ENCR_AES_CTR:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 20, true
				case 192:
					return 28, true
				case 256:
					return 36, true
				default:
					return 0, false
				}
			} else {
				return 0, false
			}
		default:
			return 0, false
		}
	case message.TypePseudorandomFunction:
		switch transformID {
		case message.PRF_HMAC_MD5:
			return 16, true
		case message.PRF_HMAC_SHA1:
			return 20, true
		case message.PRF_HMAC_TIGER:
			return 0, false
		default:
			return 0, false
		}
	case message.TypeIntegrityAlgorithm:
		switch transformID {
		case message.AUTH_NONE:
			return 0, false
		case message.AUTH_HMAC_MD5_96:
			return 16, true
		case message.AUTH_HMAC_SHA1_96:
			return 20, true
		case message.AUTH_DES_MAC:
			return 0, false
		case message.AUTH_KPDK_MD5:
			return 0, false
		case message.AUTH_AES_XCBC_96:
			return 0, false
		default:
			return 0, false
		}
	case message.TypeDiffieHellmanGroup:
		switch transformID {
		case message.DH_NONE:
			return 0, false
		case message.DH_768_BIT_MODP:
			return 0, false
		case message.DH_1024_BIT_MODP:
			return 0, false
		case message.DH_1536_BIT_MODP:
			return 0, false
		case message.DH_2048_BIT_MODP:
			return 0, false
		case message.DH_3072_BIT_MODP:
			return 0, false
		case message.DH_4096_BIT_MODP:
			return 0, false
		case message.DH_6144_BIT_MODP:
			return 0, false
		case message.DH_8192_BIT_MODP:
			return 0, false
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

func getOutputLength(transformType uint8, transformID uint16, attributePresent bool,
	attributeValue uint16) (int, bool) {
	switch transformType {
	case message.TypePseudorandomFunction:
		switch transformID {
		case message.PRF_HMAC_MD5:
			return 16, true
		case message.PRF_HMAC_SHA1:
			return 20, true
		case message.PRF_HMAC_TIGER:
			return 0, false
		default:
			return 0, false
		}
	case message.TypeIntegrityAlgorithm:
		switch transformID {
		case message.AUTH_NONE:
			return 0, false
		case message.AUTH_HMAC_MD5_96:
			return 12, true
		case message.AUTH_HMAC_SHA1_96:
			return 12, true
		case message.AUTH_DES_MAC:
			return 0, false
		case message.AUTH_KPDK_MD5:
			return 0, false
		case message.AUTH_AES_XCBC_96:
			return 0, false
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}
*/
