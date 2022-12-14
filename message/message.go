package message

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/syujy/ikev2/types"
)

type IKEMessage struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	Version      uint8
	ExchangeType uint8
	Flags        uint8
	MessageID    uint32
	Payloads     IKEPayloadContainer
}

func (ikeMessage *IKEMessage) Encode() ([]byte, error) {
	ikeMessageData := make([]byte, 28)

	binary.BigEndian.PutUint64(ikeMessageData[0:8], ikeMessage.InitiatorSPI)
	binary.BigEndian.PutUint64(ikeMessageData[8:16], ikeMessage.ResponderSPI)
	ikeMessageData[17] = ikeMessage.Version
	ikeMessageData[18] = ikeMessage.ExchangeType
	ikeMessageData[19] = ikeMessage.Flags
	binary.BigEndian.PutUint32(ikeMessageData[20:24], ikeMessage.MessageID)

	nextPayload, ikeMessagePayloadData, err := ikeMessage.Payloads.Encode()
	if err != nil {
		return nil, fmt.Errorf("Encode(): EncodePayload failed: %+v", err)
	}
	ikeMessageData[16] = nextPayload
	ikeMessageData = append(ikeMessageData, ikeMessagePayloadData...)
	binary.BigEndian.PutUint32(ikeMessageData[24:28], uint32(len(ikeMessageData)))

	return ikeMessageData, nil
}

func (ikeMessage *IKEMessage) Decode(rawData []byte) error {
	// IKE message packet format this implementation referenced is
	// defined in RFC 7296, Section 3.1

	// bounds checking
	if len(rawData) < 28 {
		return errors.New("Decode(): Received broken IKE header")
	}
	ikeMessageLength := binary.BigEndian.Uint32(rawData[24:28])
	if ikeMessageLength < 28 {
		return fmt.Errorf("Decode(): Illegal IKE message length %d < header length 20", ikeMessageLength)
	}
	// len() return int, which is 64 bit on 64-bit host and 32 bit
	// on 32-bit host, so this implementation may potentially cause
	// problem on 32-bit machine
	if len(rawData) != int(ikeMessageLength) {
		return errors.New("Decode(): The length of received message not matchs the length specified in header")
	}

	nextPayload := rawData[16]

	ikeMessage.InitiatorSPI = binary.BigEndian.Uint64(rawData[:8])
	ikeMessage.ResponderSPI = binary.BigEndian.Uint64(rawData[8:16])
	ikeMessage.Version = rawData[17]
	ikeMessage.ExchangeType = rawData[18]
	ikeMessage.Flags = rawData[19]
	ikeMessage.MessageID = binary.BigEndian.Uint32(rawData[20:24])

	err := ikeMessage.Payloads.Decode(nextPayload, rawData[28:])
	if err != nil {
		return fmt.Errorf("Decode(): DecodePayload failed: %+v", err)
	}

	return nil
}

type IKEPayloadContainer []IKEPayload

func (container *IKEPayloadContainer) Encode() (uint8, []byte, error) {
	if len(*container) == 0 {
		return types.NoNext, nil, errors.New("No payload in the container.")
	}

	ikeMessagePayloadData := make([]byte, 0)

	for index, payload := range *container {
		payloadData := make([]byte, 4)     // IKE payload general header
		if (index + 1) < len(*container) { // if it has next payload
			payloadData[0] = uint8((*container)[index+1].Type())
		} else {
			if payload.Type() == types.TypeSK {
				payloadData[0] = payload.(*Encrypted).NextPayload
			} else {
				payloadData[0] = types.NoNext
			}
		}

		data, err := payload.Marshal()
		if err != nil {
			return 0, nil, fmt.Errorf("EncodePayload(): Failed to marshal payload: %+v", err)
		}

		payloadData = append(payloadData, data...)
		binary.BigEndian.PutUint16(payloadData[2:4], uint16(len(payloadData)))

		ikeMessagePayloadData = append(ikeMessagePayloadData, payloadData...)
	}

	return uint8((*container)[0].Type()), ikeMessagePayloadData, nil
}

func (container *IKEPayloadContainer) Decode(nextPayload uint8, rawData []byte) error {
	for len(rawData) > 0 {
		// bounds checking
		if len(rawData) < 4 {
			return errors.New("DecodePayload(): No sufficient bytes to decode next payload")
		}
		payloadLength := binary.BigEndian.Uint16(rawData[2:4])
		if payloadLength < 4 {
			return fmt.Errorf("DecodePayload(): Illegal payload length %d < header length 4", payloadLength)
		}
		if len(rawData) < int(payloadLength) {
			return errors.New("DecodePayload(): The length of received message not matchs the length specified in header")
		}

		criticalBit := (rawData[1] & 0x80) >> 7

		var payload IKEPayload

		switch nextPayload {
		case types.TypeSA:
			payload = new(SecurityAssociation)
		case types.TypeKE:
			payload = new(KeyExchange)
		case types.TypeIDi:
			payload = new(IdentificationInitiator)
		case types.TypeIDr:
			payload = new(IdentificationResponder)
		case types.TypeCERT:
			payload = new(Certificate)
		case types.TypeCERTreq:
			payload = new(CertificateRequest)
		case types.TypeAUTH:
			payload = new(Authentication)
		case types.TypeNiNr:
			payload = new(Nonce)
		case types.TypeN:
			payload = new(Notification)
		case types.TypeD:
			payload = new(Delete)
		case types.TypeV:
			payload = new(VendorID)
		case types.TypeTSi:
			payload = new(TrafficSelectorInitiator)
		case types.TypeTSr:
			payload = new(TrafficSelectorResponder)
		case types.TypeSK:
			encryptedPayload := new(Encrypted)
			encryptedPayload.NextPayload = rawData[0]
			payload = encryptedPayload
		case types.TypeCP:
			payload = new(Configuration)
		case types.TypeEAP:
			payload = new(EAP)
		default:
			if criticalBit == 0 {
				// Skip this payload
				nextPayload = rawData[0]
				rawData = rawData[payloadLength:]
				continue
			} else {
				// TODO: Reject this IKE message
				return fmt.Errorf("Unknown payload type: %d", nextPayload)
			}
		}

		if err := payload.Unmarshal(rawData[4:payloadLength]); err != nil {
			return fmt.Errorf("DecodePayload(): Unmarshal payload failed: %+v", err)
		}

		*container = append(*container, payload)

		nextPayload = rawData[0]
		rawData = rawData[payloadLength:]
	}

	return nil
}

type IKEPayload interface {
	// Type specifies the IKE payload types
	Type() types.IKEPayloadType

	// Called by Encode() or Decode()
	Marshal() ([]byte, error)
	Unmarshal(rawData []byte) error
}

// Definition of Security Association

var _ IKEPayload = &SecurityAssociation{}

type SecurityAssociation struct {
	Proposals ProposalContainer
}

type ProposalContainer []*Proposal

type Proposal struct {
	ProposalNumber          uint8
	ProtocolID              uint8
	SPI                     []byte
	EncryptionAlgorithm     TransformContainer
	PseudorandomFunction    TransformContainer
	IntegrityAlgorithm      TransformContainer
	DiffieHellmanGroup      TransformContainer
	ExtendedSequenceNumbers TransformContainer
}

type TransformContainer []*Transform

type Transform struct {
	TransformType                uint8
	TransformID                  uint16
	AttributePresent             bool
	AttributeFormat              uint8
	AttributeType                uint16
	AttributeValue               uint16
	VariableLengthAttributeValue []byte
}

func (securityAssociation *SecurityAssociation) Type() types.IKEPayloadType { return types.TypeSA }

func (securityAssociation *SecurityAssociation) Marshal() ([]byte, error) {
	securityAssociationData := make([]byte, 0)

	for proposalIndex, proposal := range securityAssociation.Proposals {
		proposalData := make([]byte, 8)

		if (proposalIndex + 1) < len(securityAssociation.Proposals) {
			proposalData[0] = 2
		} else {
			proposalData[0] = 0
		}

		proposalData[4] = proposal.ProposalNumber
		proposalData[5] = proposal.ProtocolID

		proposalData[6] = uint8(len(proposal.SPI))
		if len(proposal.SPI) > 0 {
			proposalData = append(proposalData, proposal.SPI...)
		}

		// combine all transforms
		var transformList []*Transform
		transformList = append(transformList, proposal.EncryptionAlgorithm...)
		transformList = append(transformList, proposal.PseudorandomFunction...)
		transformList = append(transformList, proposal.IntegrityAlgorithm...)
		transformList = append(transformList, proposal.DiffieHellmanGroup...)
		transformList = append(transformList, proposal.ExtendedSequenceNumbers...)

		if len(transformList) == 0 {
			return nil, errors.New("One proposal has no any transform")
		}
		proposalData[7] = uint8(len(transformList))

		proposalTransformData := make([]byte, 0)

		for transformIndex, transform := range transformList {
			transformData := make([]byte, 8)

			if (transformIndex + 1) < len(transformList) {
				transformData[0] = 3
			} else {
				transformData[0] = 0
			}

			transformData[4] = transform.TransformType
			binary.BigEndian.PutUint16(transformData[6:8], transform.TransformID)

			if transform.AttributePresent {
				attributeData := make([]byte, 4)

				if transform.AttributeFormat == 0 {
					// TLV
					if len(transform.VariableLengthAttributeValue) == 0 {
						return nil, errors.New("Attribute of one transform not specified")
					}
					attributeFormatAndType := ((uint16(transform.AttributeFormat) & 0x1) << 15) | transform.AttributeType
					binary.BigEndian.PutUint16(attributeData[0:2], attributeFormatAndType)
					binary.BigEndian.PutUint16(attributeData[2:4], uint16(len(transform.VariableLengthAttributeValue)))
					attributeData = append(attributeData, transform.VariableLengthAttributeValue...)
				} else {
					// TV
					attributeFormatAndType := ((uint16(transform.AttributeFormat) & 0x1) << 15) | transform.AttributeType
					binary.BigEndian.PutUint16(attributeData[0:2], attributeFormatAndType)
					binary.BigEndian.PutUint16(attributeData[2:4], transform.AttributeValue)
				}

				transformData = append(transformData, attributeData...)
			}

			binary.BigEndian.PutUint16(transformData[2:4], uint16(len(transformData)))

			proposalTransformData = append(proposalTransformData, transformData...)
		}

		proposalData = append(proposalData, proposalTransformData...)
		binary.BigEndian.PutUint16(proposalData[2:4], uint16(len(proposalData)))

		securityAssociationData = append(securityAssociationData, proposalData...)
	}

	return securityAssociationData, nil
}

func (securityAssociation *SecurityAssociation) Unmarshal(rawData []byte) error {
	for len(rawData) > 0 {
		// bounds checking
		if len(rawData) < 8 {
			return errors.New("Proposal: No sufficient bytes to decode next proposal")
		}
		proposalLength := binary.BigEndian.Uint16(rawData[2:4])
		if proposalLength < 8 {
			return errors.New("Proposal: Illegal payload length %d < header length 8")
		}
		if len(rawData) < int(proposalLength) {
			return errors.New("Proposal: The length of received message not matchs the length specified in header")
		}

		proposal := new(Proposal)
		var transformData []byte

		proposal.ProposalNumber = rawData[4]
		proposal.ProtocolID = rawData[5]

		spiSize := rawData[6]
		if spiSize > 0 {
			// bounds checking
			if len(rawData) < int(8+spiSize) {
				return errors.New("Proposal: No sufficient bytes for unmarshalling SPI of proposal")
			}
			proposal.SPI = append(proposal.SPI, rawData[8:8+spiSize]...)
		}

		transformData = rawData[8+spiSize : proposalLength]

		for len(transformData) > 0 {
			// bounds checking
			if len(transformData) < 8 {
				return errors.New("Transform: No sufficient bytes to decode next transform")
			}
			transformLength := binary.BigEndian.Uint16(transformData[2:4])
			if transformLength < 8 {
				return errors.New("Transform: Illegal payload length %d < header length 8")
			}
			if len(transformData) < int(transformLength) {
				return errors.New("Transform: The length of received message not matchs the length specified in header")
			}

			transform := new(Transform)

			transform.TransformType = transformData[4]
			transform.TransformID = binary.BigEndian.Uint16(transformData[6:8])
			if transformLength > 8 {
				transform.AttributePresent = true
				transform.AttributeFormat = ((transformData[8] & 0x80) >> 7)
				transform.AttributeType = binary.BigEndian.Uint16(transformData[8:10]) & 0x7f

				if transform.AttributeFormat == 0 {
					attributeLength := binary.BigEndian.Uint16(transformData[10:12])
					// bounds checking
					if (12 + attributeLength) != transformLength {
						return fmt.Errorf("Illegal attribute length %d not satisfies the transform length %d",
							attributeLength, transformLength)
					}
					copy(transform.VariableLengthAttributeValue, transformData[12:12+attributeLength])
				} else {
					transform.AttributeValue = binary.BigEndian.Uint16(transformData[10:12])
				}

			}

			switch transform.TransformType {
			case types.TypeEncryptionAlgorithm:
				proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, transform)
			case types.TypePseudorandomFunction:
				proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, transform)
			case types.TypeIntegrityAlgorithm:
				proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, transform)
			case types.TypeDiffieHellmanGroup:
				proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, transform)
			case types.TypeExtendedSequenceNumbers:
				proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, transform)
			}

			transformData = transformData[transformLength:]
		}

		securityAssociation.Proposals = append(securityAssociation.Proposals, proposal)

		rawData = rawData[proposalLength:]
	}

	return nil
}

// Definition of Key Exchange

var _ IKEPayload = &KeyExchange{}

type KeyExchange struct {
	DiffieHellmanGroup uint16
	KeyExchangeData    []byte
}

func (keyExchange *KeyExchange) Type() types.IKEPayloadType { return types.TypeKE }

func (keyExchange *KeyExchange) Marshal() ([]byte, error) {
	keyExchangeData := make([]byte, 4)

	binary.BigEndian.PutUint16(keyExchangeData[0:2], keyExchange.DiffieHellmanGroup)
	keyExchangeData = append(keyExchangeData, keyExchange.KeyExchangeData...)

	return keyExchangeData, nil
}

func (keyExchange *KeyExchange) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("KeyExchange: No sufficient bytes to decode next key exchange data")
		}

		keyExchange.DiffieHellmanGroup = binary.BigEndian.Uint16(rawData[0:2])
		keyExchange.KeyExchangeData = append(keyExchange.KeyExchangeData, rawData[4:]...)
	}

	return nil
}

// Definition of Identification - Initiator

var _ IKEPayload = &IdentificationInitiator{}

type IdentificationInitiator struct {
	IDType uint8
	IDData []byte
}

func (identification *IdentificationInitiator) Type() types.IKEPayloadType { return types.TypeIDi }

func (identification *IdentificationInitiator) Marshal() ([]byte, error) {
	identificationData := make([]byte, 4)

	identificationData[0] = identification.IDType
	identificationData = append(identificationData, identification.IDData...)

	return identificationData, nil
}

func (identification *IdentificationInitiator) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("Identification: No sufficient bytes to decode next identification")
		}

		identification.IDType = rawData[0]
		identification.IDData = append(identification.IDData, rawData[4:]...)
	}

	return nil
}

// Definition of Identification - Responder

var _ IKEPayload = &IdentificationResponder{}

type IdentificationResponder struct {
	IDType uint8
	IDData []byte
}

func (identification *IdentificationResponder) Type() types.IKEPayloadType { return types.TypeIDr }

func (identification *IdentificationResponder) Marshal() ([]byte, error) {
	identificationData := make([]byte, 4)

	identificationData[0] = identification.IDType
	identificationData = append(identificationData, identification.IDData...)

	return identificationData, nil
}

func (identification *IdentificationResponder) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("Identification: No sufficient bytes to decode next identification")
		}

		identification.IDType = rawData[0]
		identification.IDData = append(identification.IDData, rawData[4:]...)
	}

	return nil
}

// Definition of Certificate

var _ IKEPayload = &Certificate{}

type Certificate struct {
	CertificateEncoding uint8
	CertificateData     []byte
}

func (certificate *Certificate) Type() types.IKEPayloadType { return types.TypeCERT }

func (certificate *Certificate) Marshal() ([]byte, error) {
	certificateData := make([]byte, 1)

	certificateData[0] = certificate.CertificateEncoding
	certificateData = append(certificateData, certificate.CertificateData...)

	return certificateData, nil
}

func (certificate *Certificate) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) <= 1 {
			return errors.New("Certificate: No sufficient bytes to decode next certificate")
		}

		certificate.CertificateEncoding = rawData[0]
		certificate.CertificateData = append(certificate.CertificateData, rawData[1:]...)
	}

	return nil
}

// Definition of Certificate Request

var _ IKEPayload = &CertificateRequest{}

type CertificateRequest struct {
	CertificateEncoding    uint8
	CertificationAuthority []byte
}

func (certificateRequest *CertificateRequest) Type() types.IKEPayloadType { return types.TypeCERTreq }

func (certificateRequest *CertificateRequest) Marshal() ([]byte, error) {
	certificateRequestData := make([]byte, 1)

	certificateRequestData[0] = certificateRequest.CertificateEncoding
	certificateRequestData = append(certificateRequestData, certificateRequest.CertificationAuthority...)

	return certificateRequestData, nil
}

func (certificateRequest *CertificateRequest) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) <= 1 {
			return errors.New("CertificateRequest: No sufficient bytes to decode next certificate request")
		}

		certificateRequest.CertificateEncoding = rawData[0]
		certificateRequest.CertificationAuthority = append(certificateRequest.CertificationAuthority, rawData[1:]...)
	}

	return nil
}

// Definition of Authentication

var _ IKEPayload = &Authentication{}

type Authentication struct {
	AuthenticationMethod uint8
	AuthenticationData   []byte
}

func (authentication *Authentication) Type() types.IKEPayloadType { return types.TypeAUTH }

func (authentication *Authentication) Marshal() ([]byte, error) {
	authenticationData := make([]byte, 4)

	authenticationData[0] = authentication.AuthenticationMethod
	authenticationData = append(authenticationData, authentication.AuthenticationData...)

	return authenticationData, nil
}

func (authentication *Authentication) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("Authentication: No sufficient bytes to decode next authentication")
		}

		authentication.AuthenticationMethod = rawData[0]
		authentication.AuthenticationData = append(authentication.AuthenticationData, rawData[4:]...)
	}

	return nil
}

// Definition of Nonce

var _ IKEPayload = &Nonce{}

type Nonce struct {
	NonceData []byte
}

func (nonce *Nonce) Type() types.IKEPayloadType { return types.TypeNiNr }

func (nonce *Nonce) Marshal() ([]byte, error) {
	nonceData := make([]byte, 0)
	nonceData = append(nonceData, nonce.NonceData...)

	return nonceData, nil
}

func (nonce *Nonce) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		nonce.NonceData = append(nonce.NonceData, rawData...)
	}

	return nil
}

// Definition of Notification

var _ IKEPayload = &Notification{}

type Notification struct {
	ProtocolID        uint8
	NotifyMessageType uint16
	SPI               []byte
	NotificationData  []byte
}

func (notification *Notification) Type() types.IKEPayloadType { return types.TypeN }

func (notification *Notification) Marshal() ([]byte, error) {
	notificationData := make([]byte, 4)

	notificationData[0] = notification.ProtocolID
	notificationData[1] = uint8(len(notification.SPI))
	binary.BigEndian.PutUint16(notificationData[2:4], notification.NotifyMessageType)

	notificationData = append(notificationData, notification.SPI...)
	notificationData = append(notificationData, notification.NotificationData...)

	return notificationData, nil
}

func (notification *Notification) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) < 4 {
			return errors.New("Notification: No sufficient bytes to decode next notification")
		}
		spiSize := rawData[1]
		if len(rawData) < int(4+spiSize) {
			return errors.New("Notification: No sufficient bytes to get SPI according to the length specified in header")
		}

		notification.ProtocolID = rawData[0]
		notification.NotifyMessageType = binary.BigEndian.Uint16(rawData[2:4])

		notification.SPI = append(notification.SPI, rawData[4:4+spiSize]...)
		notification.NotificationData = append(notification.NotificationData, rawData[4+spiSize:]...)
	}

	return nil
}

// Definition of Delete

var _ IKEPayload = &Delete{}

type Delete struct {
	ProtocolID  uint8
	SPISize     uint8
	NumberOfSPI uint16
	SPIs        []byte
}

func (delete *Delete) Type() types.IKEPayloadType { return types.TypeD }

func (delete *Delete) Marshal() ([]byte, error) {
	if len(delete.SPIs) != (int(delete.SPISize) * int(delete.NumberOfSPI)) {
		return nil, fmt.Errorf("Total bytes of all SPIs not correct")
	}

	deleteData := make([]byte, 4)

	deleteData[0] = delete.ProtocolID
	deleteData[1] = delete.SPISize
	binary.BigEndian.PutUint16(deleteData[2:4], delete.NumberOfSPI)

	deleteData = append(deleteData, delete.SPIs...)

	return deleteData, nil
}

func (delete *Delete) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("Delete: No sufficient bytes to decode next delete")
		}
		spiSize := rawData[1]
		numberOfSPI := binary.BigEndian.Uint16(rawData[2:4])
		if len(rawData) < (4 + (int(spiSize) * int(numberOfSPI))) {
			return errors.New("Delete: No Sufficient bytes to get SPIs according to the length specified in header")
		}

		delete.ProtocolID = rawData[0]
		delete.SPISize = spiSize
		delete.NumberOfSPI = numberOfSPI

		delete.SPIs = append(delete.SPIs, rawData[4:]...)
	}

	return nil
}

// Definition of Vendor ID

var _ IKEPayload = &VendorID{}

type VendorID struct {
	VendorIDData []byte
}

func (vendorID *VendorID) Type() types.IKEPayloadType { return types.TypeV }

func (vendorID *VendorID) Marshal() ([]byte, error) {
	return vendorID.VendorIDData, nil
}

func (vendorID *VendorID) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		vendorID.VendorIDData = append(vendorID.VendorIDData, rawData...)
	}

	return nil
}

// Definition of Traffic Selector - Initiator

var _ IKEPayload = &TrafficSelectorInitiator{}

type TrafficSelectorInitiator struct {
	TrafficSelectors IndividualTrafficSelectorContainer
}

type IndividualTrafficSelectorContainer []*IndividualTrafficSelector

type IndividualTrafficSelector struct {
	TSType       uint8
	IPProtocolID uint8
	StartPort    uint16
	EndPort      uint16
	StartAddress []byte
	EndAddress   []byte
}

func (trafficSelector *TrafficSelectorInitiator) Type() types.IKEPayloadType { return types.TypeTSi }

func (trafficSelector *TrafficSelectorInitiator) Marshal() ([]byte, error) {
	if len(trafficSelector.TrafficSelectors) > 0 {
		trafficSelectorData := make([]byte, 4)
		trafficSelectorData[0] = uint8(len(trafficSelector.TrafficSelectors))

		for _, individualTrafficSelector := range trafficSelector.TrafficSelectors {
			if individualTrafficSelector.TSType == types.TS_IPV4_ADDR_RANGE {
				// Address length checking
				if len(individualTrafficSelector.StartAddress) != 4 {
					return nil, errors.New("TrafficSelector: Start IPv4 address length is not correct")
				}
				if len(individualTrafficSelector.EndAddress) != 4 {
					return nil, errors.New("TrafficSelector: End IPv4 address length is not correct")
				}

				individualTrafficSelectorData := make([]byte, 8)

				individualTrafficSelectorData[0] = individualTrafficSelector.TSType
				individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
				binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
				binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

				binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(len(individualTrafficSelectorData)))

				trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
			} else if individualTrafficSelector.TSType == types.TS_IPV6_ADDR_RANGE {
				// Address length checking
				if len(individualTrafficSelector.StartAddress) != 16 {
					return nil, errors.New("TrafficSelector: Start IPv6 address length is not correct")
				}
				if len(individualTrafficSelector.EndAddress) != 16 {
					return nil, errors.New("TrafficSelector: End IPv6 address length is not correct")
				}

				individualTrafficSelectorData := make([]byte, 8)

				individualTrafficSelectorData[0] = individualTrafficSelector.TSType
				individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
				binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
				binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

				binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(len(individualTrafficSelectorData)))

				trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
			} else {
				return nil, errors.New("TrafficSelector: Unsupported traffic selector type")
			}
		}

		return trafficSelectorData, nil
	} else {
		return nil, errors.New("TrafficSelector: Contains no traffic selector for marshalling message")
	}
}

func (trafficSelector *TrafficSelectorInitiator) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) < 4 {
			return errors.New("TrafficSelector: No sufficient bytes to get number of traffic selector in header")
		}

		numberOfSPI := rawData[0]

		rawData = rawData[4:]

		for ; numberOfSPI > 0; numberOfSPI-- {
			// bounds checking
			if len(rawData) < 4 {
				return errors.New(
					"TrafficSelector: No sufficient bytes to decode next individual traffic selector length in header")
			}
			trafficSelectorType := rawData[0]
			if trafficSelectorType == types.TS_IPV4_ADDR_RANGE {
				selectorLength := binary.BigEndian.Uint16(rawData[2:4])
				if selectorLength != 16 {
					return errors.New("TrafficSelector: A TS_IPV4_ADDR_RANGE type traffic selector should has length 16 bytes")
				}
				if len(rawData) < int(selectorLength) {
					return errors.New("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
				}

				individualTrafficSelector := &IndividualTrafficSelector{}

				individualTrafficSelector.TSType = rawData[0]
				individualTrafficSelector.IPProtocolID = rawData[1]
				individualTrafficSelector.StartPort = binary.BigEndian.Uint16(rawData[4:6])
				individualTrafficSelector.EndPort = binary.BigEndian.Uint16(rawData[6:8])

				individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, rawData[8:12]...)
				individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, rawData[12:16]...)

				trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

				rawData = rawData[16:]
			} else if trafficSelectorType == types.TS_IPV6_ADDR_RANGE {
				selectorLength := binary.BigEndian.Uint16(rawData[2:4])
				if selectorLength != 40 {
					return errors.New("TrafficSelector: A TS_IPV6_ADDR_RANGE type traffic selector should has length 40 bytes")
				}
				if len(rawData) < int(selectorLength) {
					return errors.New("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
				}

				individualTrafficSelector := &IndividualTrafficSelector{}

				individualTrafficSelector.TSType = rawData[0]
				individualTrafficSelector.IPProtocolID = rawData[1]
				individualTrafficSelector.StartPort = binary.BigEndian.Uint16(rawData[4:6])
				individualTrafficSelector.EndPort = binary.BigEndian.Uint16(rawData[6:8])

				individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, rawData[8:24]...)
				individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, rawData[24:40]...)

				trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

				rawData = rawData[40:]
			} else {
				return errors.New("TrafficSelector: Unsupported traffic selector type")
			}
		}
	}

	return nil
}

// Definition of Traffic Selector - Responder

var _ IKEPayload = &TrafficSelectorResponder{}

type TrafficSelectorResponder struct {
	TrafficSelectors IndividualTrafficSelectorContainer
}

func (trafficSelector *TrafficSelectorResponder) Type() types.IKEPayloadType { return types.TypeTSr }

func (trafficSelector *TrafficSelectorResponder) Marshal() ([]byte, error) {
	if len(trafficSelector.TrafficSelectors) > 0 {
		trafficSelectorData := make([]byte, 4)
		trafficSelectorData[0] = uint8(len(trafficSelector.TrafficSelectors))

		for _, individualTrafficSelector := range trafficSelector.TrafficSelectors {
			if individualTrafficSelector.TSType == types.TS_IPV4_ADDR_RANGE {
				// Address length checking
				if len(individualTrafficSelector.StartAddress) != 4 {
					return nil, errors.New("TrafficSelector: Start IPv4 address length is not correct")
				}
				if len(individualTrafficSelector.EndAddress) != 4 {
					return nil, errors.New("TrafficSelector: End IPv4 address length is not correct")
				}

				individualTrafficSelectorData := make([]byte, 8)

				individualTrafficSelectorData[0] = individualTrafficSelector.TSType
				individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
				binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
				binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

				binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(len(individualTrafficSelectorData)))

				trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
			} else if individualTrafficSelector.TSType == types.TS_IPV6_ADDR_RANGE {
				// Address length checking
				if len(individualTrafficSelector.StartAddress) != 16 {
					return nil, errors.New("TrafficSelector: Start IPv6 address length is not correct")
				}
				if len(individualTrafficSelector.EndAddress) != 16 {
					return nil, errors.New("TrafficSelector: End IPv6 address length is not correct")
				}

				individualTrafficSelectorData := make([]byte, 8)

				individualTrafficSelectorData[0] = individualTrafficSelector.TSType
				individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
				binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
				binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

				binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(len(individualTrafficSelectorData)))

				trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
			} else {
				return nil, errors.New("TrafficSelector: Unsupported traffic selector type")
			}
		}

		return trafficSelectorData, nil
	} else {
		return nil, errors.New("TrafficSelector: Contains no traffic selector for marshalling message")
	}
}

func (trafficSelector *TrafficSelectorResponder) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) < 4 {
			return errors.New("TrafficSelector: No sufficient bytes to get number of traffic selector in header")
		}

		numberOfSPI := rawData[0]

		rawData = rawData[4:]

		for ; numberOfSPI > 0; numberOfSPI-- {
			// bounds checking
			if len(rawData) < 4 {
				return errors.New(
					"TrafficSelector: No sufficient bytes to decode next individual traffic selector length in header")
			}
			trafficSelectorType := rawData[0]
			if trafficSelectorType == types.TS_IPV4_ADDR_RANGE {
				selectorLength := binary.BigEndian.Uint16(rawData[2:4])
				if selectorLength != 16 {
					return errors.New("TrafficSelector: A TS_IPV4_ADDR_RANGE type traffic selector should has length 16 bytes")
				}
				if len(rawData) < int(selectorLength) {
					return errors.New("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
				}

				individualTrafficSelector := &IndividualTrafficSelector{}

				individualTrafficSelector.TSType = rawData[0]
				individualTrafficSelector.IPProtocolID = rawData[1]
				individualTrafficSelector.StartPort = binary.BigEndian.Uint16(rawData[4:6])
				individualTrafficSelector.EndPort = binary.BigEndian.Uint16(rawData[6:8])

				individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, rawData[8:12]...)
				individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, rawData[12:16]...)

				trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

				rawData = rawData[16:]
			} else if trafficSelectorType == types.TS_IPV6_ADDR_RANGE {
				selectorLength := binary.BigEndian.Uint16(rawData[2:4])
				if selectorLength != 40 {
					return errors.New("TrafficSelector: A TS_IPV6_ADDR_RANGE type traffic selector should has length 40 bytes")
				}
				if len(rawData) < int(selectorLength) {
					return errors.New("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
				}

				individualTrafficSelector := &IndividualTrafficSelector{}

				individualTrafficSelector.TSType = rawData[0]
				individualTrafficSelector.IPProtocolID = rawData[1]
				individualTrafficSelector.StartPort = binary.BigEndian.Uint16(rawData[4:6])
				individualTrafficSelector.EndPort = binary.BigEndian.Uint16(rawData[6:8])

				individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, rawData[8:24]...)
				individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, rawData[24:40]...)

				trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

				rawData = rawData[40:]
			} else {
				return errors.New("TrafficSelector: Unsupported traffic selector type")
			}
		}
	}

	return nil
}

// Definition of Encrypted Payload

var _ IKEPayload = &Encrypted{}

type Encrypted struct {
	NextPayload   uint8
	EncryptedData []byte
}

func (encrypted *Encrypted) Type() types.IKEPayloadType { return types.TypeSK }

func (encrypted *Encrypted) Marshal() ([]byte, error) {
	return encrypted.EncryptedData, nil
}

func (encrypted *Encrypted) Unmarshal(rawData []byte) error {
	encrypted.EncryptedData = append(encrypted.EncryptedData, rawData...)
	return nil
}

// Definition of Configuration

var _ IKEPayload = &Configuration{}

type Configuration struct {
	ConfigurationType      uint8
	ConfigurationAttribute ConfigurationAttributeContainer
}

type ConfigurationAttributeContainer []*IndividualConfigurationAttribute

type IndividualConfigurationAttribute struct {
	Type  uint16
	Value []byte
}

func (configuration *Configuration) Type() types.IKEPayloadType { return types.TypeCP }

func (configuration *Configuration) Marshal() ([]byte, error) {
	configurationData := make([]byte, 4)

	configurationData[0] = configuration.ConfigurationType

	for _, attribute := range configuration.ConfigurationAttribute {
		individualConfigurationAttributeData := make([]byte, 4)

		binary.BigEndian.PutUint16(individualConfigurationAttributeData[0:2], (attribute.Type & 0x7fff))
		binary.BigEndian.PutUint16(individualConfigurationAttributeData[2:4], uint16(len(attribute.Value)))

		individualConfigurationAttributeData = append(individualConfigurationAttributeData, attribute.Value...)

		configurationData = append(configurationData, individualConfigurationAttributeData...)
	}

	return configurationData, nil
}

func (configuration *Configuration) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) <= 4 {
			return errors.New("Configuration: No sufficient bytes to decode next configuration")
		}
		configuration.ConfigurationType = rawData[0]

		configurationAttributeData := rawData[4:]

		for len(configurationAttributeData) > 0 {
			// bounds checking
			if len(configurationAttributeData) < 4 {
				return errors.New("ConfigurationAttribute: No sufficient bytes to decode next configuration attribute")
			}
			length := binary.BigEndian.Uint16(configurationAttributeData[2:4])
			if len(configurationAttributeData) < int(4+length) {
				return errors.New("ConfigurationAttribute: TLV attribute length error")
			}

			individualConfigurationAttribute := new(IndividualConfigurationAttribute)

			individualConfigurationAttribute.Type = binary.BigEndian.Uint16(configurationAttributeData[0:2])
			configurationAttributeData = configurationAttributeData[4:]
			individualConfigurationAttribute.Value =
				append(individualConfigurationAttribute.Value, configurationAttributeData[:length]...)
			configurationAttributeData = configurationAttributeData[length:]

			configuration.ConfigurationAttribute = append(configuration.ConfigurationAttribute, individualConfigurationAttribute)
		}
	}

	return nil
}

// Definition of IKE EAP

var _ IKEPayload = &EAP{}

type EAP struct {
	Code        uint8
	Identifier  uint8
	EAPTypeData EAPTypeDataContainer
}

func (eap *EAP) Type() types.IKEPayloadType { return types.TypeEAP }

func (eap *EAP) Marshal() ([]byte, error) {
	eapData := make([]byte, 4)

	eapData[0] = eap.Code
	eapData[1] = eap.Identifier

	if len(eap.EAPTypeData) > 0 {
		eapTypeData, err := eap.EAPTypeData[0].Marshal()
		if err != nil {
			return nil, fmt.Errorf("EAP: EAP type data marshal failed: %+v", err)
		}

		eapData = append(eapData, eapTypeData...)
	}

	binary.BigEndian.PutUint16(eapData[2:4], uint16(len(eapData)))

	return eapData, nil
}

func (eap *EAP) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) < 4 {
			return errors.New("EAP: No sufficient bytes to decode next EAP payload")
		}
		eapPayloadLength := binary.BigEndian.Uint16(rawData[2:4])
		if eapPayloadLength < 4 {
			return errors.New("EAP: Payload length specified in the header is too small for EAP")
		}
		if len(rawData) != int(eapPayloadLength) {
			return errors.New("EAP: Received payload length not matches the length specified in header")
		}

		eap.Code = rawData[0]
		eap.Identifier = rawData[1]

		// EAP Success or Failed
		if eapPayloadLength == 4 {
			return nil
		}

		eapType := rawData[4]
		var eapTypeData EAPTypeFormat

		switch eapType {
		case types.EAPTypeIdentity:
			eapTypeData = new(EAPIdentity)
		case types.EAPTypeNotification:
			eapTypeData = new(EAPNotification)
		case types.EAPTypeNak:
			eapTypeData = new(EAPNak)
		case types.EAPTypeExpanded:
			eapTypeData = new(EAPExpanded)
		default:
			// TODO: Create unsupprted type to handle it
			return errors.New("EAP: Not supported EAP type")
		}

		if err := eapTypeData.Unmarshal(rawData[4:]); err != nil {
			return fmt.Errorf("EAP: Unamrshal EAP type data failed: %+v", err)
		}

		eap.EAPTypeData = append(eap.EAPTypeData, eapTypeData)

	}

	return nil
}

type EAPTypeDataContainer []EAPTypeFormat

type EAPTypeFormat interface {
	// Type specifies EAP types
	Type() types.EAPType

	// Called by EAP.Marshal() or EAP.Unmarshal()
	Marshal() ([]byte, error)
	Unmarshal(rawData []byte) error
}

// Definition of EAP Identity

var _ EAPTypeFormat = &EAPIdentity{}

type EAPIdentity struct {
	IdentityData []byte
}

func (eapIdentity *EAPIdentity) Type() types.EAPType { return types.EAPTypeIdentity }

func (eapIdentity *EAPIdentity) Marshal() ([]byte, error) {
	if len(eapIdentity.IdentityData) == 0 {
		return nil, errors.New("EAPIdentity: EAP identity is empty")
	}

	eapIdentityData := []byte{types.EAPTypeIdentity}
	eapIdentityData = append(eapIdentityData, eapIdentity.IdentityData...)

	return eapIdentityData, nil
}

func (eapIdentity *EAPIdentity) Unmarshal(rawData []byte) error {
	if len(rawData) > 1 {
		eapIdentity.IdentityData = append(eapIdentity.IdentityData, rawData[1:]...)
	}

	return nil
}

// Definition of EAP Notification

var _ EAPTypeFormat = &EAPNotification{}

type EAPNotification struct {
	NotificationData []byte
}

func (eapNotification *EAPNotification) Type() types.EAPType { return types.EAPTypeNotification }

func (eapNotification *EAPNotification) Marshal() ([]byte, error) {
	if len(eapNotification.NotificationData) == 0 {
		return nil, errors.New("EAPNotification: EAP notification is empty")
	}

	eapNotificationData := []byte{types.EAPTypeNotification}
	eapNotificationData = append(eapNotificationData, eapNotification.NotificationData...)

	return eapNotificationData, nil
}

func (eapNotification *EAPNotification) Unmarshal(rawData []byte) error {
	if len(rawData) > 1 {
		eapNotification.NotificationData = append(eapNotification.NotificationData, rawData[1:]...)
	}

	return nil
}

// Definition of EAP Nak

var _ EAPTypeFormat = &EAPNak{}

type EAPNak struct {
	NakData []byte
}

func (eapNak *EAPNak) Type() types.EAPType { return types.EAPTypeNak }

func (eapNak *EAPNak) Marshal() ([]byte, error) {
	if len(eapNak.NakData) == 0 {
		return nil, errors.New("EAPNak: EAP nak is empty")
	}

	eapNakData := []byte{types.EAPTypeNak}
	eapNakData = append(eapNakData, eapNak.NakData...)

	return eapNakData, nil
}

func (eapNak *EAPNak) Unmarshal(rawData []byte) error {
	if len(rawData) > 1 {
		eapNak.NakData = append(eapNak.NakData, rawData[1:]...)
	}

	return nil
}

// Definition of EAP expanded

var _ EAPTypeFormat = &EAPExpanded{}

type EAPExpanded struct {
	VendorID   uint32
	VendorType uint32
	VendorData []byte
}

func (eapExpanded *EAPExpanded) Type() types.EAPType { return types.EAPTypeExpanded }

func (eapExpanded *EAPExpanded) Marshal() ([]byte, error) {
	eapExpandedData := make([]byte, 8)

	vendorID := eapExpanded.VendorID & 0x00ffffff
	typeAndVendorID := (uint32(types.EAPTypeExpanded)<<24 | vendorID)

	binary.BigEndian.PutUint32(eapExpandedData[0:4], typeAndVendorID)
	binary.BigEndian.PutUint32(eapExpandedData[4:8], eapExpanded.VendorType)

	if len(eapExpanded.VendorData) == 0 {
		return eapExpandedData, nil
	}

	eapExpandedData = append(eapExpandedData, eapExpanded.VendorData...)

	return eapExpandedData, nil
}

func (eapExpanded *EAPExpanded) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		if len(rawData) < 8 {
			return errors.New("EAPExpanded: No sufficient bytes to decode the EAP expanded type")
		}

		typeAndVendorID := binary.BigEndian.Uint32(rawData[0:4])
		eapExpanded.VendorID = typeAndVendorID & 0x00ffffff

		eapExpanded.VendorType = binary.BigEndian.Uint32(rawData[4:8])

		if len(rawData) > 8 {
			eapExpanded.VendorData = append(eapExpanded.VendorData, rawData[8:]...)
		}
	}

	return nil
}
