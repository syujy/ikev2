package esn

import (
	"bitbucket.org/_syujy/ike/types"
)

const string_ESN_ENABLE string = "ESN_ENABLE"

func toString_ESN_ENABLE(attrType uint16, intValue uint16, bytesValue []byte) string {
	return string_ESN_ENABLE
}

var _ ESNType = &ESN_ENABLE{}

type ESN_ENABLE struct {
	priority uint32
}

func (t *ESN_ENABLE) transformID() uint16 {
	return types.ESN_ENABLE
}

func (t *ESN_ENABLE) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *ESN_ENABLE) setPriority(priority uint32) {
	t.priority = priority
}

func (t *ESN_ENABLE) Priority() uint32 {
	return t.priority
}

func (t *ESN_ENABLE) Init() bool {
	return true
}
