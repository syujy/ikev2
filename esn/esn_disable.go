package esn

import (
	"bitbucket.org/_syujy/ike/types"
)

const String_ESN_DISABLE string = "ESN_DISABLE"

func toString_ESN_DISABLE(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_ESN_DISABLE
}

var _ ESNType = &ESN_DISABLE{}

type ESN_DISABLE struct {
	priority uint32
}

func (t *ESN_DISABLE) transformID() uint16 {
	return types.ESN_DISABLE
}

func (t *ESN_DISABLE) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *ESN_DISABLE) setPriority(priority uint32) {
	t.priority = priority
}

func (t *ESN_DISABLE) Priority() uint32 {
	return t.priority
}

func (t *ESN_DISABLE) Init() bool {
	return false
}
