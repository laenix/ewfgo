package vmfs

import (
	"fmt"
	"strconv"
)

func hex32(v uint32) string { return fmt.Sprintf("%08x", v) }

func utoa(v uint64) string { return strconv.FormatUint(v, 10) }
