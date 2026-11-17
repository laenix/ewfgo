package leveldb

import "errors"

// ErrLimitExceeded marks input that is larger than a caller-set or built-in
// bound. Readers return it before allocating for the claimed size.
var ErrLimitExceeded = errors.New("leveldb: limit exceeded")
