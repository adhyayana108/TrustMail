package util

import(
	"crypto/rand"
	"encoding/hex"
)

func NewID() string {
	b:= make([]byte , 12)
	if _,err := rand.Read(b); err!= nil {

		panic("util: failed to read random bytes " + err.Error())
	}

	return hex.EncodeToString(b)
}