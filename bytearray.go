//Original - https://pkg.go.dev/github.com/paultag/go-ykpiv/internal/bytearray

package main

import (
	"encoding/asn1"
)

func b_Decode(bytes []byte) []asn1.RawValue {
	ret := []asn1.RawValue{}
	for {
		rawData := asn1.RawValue{}
		rest, err := asn1.Unmarshal(bytes, &rawData)
		if err != nil {
			return nil
		}
		ret = append(ret, rawData)
		if len(rest) == 0 {
			break
		}
		bytes = rest
	}
	return ret
}

func b_DERDecode(bytes []byte) []asn1.RawValue {
	rawData := asn1.RawValue{}
	if _, err := asn1.Unmarshal(bytes, &rawData); err != nil {
		return nil
	}
	return b_Decode(rawData.Bytes)

}
