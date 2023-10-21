package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

type keyBlob struct {
	Version             int
	AlgorithmIdentifier asn1.RawValue
	Blob                []byte
}

type privateKey struct {
	Version   int `asn1:"default:0"`
	Algorithm struct {
		Value      asn1.ObjectIdentifier
		Parameters struct {
			Curve  asn1.ObjectIdentifier
			Digest asn1.ObjectIdentifier
		}
	}
	PrivateKey []byte
}

type exportKeyBlobOids struct {
	Id    asn1.ObjectIdentifier
	Value struct {
		Curve  asn1.ObjectIdentifier
		Digest asn1.ObjectIdentifier
	}
}

type exportKeyBlob struct {
	Value struct {
		Ukm []byte
		Cek struct {
			Enc []byte
			Mac []byte
		}
		Oids asn1.RawValue
	}
}

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}
type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

// from PKCS#7:
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type safeBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type pbeInfo struct {
	Header struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters struct {
			Salt   []byte
			Rounds int
		}
	}
	EncryptedKey []byte
}

func unmarshal(in []byte, out interface{}) error {
	trailing, err := asn1.Unmarshal(in, out)
	if err != nil {
		return err
	}
	if len(trailing) != 0 {
		panic("pkcs12: trailing data found")
	}
	return nil
}

func getKeybags(bin []byte) (bags []safeBag, err error) {
	var pfx pfxPdu
	oidDataContentType := asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidEncryptedDataContentType := asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 6})

	asn1.Unmarshal(bin, &pfx)
	if pfx.Version != 3 {
		panic("can only decode v3 PFX PDU's")
	}

	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		panic("only password-protected PFX is implemented")
	}

	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		panic(err)
	}
	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		panic("pkcs12: no MAC in data")
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		panic(err)
	}
	if len(authenticatedSafe) != 2 {
		panic("expected exactly two items in the authenticated safe")
	}

	for _, ci := range authenticatedSafe {
		var data []byte

		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if err := unmarshal(ci.Content.Bytes, &data); err != nil {
				panic(err)
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			return
		default:
			return
		}

		var safeContents []safeBag
		if err := unmarshal(data, &safeContents); err != nil {
			panic(err)
		}
		bags = append(bags, safeContents...)
	}

	return bags, nil
}
