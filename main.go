package main

import (
	"bufio"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"unicode/utf16"

	"github.com/google/uuid"
	"github.com/thefish/gogost/gost28147"
	"github.com/thefish/gogost/gost34112012256"
	"github.com/thefish/gogost/gost341194"
	"golang.org/x/term"
)

func readBinFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)

	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats, statsErr := file.Stat()
	if statsErr != nil {
		return nil, statsErr
	}

	var size int64 = stats.Size()
	bytes := make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(bytes)

	return bytes, err
}

func utf16le(val string) []byte {
	var v []byte
	for _, r := range val {
		if utf16.IsSurrogate(r) {
			r1, r2 := utf16.EncodeRune(r)
			v = append(v, byte(r1), byte(r1>>8))
			v = append(v, byte(r2), byte(r2>>8))
		} else {
			v = append(v, byte(r), byte(r>>8))
		}
	}
	return v
}

func decodeHex(val string) []byte {
	j, _ := hex.DecodeString(val)
	return j
}

// Танец с бубном для преобразования A0 (Context Specific) в 30 (Sequence)
func costyl(val []byte) []byte {
	tmp := b_DERDecode(val)[1].Bytes
	return decodeHex("30" + fmt.Sprintf("%x", len(tmp)) + hex.EncodeToString(tmp))
}

// CryptoPro KEK diversification algorithm, RFC 4757 section 6.5
func cp_kek_diversify(kek []byte, ukm []byte) []byte {
	out := make([]byte, len(kek))
	copy(out, kek)

	for i := 0; i < 8; i++ {
		s1, s2 := 0, 0
		for j := 0; j < 8; j++ {
			k := int32(binary.LittleEndian.Uint32(out[j*4 : j*4+4]))
			if (ukm[i] >> uint(j) & 1) != 0 {
				s1 += int(k)
			} else {
				s2 += int(k)
			}
		}
		iv := make([]byte, 8)
		binary.LittleEndian.PutUint32(iv[:4], uint32(s1%(1<<32)))
		binary.LittleEndian.PutUint32(iv[4:], uint32(s2%(1<<32)))
		cipher := gost28147.NewCipher(out, &gost28147.SboxIdGost2814789CryptoProAParamSet).NewCFBEncrypter(iv)
		cipher.XORKeyStream(out, out)
	}

	return out
}

func save_key(ks []byte, algooid asn1.ObjectIdentifier, curve asn1.ObjectIdentifier, digest asn1.ObjectIdentifier) {
	var pkey privateKey
	pkey.PrivateKey = ks
	pkey.Algorithm.Value = algooid
	pkey.Algorithm.Parameters.Curve = curve
	pkey.Algorithm.Parameters.Digest = digest
	result, err := asn1.Marshal(pkey)
	if err != nil {
		panic("Ks2pem: " + err.Error())
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: result,
	}
	uid := uuid.NewString()
	file, _ := os.Create("exported_" + uid + ".pem")
	defer file.Close()
	pem.Encode(file, block)
	fmt.Println("Сохранено в exported_" + uid + ".pem")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Как использовать: ./program <файл PFX>")
		os.Exit(0)
	}
	fmt.Println("CryptoPro PFX Decoder by li0ard (Go version)")
	fmt.Printf("Введите пароль: ")
	password, _ := term.ReadPassword(0)
	fmt.Println("")
	PASS := string(password)
	bin, _ := readBinFile(os.Args[1])
	pfx, _ := getKeybags(bin)
	count := 0
	for _, keybag := range pfx {
		if count == 1 {
			break
		}

		var info pbeInfo
		asn1.Unmarshal(keybag.Value.Bytes, &info)
		ROUNDS := info.Header.Parameters.Rounds
		SALT := hex.EncodeToString(info.Header.Parameters.Salt)
		KEY := utf16le(PASS)
		fmt.Println(" SALT  = " + SALT)
		fmt.Printf(" ITERS = %d\n", ROUNDS)
		for i := 1; i < ROUNDS+1; i++ {
			hasher := gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			tmp := decodeHex(hex.EncodeToString(KEY) + SALT + fmt.Sprintf("%04s", fmt.Sprintf("%x", i)))
			hasher.Write(tmp)
			KEY = hasher.Sum(nil)
		}
		fmt.Println(" KEY   = " + hex.EncodeToString(KEY))
		fmt.Println(" IV    = " + SALT[:16])

		cipher := gost28147.NewCipher(KEY, &gost28147.SboxIdGost2814789CryptoProAParamSet)
		fe := cipher.NewCFBDecrypter(decodeHex(SALT[:16]))
		result := make([]byte, len(info.EncryptedKey))
		fe.XORKeyStream(result, info.EncryptedKey)

		var blob keyBlob
		asn1.Unmarshal(result, &blob)

		var blob2 exportKeyBlob
		asn1.Unmarshal(decodeHex(hex.EncodeToString(blob.Blob)[32:]), &blob2)
		UKM := blob2.Value.Ukm
		ENC := blob2.Value.Cek.Enc
		algtype := hex.EncodeToString(blob.Blob)[:32][8:12]
		algooid := asn1.ObjectIdentifier([]int{1, 2, 643, 7, 1, 1, 1, 1})
		if algtype == "42aa" {
			algooid = asn1.ObjectIdentifier([]int{1, 2, 643, 7, 1, 1, 1, 2})
		}
		if algtype == "24aa" {
			algooid = asn1.ObjectIdentifier([]int{1, 2, 643, 2, 2, 19})
		}

		var oids exportKeyBlobOids
		_, err := asn1.Unmarshal(costyl(blob2.Value.Oids.FullBytes), &oids)
		if err != nil {
			panic("costyl: " + err.Error())
		}

		kdfer := gost34112012256.NewKDF(KEY)
		KEKe := kdfer.Derive(nil, decodeHex("26BDB878"), UKM)
		fmt.Println(" KEKE  = " + hex.EncodeToString(KEKe))

		switch algtype {
		case "24aa":
			Ks := make([]byte, len(ENC))
			cipher := gost28147.NewCipher(cp_kek_diversify(KEY, UKM), &gost28147.SboxIdGost2814789CryptoProAParamSet)
			fe := cipher.NewECBDecrypter()
			fe.CryptBlocks(Ks, ENC)
			fmt.Println(" K     = " + hex.EncodeToString(Ks))
			save_key(Ks, algooid, oids.Value.Curve, oids.Value.Digest)

		case "46aa", "42aa":
			Ks := make([]byte, len(ENC))
			cipher := gost28147.NewCipher(KEKe, &gost28147.SboxIdGost2814789CryptoProAParamSet)
			fe := cipher.NewECBDecrypter()
			fe.CryptBlocks(Ks, ENC)
			fmt.Println(" K     = " + hex.EncodeToString(Ks))
			save_key(Ks, algooid, oids.Value.Curve, oids.Value.Digest)
		default:
			panic("unwrap: not supported key algorithm. It must be GOST 34.10-2012_256 or 34.10-2012_512 (" + algtype + ")")
		}
		count++
	}
}
