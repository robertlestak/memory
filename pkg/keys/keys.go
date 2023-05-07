package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"
)

type MessageHeader struct {
	Key   string `json:"k"`
	Nonce string `json:"n"`
}

func RsaEncrypt(publicKey *rsa.PublicKey, origData []byte) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"pkg": "keys",
		"fn":  "RsaEncrypt",
	})
	l.Debug("encrypting data")
	l.Debugf("public key: %s", publicKey)
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, origData, nil)
}

func RsaDecrypt(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"pkg": "keys",
		"fn":  "RsaDecrypt",
	})
	l.Debug("decrypting data")
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, ciphertext, nil)
}

func GenerateNewAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func AESEncrypt(data, secret []byte) (string, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	hd := hex.EncodeToString(ciphertext)
	return hd, nil
}

func AESDecrypt(data string, secret []byte) ([]byte, error) {
	ciphertext, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// AesGcmEncrypt takes an encryption key and a plaintext string and encrypts it with AES256 in GCM mode, which provides authenticated encryption. Returns the ciphertext and the used nonce.
func AesGcmEncrypt(key []byte, raw []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, raw, nil)
	return ciphertext, nonce, nil
}

// AesGcmDecrypt takes an decryption key, a ciphertext and the corresponding nonce and decrypts it with AES256 in GCM mode. Returns the plaintext string.
func AesGcmDecrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintextBytes, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintextBytes, nil
}

func Encrypt(data []byte, key *rsa.PublicKey) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"pkg": "keys",
		"fn":  "EncryptMessage",
	})
	l.Debug("Encrypting message")
	// create a new key
	aesKey, err := GenerateNewAESKey()
	if err != nil {
		l.Error("Error generating new AES key")
		return nil, err
	}
	// encrypt the data
	ciphertext, nonce, err := AesGcmEncrypt(aesKey, data)
	if err != nil {
		l.Error("Error encrypting data")
		return nil, err
	}
	hdr := &MessageHeader{
		Key:   hex.EncodeToString(aesKey),
		Nonce: hex.EncodeToString(nonce),
	}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		l.Error("Error marshalling header")
		return nil, err
	}
	// encrypt the header with the rsa key
	hdrEncrypted, err := RsaEncrypt(key, hdrBytes)
	if err != nil {
		l.Error("Error encrypting header")
		return nil, err
	}
	hexHdr := hex.EncodeToString(hdrEncrypted)
	// join the header bytes and the ciphertext bytes together
	// with a string "."
	sep := "."
	mes := hexHdr + sep + hex.EncodeToString(ciphertext)
	return []byte(mes), nil
}

func Decrypt(d []byte, key *rsa.PrivateKey) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"pkg": "keys",
		"fn":  "DecryptMessage",
	})
	l.Debug("Decrypting message")
	data := string(d)
	l.Debugf("data: %s", data)
	// split the data into the header and the ciphertext
	sep := "."
	parts := strings.Split(data, sep)
	if len(parts) != 2 {
		l.Error("Error splitting data")
		return nil, errors.New("data error")
	}
	// decrypt the header
	hdrEncrypted := parts[0]
	// decode the header
	hdrBytes, err := hex.DecodeString(hdrEncrypted)
	if err != nil {
		l.Error("Error decoding header")
		return nil, err
	}
	hdrb, err := RsaDecrypt(key, hdrBytes)
	if err != nil {
		l.Error("Error decrypting header")
		return nil, err
	}
	l.Debugf("hdrb: %s", hdrb)
	// unmarshal the header
	var hdr MessageHeader
	err = json.Unmarshal(hdrb, &hdr)
	if err != nil {
		l.Error("Error unmarshalling header")
		return nil, err
	}
	// decrypt the ciphertext
	ciphertext := parts[1]
	cd, err := hex.DecodeString(ciphertext)
	if err != nil {
		l.Error("Error decoding ciphertext")
		return nil, err
	}
	l.Debugf("Key: %s", hdr.Key)
	l.Debugf("Nonce: %s", hdr.Nonce)
	kd, err := hex.DecodeString(hdr.Key)
	if err != nil {
		l.Error("Error decoding key")
		return nil, err
	}
	nd, err := hex.DecodeString(hdr.Nonce)
	if err != nil {
		l.Error("Error decoding nonce")
		return nil, err
	}
	plaintext, err := AesGcmDecrypt(kd, cd, nd)
	if err != nil {
		l.Error("Error decrypting data")
		return nil, err
	}
	return plaintext, nil
}

func ByesToPrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		p, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, err
		}
		priv = p.(*rsa.PrivateKey)
	}
	return priv, nil
}
