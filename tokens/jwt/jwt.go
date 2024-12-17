package jwt

import (
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"
)

// JWT токен.
type Jwt[T any] struct {
	// Заголовок JWT токена.
	Header Header

	// Полезная нагрузка JWT токена.
	Payload T
}

// Заголовок JWT токена.
type Header struct {
	// Алгоритм шифрования.
	Algorythm string `json:"alg"`

	// Тип токена.
	Type string `json:"typ"`
}

// Закодировать JWT токен.
func (s Jwt[T]) Encoded(hash hash.Hash) (string, error) {
	encodedHeader, err := marshalAndEncode(s.Header)
	if err != nil {
		return "", err
	}

	encodedPayload, err := marshalAndEncode(s.Payload)
	if err != nil {
		return "", err
	}

	signature, err := s.Signature(hash)
	if err != nil {
		return "", err
	}

	return encodedHeader + "." + encodedPayload + "." + signature, nil
}

// Получить подпись JWT токена с помощью указанной функции.
func (s Jwt[T]) Signature(hash hash.Hash) (string, error) {
	encodedHeader, err := marshalAndEncode(s.Header)
	if err != nil {
		return "", err
	}

	encodedPayload, err := marshalAndEncode(s.Payload)
	if err != nil {
		return "", err
	}

	hash.Write([]byte(encodedHeader + "." + encodedPayload))

	var result = encode(hash.Sum(nil))

	return result, nil
}

func Decode[T any](value string) (*T, error) {
	afterDecoding, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}

	var afterUnmarshalling T
	err = json.Unmarshal(afterDecoding, &afterUnmarshalling)
	if err != nil {
		return nil, err
	}

	return &afterUnmarshalling, nil
}

func marshalAndEncode[T any](value T) (string, error) {
	afterMarshalling, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	return encode(afterMarshalling), nil
}

func encode(value []byte) string {
	var afterEncoding = base64.URLEncoding.EncodeToString(value)
	var afterTrimming = strings.TrimRight(afterEncoding, "=")

	return afterTrimming
}
