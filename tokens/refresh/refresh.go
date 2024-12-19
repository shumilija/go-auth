package refresh

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"goauth/tokens/jwt"
	"hash"
	"strings"
	"time"
)

// Полезная нагрузка JWT токена обновления.
type RefreshTokenPayload struct {
	// Имя издателя токена.
	Issuer string `json:"iss"`

	// Момент времени, когда токен был выдан в формате UNIX.
	IssuedAt int64 `json:"iat"`

	// Момент времени, до которого токен считается действительным в формате UNIX.
	ExpirationTime int64 `json:"exp"`

	// Идентификатор токена.
	Id int32 `json:"jti"`

	// IP адрес пользователя, под которым тот получил токен.
	UserIp string `json:"uip"`
}

// Вспомогательное средство для издания JWT токенов обновления.
type Issuer struct {
	// Имя издателя токена.
	Name string

	// Ключ, с помощью которого подписываются токены.
	Key string

	// Время жизни токена в часах.
	TokenLifeTimeInHours int
}

// Выдать новый токен с указанными параметрами.
func (s Issuer) New(userIp string, tokenId int32) jwt.Jwt[RefreshTokenPayload] {
	now := time.Now()

	result := jwt.Jwt[RefreshTokenPayload]{
		Header: jwt.Header{
			Algorythm: "HS512",
			Type:      "JWT",
		},
		Payload: RefreshTokenPayload{
			Issuer:         s.Name,
			IssuedAt:       now.Unix(),
			ExpirationTime: now.Add(time.Duration(s.TokenLifeTimeInHours) * time.Hour).Unix(),
			Id:             tokenId,
			UserIp:         userIp,
		},
	}

	return result
}

// Закодировать указанный токен с помощью определенного внутри средства алгоритма.
func (s Issuer) Encode(token jwt.Jwt[RefreshTokenPayload]) (string, error) {
	encodedToken, err := token.Encoded(s.Hash())
	if err != nil {
		return "", err
	}

	return encodedToken, nil
}

// Декодировать указанный закодированный токен.
func (s Issuer) Decode(encodedToken string) (*jwt.Jwt[RefreshTokenPayload], error) {
	parts := strings.Split(encodedToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("the number of encoded token %s parts is not equal to 3", encodedToken)
	}

	decodedHeader, err := jwt.Decode[jwt.Header](parts[0])
	if err != nil {
		return nil, err
	}

	decodedPayload, err := jwt.Decode[RefreshTokenPayload](parts[1])
	if err != nil {
		return nil, err
	}

	decodedToken := &jwt.Jwt[RefreshTokenPayload]{
		Header:  *decodedHeader,
		Payload: *decodedPayload,
	}

	decodedTokenSignature, err := decodedToken.Signature(s.Hash())
	if err != nil {
		return nil, err
	}

	encodedTokenSignature := parts[2]
	if encodedTokenSignature != decodedTokenSignature {
		return nil, fmt.Errorf("the signature of the encoded token %s is not equal to the calculated signature of the decoded token", encodedToken)
	}

	return decodedToken, nil
}

// Получить хэш-функцию, используемую издателем токенов.
func (s Issuer) Hash() hash.Hash {
	return hmac.New(sha512.New, []byte(s.Key))
}
