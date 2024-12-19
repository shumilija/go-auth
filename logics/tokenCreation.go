package logics

import (
	"goauth/data/auths"
	"goauth/logics/services"
	"goauth/tokens/access"
	"goauth/tokens/jwt"
	"goauth/tokens/refresh"

	"golang.org/x/crypto/bcrypt"
)

// Команда для создания пары токенов.
type TokensCreationCommand struct {
	// Идентификатор пользователя, которому требуется выдать пару токенов.
	UserId int32

	// IP адрес пользователя.
	UserAddress string
}

// Результат создания пары токенов.
type TokensCreationResult struct {
	// ACCESS токен.
	AccessToken string

	// REFRESH токен.
	RefreshToken string
}

// Обработчик команды для создания пары токенов.
type TokensCreationCommandHandler struct {
	// Обрабатываемая команда.
	Command *TokensCreationCommand

	_createdAuth *auths.Auth

	_accessToken        *jwt.Jwt[access.AccessTokenPayload]
	_encodedAccessToken *string

	_refreshToken        *jwt.Jwt[refresh.RefreshTokenPayload]
	_encodedRefreshToken *string
}

// Обработать команду для создания пары токенов.
func (s *TokensCreationCommandHandler) Handle() *TokensCreationResult {
	s.saveRefreshTokenHash()

	return s.result()
}

// 1-й уровень абстракции.

func (s *TokensCreationCommandHandler) saveRefreshTokenHash() {
	createdAuth := *s.createdAuth()
	createdAuth.RefreshTokenHash = string(s.createRefreshTokenHash())

	services.AuthsRepository().Update(createdAuth)
}

func (s *TokensCreationCommandHandler) result() *TokensCreationResult {
	return &TokensCreationResult{
		AccessToken:  *s.encodedAccessToken(),
		RefreshToken: *s.encodedRefreshToken(),
	}
}

// 2-й уровень абстракции.

func (s *TokensCreationCommandHandler) createdAuth() *auths.Auth {
	if s._createdAuth == nil {
		s._createdAuth = s.createAuth()
	}

	return s._createdAuth
}

func (s *TokensCreationCommandHandler) createRefreshTokenHash() []byte {
	refreshTokenHash, err := bcrypt.GenerateFromPassword(s.encodedRefreshTokenBytesForBcrypt(), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	return refreshTokenHash
}

func (s *TokensCreationCommandHandler) encodedAccessToken() *string {
	if s._encodedAccessToken == nil {
		s._encodedAccessToken = s.encodeAccessToken()
	}

	return s._encodedAccessToken
}

// 3-й уровень абстракции.

func (s *TokensCreationCommandHandler) createAuth() *auths.Auth {
	token, err := services.AuthsRepository().Create(auths.Auth{
		UserId: s.Command.UserId,
	})
	if err != nil {
		panic(err)
	}

	return token
}

func (s *TokensCreationCommandHandler) encodedRefreshTokenBytesForBcrypt() []byte {
	return []byte(*s.encodedRefreshToken())[:MAX_BYTES_IN_VALUE_FOR_BCRYPT]
}

func (s *TokensCreationCommandHandler) encodeAccessToken() *string {
	encodedAccessToken, err := services.AccessTokenIssuer().Encode(*s.accessToken())
	if err != nil {
		panic(err)
	}

	return &encodedAccessToken
}

// 4-й уровень абстракции.

func (s *TokensCreationCommandHandler) encodedRefreshToken() *string {
	if s._encodedRefreshToken == nil {
		s._encodedRefreshToken = s.encodeRefreshToken()
	}

	return s._encodedRefreshToken
}

func (s *TokensCreationCommandHandler) accessToken() *jwt.Jwt[access.AccessTokenPayload] {
	if s._accessToken == nil {
		s._accessToken = s.createAccessToken()
	}

	return s._accessToken
}

// 5-й уровень абстракции.

func (s *TokensCreationCommandHandler) encodeRefreshToken() *string {
	encodedRefreshToken, err := services.RefreshTokenIssuer().Encode(*s.refreshToken())
	if err != nil {
		panic(err)
	}

	return &encodedRefreshToken
}

func (s *TokensCreationCommandHandler) createAccessToken() *jwt.Jwt[access.AccessTokenPayload] {
	token := services.AccessTokenIssuer().New(s.Command.UserId, s.Command.UserAddress, s.createdAuth().Id)

	return &token
}

// 6-й уровень абстракции.

func (s *TokensCreationCommandHandler) refreshToken() *jwt.Jwt[refresh.RefreshTokenPayload] {
	if s._refreshToken == nil {
		s._refreshToken = s.createRefreshToken()
	}

	return s._refreshToken
}

// 7-й уровень абстракции.

func (s *TokensCreationCommandHandler) createRefreshToken() *jwt.Jwt[refresh.RefreshTokenPayload] {
	token := services.RefreshTokenIssuer().New(s.createdAuth().Id)

	return &token
}
