package login

import (
	"goauth/data/auths"
	"goauth/logics/services"
	"goauth/tokens/access"
	"goauth/tokens/jwt"
	"goauth/tokens/refresh"

	"golang.org/x/crypto/bcrypt"
)

const maxBytesInValueForBcrypt = 72

// Команда для аутентификации пользователя.
type Command struct {
	// Идентификатор пользователя, которому требуется выдать пару токенов.
	UserId int32

	// IP адрес пользователя.
	UserAddress string
}

// Результат аутентификации пользователя.
type Result struct {
	// ACCESS токен.
	AccessToken string

	// REFRESH токен.
	RefreshToken string
}

// Обработчик команды для аутентификации пользователя.
type CommandHandler struct {
	// Обрабатываемая команда.
	Command *Command

	_createdAuth *auths.Auth

	_accessToken        *jwt.Jwt[access.AccessTokenPayload]
	_encodedAccessToken *string

	_refreshToken        *jwt.Jwt[refresh.RefreshTokenPayload]
	_encodedRefreshToken *string
}

// Обработать команду для аутентификации пользователя.
func (s *CommandHandler) Handle() *Result {
	s.panicIfUserDoesNotExist()

	s.deletePreviousAuth()

	result := &Result{
		AccessToken:  *s.encodedAccessToken(),
		RefreshToken: *s.encodedRefreshToken(),
	}

	s.saveRefreshTokenHash()

	return result
}

func (s *CommandHandler) panicIfUserDoesNotExist() {
	_, err := services.UsersRepository().Get(s.Command.UserId)
	if err != nil {
		panic(err)
	}
}

func (s *CommandHandler) deletePreviousAuth() {
	err := services.AuthsRepository().DeleteByUser(s.Command.UserId)
	if err != nil {
		panic(err)
	}
}

func (s *CommandHandler) encodedAccessToken() *string {
	if s._encodedAccessToken == nil {
		s._encodedAccessToken = s.encodeAccessToken()
	}

	return s._encodedAccessToken
}

func (s *CommandHandler) encodeAccessToken() *string {
	encodedAccessToken, err := services.AccessTokenIssuer().Encode(*s.accessToken())
	if err != nil {
		panic(err)
	}

	return &encodedAccessToken
}

func (s *CommandHandler) accessToken() *jwt.Jwt[access.AccessTokenPayload] {
	if s._accessToken == nil {
		s._accessToken = s.createAccessToken()
	}

	return s._accessToken
}

func (s *CommandHandler) createAccessToken() *jwt.Jwt[access.AccessTokenPayload] {
	token := services.AccessTokenIssuer().New(s.Command.UserId, s.Command.UserAddress, s.createdAuth().Id)

	return &token
}

func (s *CommandHandler) encodedRefreshToken() *string {
	if s._encodedRefreshToken == nil {
		s._encodedRefreshToken = s.encodeRefreshToken()
	}

	return s._encodedRefreshToken
}

func (s *CommandHandler) encodeRefreshToken() *string {
	encodedRefreshToken, err := services.RefreshTokenIssuer().Encode(*s.refreshToken())
	if err != nil {
		panic(err)
	}

	return &encodedRefreshToken
}

func (s *CommandHandler) refreshToken() *jwt.Jwt[refresh.RefreshTokenPayload] {
	if s._refreshToken == nil {
		s._refreshToken = s.createRefreshToken()
	}

	return s._refreshToken
}

func (s *CommandHandler) createRefreshToken() *jwt.Jwt[refresh.RefreshTokenPayload] {
	token := services.RefreshTokenIssuer().New(s.createdAuth().Id)

	return &token
}

func (s *CommandHandler) saveRefreshTokenHash() {
	createdAuth := *s.createdAuth()
	createdAuth.RefreshTokenHash = string(s.createRefreshTokenHash())

	services.AuthsRepository().Update(createdAuth)
}

func (s *CommandHandler) createRefreshTokenHash() []byte {
	refreshTokenHash, err := bcrypt.GenerateFromPassword(s.encodedRefreshTokenBytesForBcrypt(), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	return refreshTokenHash
}

func (s *CommandHandler) encodedRefreshTokenBytesForBcrypt() []byte {
	return []byte(*s.encodedRefreshToken())[:maxBytesInValueForBcrypt]
}

func (s *CommandHandler) createdAuth() *auths.Auth {
	if s._createdAuth == nil {
		s._createdAuth = s.createAuth()
	}

	return s._createdAuth
}

func (s *CommandHandler) createAuth() *auths.Auth {
	token, err := services.AuthsRepository().Create(auths.Auth{
		UserId: s.Command.UserId,
	})
	if err != nil {
		panic(err)
	}

	return token
}
