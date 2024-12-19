package refresh

import (
	"fmt"
	"goauth/data/auths"
	"goauth/data/users"
	"goauth/logics/notification"
	"goauth/logics/services"
	"goauth/logics/tokenCreation"
	"goauth/tokens/access"
	"goauth/tokens/jwt"
	"goauth/tokens/refresh"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const maxBytesInValueForBcrypt = 72

// Команда на обновление аутентификации пользователя.
type Command struct {
	// ACCESS токен пользователя.
	AccessToken string

	// REFRESH токен пользователя.
	RefreshToken string

	// IP адрес пользователя.
	UserAddress string
}

// Результат обновления аутентификации пользователя.
type Result struct {
	// Новый ACCESS токен пользователя.
	AccessToken string

	// Новый REFRESH токен пользователя.
	RefreshToken string
}

// Обработчик команды на обновление аутентификации пользователя.
type CommandHandler struct {
	// Обрабатываемая команда.
	Command *Command

	_previousAuth *auths.Auth

	_previousAccessToken  *jwt.Jwt[access.AccessTokenPayload]
	_previousRefreshToken *jwt.Jwt[refresh.RefreshTokenPayload]

	_tokensCreationHandler *tokenCreation.CommandHandler
	_createdPairOfTokens   *tokenCreation.Result

	_user *users.User
}

// Обработать команду на обновление аутентификации пользователя.
func (s *CommandHandler) Handle() *Result {
	s.validateCommand()

	s.deletePreviousAuth()

	s.notifyUserIfAddressIsDifferent()

	return s.result()
}

// 1-й уровень абстракции.

func (s *CommandHandler) validateCommand() {
	s.panicIfTokensHaveDifferentIds()
	s.panicIfRefreshTokenHasExpired()
	s.validateRefreshTokenBySavedHash()
}

func (s *CommandHandler) deletePreviousAuth() {
	err := services.AuthsRepository().Delete(s.previousAuth().Id)
	if err != nil {
		panic(err)
	}
}

func (s *CommandHandler) notifyUserIfAddressIsDifferent() {
	if s.previousAccessToken().Payload.Address != s.Command.UserAddress {
		s.createNotificationCommandHandler().Handle()
	}
}

func (s *CommandHandler) result() *Result {
	return &Result{
		AccessToken:  s.createdPairOfTokens().AccessToken,
		RefreshToken: s.createdPairOfTokens().RefreshToken,
	}
}

// 2-й уровень абстракции.

func (s *CommandHandler) panicIfTokensHaveDifferentIds() {
	if s.previousAccessToken().Payload.Id != s.previousRefreshToken().Payload.Id {
		panic(fmt.Errorf("tokens have different ids"))
	}
}

func (s *CommandHandler) panicIfRefreshTokenHasExpired() {
	if s.previousRefreshToken().Payload.ExpirationTime < time.Now().Unix() {
		panic(fmt.Errorf("REFRESH token has expired"))
	}
}

func (s *CommandHandler) validateRefreshTokenBySavedHash() {
	err := bcrypt.CompareHashAndPassword([]byte(s.previousAuth().RefreshTokenHash), s.encodedPreviousRefreshTokenBytesForBcrypt())
	if err != nil {
		panic(fmt.Errorf("REFRESH token does not match the token stored in the database"))
	}
}

func (s *CommandHandler) previousAuth() *auths.Auth {
	if s._previousAuth == nil {
		s._previousAuth = s.getPreviousAuth()
	}

	return s._previousAuth
}

func (s *CommandHandler) createdPairOfTokens() *tokenCreation.Result {
	if s._createdPairOfTokens == nil {
		s._createdPairOfTokens = s.createPairOfTokens()
	}

	return s._createdPairOfTokens
}

func (s *CommandHandler) createNotificationCommandHandler() *notification.CommandHandler {
	return &notification.CommandHandler{
		Command: &notification.Command{
			ReceiverEmail:  s.user().Email,
			MessageSubject: "(shumilija/goauth) WARNING",
			MessageBody:    "Выполнена аутентификация по REFRESH токену. ID адрес: " + s.Command.UserAddress,
		},
	}
}

// 3-й уровень абстракции.

func (s *CommandHandler) getPreviousAuth() *auths.Auth {
	previousAuth, err := services.AuthsRepository().Get(s.previousRefreshToken().Payload.Id)
	if err != nil {
		panic(err)
	}

	return previousAuth
}

func (s *CommandHandler) previousRefreshToken() *jwt.Jwt[refresh.RefreshTokenPayload] {
	if s._previousRefreshToken == nil {
		s._previousRefreshToken = s.decodePreviousRefreshToken()
	}

	return s._previousRefreshToken
}

func (s *CommandHandler) encodedPreviousRefreshTokenBytesForBcrypt() []byte {
	return []byte(s.Command.RefreshToken)[:maxBytesInValueForBcrypt]
}

func (s *CommandHandler) createPairOfTokens() *tokenCreation.Result {
	return s.tokenCreationHandler().Handle()
}

func (s *CommandHandler) user() *users.User {
	if s._user == nil {
		s._user = s.getUser()
	}

	return s._user
}

// 4-й уровень абстракции.

func (s *CommandHandler) decodePreviousRefreshToken() *jwt.Jwt[refresh.RefreshTokenPayload] {
	decodedPreviousRefreshToken, err := services.RefreshTokenIssuer().Decode(s.Command.RefreshToken)
	if err != nil {
		panic(err)
	}

	return decodedPreviousRefreshToken
}

func (s *CommandHandler) tokenCreationHandler() *tokenCreation.CommandHandler {
	if s._tokensCreationHandler == nil {
		s._tokensCreationHandler = s.createTokenCreationHandler()
	}

	return s._tokensCreationHandler
}

func (s *CommandHandler) getUser() *users.User {
	user, err := services.UsersRepository().Get(s.previousAccessToken().Payload.Subject)
	if err != nil {
		panic(err)
	}

	return user
}

// 5-й уровень абстракции.

func (s *CommandHandler) createTokenCreationHandler() *tokenCreation.CommandHandler {
	tokenCreationHandler := tokenCreation.CommandHandler{
		Command: &tokenCreation.Command{
			UserId:      s.previousAccessToken().Payload.Subject,
			UserAddress: s.Command.UserAddress,
		},
	}

	return &tokenCreationHandler
}

// 6-й уровень абстракции.

func (s *CommandHandler) previousAccessToken() *jwt.Jwt[access.AccessTokenPayload] {
	if s._previousAccessToken == nil {
		s._previousAccessToken = s.decodePreviousAccessToken()
	}

	return s._previousAccessToken
}

// 7-й уровень абстракции.

func (s *CommandHandler) decodePreviousAccessToken() *jwt.Jwt[access.AccessTokenPayload] {
	decodedPreviousAccessToken, err := services.AccessTokenIssuer().Decode(s.Command.AccessToken)
	if err != nil {
		panic(err)
	}

	return decodedPreviousAccessToken
}
