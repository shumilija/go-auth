package logics

import (
	"fmt"
	"goauth/data/auths"
	"goauth/data/users"
	"goauth/logics/services"
	"goauth/tokens/access"
	"goauth/tokens/jwt"
	"goauth/tokens/refresh"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Команда на обновление аутентификации пользователя.
type RefreshCommand struct {
	// ACCESS токен пользователя.
	AccessToken string

	// REFRESH токен пользователя.
	RefreshToken string

	// IP адрес пользователя.
	UserAddress string
}

// Результат обновления аутентификации пользователя.
type RefreshResult struct {
	// Новый ACCESS токен пользователя.
	AccessToken string

	// Новый REFRESH токен пользователя.
	RefreshToken string
}

// Обработчик команды на обновление аутентификации пользователя.
type RefreshCommandHandler struct {
	// Обрабатываемая команда.
	Command *RefreshCommand

	_previousAuth *auths.Auth

	_previousAccessToken  *jwt.Jwt[access.AccessTokenPayload]
	_previousRefreshToken *jwt.Jwt[refresh.RefreshTokenPayload]

	_tokensCreationHandler *TokensCreationCommandHandler
	_createdPairOfTokens   *TokensCreationResult

	_user *users.User
}

// Обработать команду на обновление аутентификации пользователя.
func (s *RefreshCommandHandler) Handle() *RefreshResult {
	s.validateCommand()

	s.deletePreviousAuth()

	s.notifyUserIfAddressIsDifferent()

	return s.result()
}

// 1-й уровень абстракции.

func (s *RefreshCommandHandler) validateCommand() {
	s.panicIfTokensHaveDifferentIds()
	s.panicIfRefreshTokenHasExpired()
	s.validateRefreshTokenBySavedHash()
}

func (s *RefreshCommandHandler) deletePreviousAuth() {
	err := services.AuthsRepository().Delete(s.previousAuth().Id)
	if err != nil {
		panic(err)
	}
}

func (s *RefreshCommandHandler) notifyUserIfAddressIsDifferent() {
	if s.previousAccessToken().Payload.Address != s.Command.UserAddress {
		s.createNotificationCommandHandler().Handle()
	}
}

func (s *RefreshCommandHandler) result() *RefreshResult {
	return &RefreshResult{
		AccessToken:  s.createdPairOfTokens().AccessToken,
		RefreshToken: s.createdPairOfTokens().RefreshToken,
	}
}

// 2-й уровень абстракции.

func (s *RefreshCommandHandler) panicIfTokensHaveDifferentIds() {
	if s.previousAccessToken().Payload.Id != s.previousRefreshToken().Payload.Id {
		panic(fmt.Errorf("tokens have different ids"))
	}
}

func (s *RefreshCommandHandler) panicIfRefreshTokenHasExpired() {
	if s.previousRefreshToken().Payload.ExpirationTime < time.Now().Unix() {
		panic(fmt.Errorf("REFRESH token has expired"))
	}
}

func (s *RefreshCommandHandler) validateRefreshTokenBySavedHash() {
	err := bcrypt.CompareHashAndPassword([]byte(s.previousAuth().RefreshTokenHash), s.encodedPreviousRefreshTokenBytesForBcrypt())
	if err != nil {
		panic(fmt.Errorf("REFRESH token does not match the token stored in the database"))
	}
}

func (s *RefreshCommandHandler) previousAuth() *auths.Auth {
	if s._previousAuth == nil {
		s._previousAuth = s.getPreviousAuth()
	}

	return s._previousAuth
}

func (s *RefreshCommandHandler) createdPairOfTokens() *TokensCreationResult {
	if s._createdPairOfTokens == nil {
		s._createdPairOfTokens = s.createPairOfTokens()
	}

	return s._createdPairOfTokens
}

func (s *RefreshCommandHandler) createNotificationCommandHandler() *NotificationCommandHandler {
	return &NotificationCommandHandler{
		Command: &NotificationCommand{
			ReceiverEmail:  s.user().Email,
			MessageSubject: "(shumilija/goauth) WARNING",
			MessageBody:    "Выполнена аутентификация по REFRESH токену. ID адрес: " + s.Command.UserAddress,
		},
	}
}

// 3-й уровень абстракции.

func (s *RefreshCommandHandler) getPreviousAuth() *auths.Auth {
	previousAuth, err := services.AuthsRepository().Get(s.previousRefreshToken().Payload.Id)
	if err != nil {
		panic(err)
	}

	return previousAuth
}

func (s *RefreshCommandHandler) previousRefreshToken() *jwt.Jwt[refresh.RefreshTokenPayload] {
	if s._previousRefreshToken == nil {
		s._previousRefreshToken = s.decodePreviousRefreshToken()
	}

	return s._previousRefreshToken
}

func (s *RefreshCommandHandler) encodedPreviousRefreshTokenBytesForBcrypt() []byte {
	return []byte(s.Command.RefreshToken)[:MAX_BYTES_IN_VALUE_FOR_BCRYPT]
}

func (s *RefreshCommandHandler) createPairOfTokens() *TokensCreationResult {
	return s.tokenCreationHandler().Handle()
}

func (s *RefreshCommandHandler) user() *users.User {
	if s._user == nil {
		s._user = s.getUser()
	}

	return s._user
}

// 4-й уровень абстракции.

func (s *RefreshCommandHandler) decodePreviousRefreshToken() *jwt.Jwt[refresh.RefreshTokenPayload] {
	decodedPreviousRefreshToken, err := services.RefreshTokenIssuer().Decode(s.Command.RefreshToken)
	if err != nil {
		panic(err)
	}

	return decodedPreviousRefreshToken
}

func (s *RefreshCommandHandler) tokenCreationHandler() *TokensCreationCommandHandler {
	if s._tokensCreationHandler == nil {
		s._tokensCreationHandler = s.createTokenCreationHandler()
	}

	return s._tokensCreationHandler
}

func (s *RefreshCommandHandler) getUser() *users.User {
	user, err := services.UsersRepository().Get(s.previousAccessToken().Payload.Subject)
	if err != nil {
		panic(err)
	}

	return user
}

// 5-й уровень абстракции.

func (s *RefreshCommandHandler) createTokenCreationHandler() *TokensCreationCommandHandler {
	tokenCreationHandler := TokensCreationCommandHandler{
		Command: &TokensCreationCommand{
			UserId:      s.previousAccessToken().Payload.Subject,
			UserAddress: s.Command.UserAddress,
		},
	}

	return &tokenCreationHandler
}

// 6-й уровень абстракции.

func (s *RefreshCommandHandler) previousAccessToken() *jwt.Jwt[access.AccessTokenPayload] {
	if s._previousAccessToken == nil {
		s._previousAccessToken = s.decodePreviousAccessToken()
	}

	return s._previousAccessToken
}

// 7-й уровень абстракции.

func (s *RefreshCommandHandler) decodePreviousAccessToken() *jwt.Jwt[access.AccessTokenPayload] {
	decodedPreviousAccessToken, err := services.AccessTokenIssuer().Decode(s.Command.AccessToken)
	if err != nil {
		panic(err)
	}

	return decodedPreviousAccessToken
}
