package logics

import (
	"goauth/logics/services"
)

// Команда для аутентификации пользователя.
type LoginCommand struct {
	// Идентификатор пользователя, которому требуется выдать пару токенов.
	UserId int32

	// IP адрес пользователя.
	UserIp string
}

// Результат аутентификации пользователя.
type LoginResult struct {
	// ACCESS токен.
	AccessToken string

	// REFRESH токен.
	RefreshToken string
}

// Обработчик команды для аутентификации пользователя.
type LoginCommandHandler struct {
	// Обрабатываемая команда.
	Command *LoginCommand

	_tokensCreationHandler *TokensCreationCommandHandler
	_createdPairOfTokens   *TokensCreationResult
}

// Обработать команду для аутентификации пользователя.
func (s *LoginCommandHandler) Handle() *LoginResult {
	s.panicIfUserDoesNotExist()

	s.deletePreviousAuth()

	return s.result()
}

// 1-й уровень абстракции.

func (s *LoginCommandHandler) panicIfUserDoesNotExist() {
	_, err := services.UsersRepository().Get(s.Command.UserId)
	if err != nil {
		panic(err)
	}
}

func (s *LoginCommandHandler) deletePreviousAuth() {
	err := services.AuthsRepository().DeleteByUser(s.Command.UserId)
	if err != nil {
		panic(err)
	}
}

func (s *LoginCommandHandler) result() *LoginResult {
	return &LoginResult{
		AccessToken:  s.createdPairOfTokens().AccessToken,
		RefreshToken: s.createdPairOfTokens().RefreshToken,
	}
}

// 2-й уровень абстракции.

func (s *LoginCommandHandler) createdPairOfTokens() *TokensCreationResult {
	if s._createdPairOfTokens == nil {
		s._createdPairOfTokens = s.createPairOfTokens()
	}

	return s._createdPairOfTokens
}

// 3-й уровень абстракции.

func (s *LoginCommandHandler) createPairOfTokens() *TokensCreationResult {
	return s.tokenCreationHandler().Handle()
}

// 4-й уровень абстракции.

func (s *LoginCommandHandler) tokenCreationHandler() *TokensCreationCommandHandler {
	if s._tokensCreationHandler == nil {
		s._tokensCreationHandler = s.createTokenCreationHandler()
	}

	return s._tokensCreationHandler
}

// 5-й уровень абстракции.

func (s *LoginCommandHandler) createTokenCreationHandler() *TokensCreationCommandHandler {
	tokenCreationHandler := TokensCreationCommandHandler{
		Command: &TokensCreationCommand{
			UserId: s.Command.UserId,
			UserIp: s.Command.UserIp,
		},
	}

	return &tokenCreationHandler
}
