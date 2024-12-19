package login

import (
	"goauth/logics/services"
	"goauth/logics/tokenCreation"
)

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

	_tokensCreationHandler *tokenCreation.CommandHandler
	_createdPairOfTokens   *tokenCreation.Result
}

// Обработать команду для аутентификации пользователя.
func (s *CommandHandler) Handle() *Result {
	s.panicIfUserDoesNotExist()

	s.deletePreviousAuth()

	return s.result()
}

// 1-й уровень абстракции.

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

func (s *CommandHandler) result() *Result {
	return &Result{
		AccessToken:  s.createdPairOfTokens().AccessToken,
		RefreshToken: s.createdPairOfTokens().RefreshToken,
	}
}

// 2-й уровень абстракции.

func (s *CommandHandler) createdPairOfTokens() *tokenCreation.Result {
	if s._createdPairOfTokens == nil {
		s._createdPairOfTokens = s.createPairOfTokens()
	}

	return s._createdPairOfTokens
}

// 3-й уровень абстракции.

func (s *CommandHandler) createPairOfTokens() *tokenCreation.Result {
	return s.tokenCreationHandler().Handle()
}

// 4-й уровень абстракции.

func (s *CommandHandler) tokenCreationHandler() *tokenCreation.CommandHandler {
	if s._tokensCreationHandler == nil {
		s._tokensCreationHandler = s.createTokenCreationHandler()
	}

	return s._tokensCreationHandler
}

// 5-й уровень абстракции.

func (s *CommandHandler) createTokenCreationHandler() *tokenCreation.CommandHandler {
	tokenCreationHandler := tokenCreation.CommandHandler{
		Command: &tokenCreation.Command{
			UserId:      s.Command.UserId,
			UserAddress: s.Command.UserAddress,
		},
	}

	return &tokenCreationHandler
}
