package services

import (
	"goauth/data"
	"goauth/data/auths"
	"goauth/data/users"
	"goauth/secrets"
	"goauth/tokens/access"
	"goauth/tokens/refresh"
)

// Настроенный для приложения издатель ACCESS токенов.
func AccessTokenIssuer() access.Issuer {
	return access.Issuer{
		Name:                   secrets.TOKEN_ISSUER_NAME,
		Key:                    secrets.ACCESS_TOKEN_KEY,
		TokenLifeTimeInMinutes: 15,
	}
}

// Настроенный для приложения издатель REFRESH токенов.
func RefreshTokenIssuer() refresh.Issuer {
	return refresh.Issuer{
		Name:                 secrets.TOKEN_ISSUER_NAME,
		Key:                  secrets.REFRESH_TOKEN_KEY,
		TokenLifeTimeInHours: 24,
	}
}

// Настроенный для приложения репозиторий для таблицы USERS.
func UsersRepository() users.Repository {
	return users.Repository{
		Context: Context(),
	}
}

// Настроенный для приложения репозиторий для таблицы AUTHS.
func AuthsRepository() auths.Repository {
	return auths.Repository{
		Context: Context(),
	}
}

// Настроенный для приложения контекст подключения к БД.
func Context() data.Context {
	return data.Context{
		User:     secrets.DB_USER_NAME,
		Password: secrets.DB_USER_PASSWORD,
		DbName:   secrets.DB_NAME,
	}
}
