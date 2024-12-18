package services

import (
	"goauth/data"
	"goauth/data/auths"
	"goauth/data/users"
	"goauth/tokens/access"
	"goauth/tokens/refresh"
)

// Настроенный для приложения издатель ACCESS токенов.
func AccessTokenIssuer() access.Issuer {
	return access.Issuer{
		Name:                   "shumilija/goauth",
		Key:                    "e14kHjK2Qn_o",
		TokenLifeTimeInMinutes: 15,
	}
}

// Настроенный для приложения издатель REFRESH токенов.
func RefreshTokenIssuer() refresh.Issuer {
	return refresh.Issuer{
		Name:                 "shumilija/goauth",
		Key:                  "AvR-HIA5CaUn",
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
		User:     "postgres",
		Password: "admin",
		DbName:   "AUTH",
	}
}
