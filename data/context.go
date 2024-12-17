package data

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// Контекст подключения к БД.
type Context struct {
	// Имя пользователя, через которого осуществляется подключение к БД.
	User string

	// Пароль  пользователя.
	Password string

	// Название БД.
	DbName string
}

// Открыть соединение с БД.
func (s Context) Open() (*sql.DB, error) {
	connection := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", s.User, s.Password, s.DbName)
	db, err := sql.Open("postgres", connection)

	if err != nil {
		return nil, err
	}

	return db, nil
}
