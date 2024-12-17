package users

import (
	"fmt"
	"goauth/data"
)

// Проекция таблицы USERS.
type User struct {
	// Идентификатор пользователя.
	Id int32

	// Адрес электронной почты пользователя.
	Email string
}

// Репозиторий таблицы USERS.
type Repository struct {
	// Контекст подключения к БД.
	Context data.Context
}

// Получить пользователя по его идентификатору.
func (s Repository) Get(id int32) (*User, error) {
	db, err := s.Context.Open()
	if err != nil {
		return nil, err
	}

	defer db.Close()

	sql := fmt.Sprintf("SELECT * FROM USERS WHERE ID = %d", id)

	row := db.QueryRow(sql)

	result := &User{}
	err = row.Scan(&result.Id, &result.Email)
	if err != nil {
		return nil, err
	}

	return result, nil
}
