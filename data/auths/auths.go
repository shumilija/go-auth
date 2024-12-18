package auths

import (
	"fmt"
	"goauth/data"
)

// Проекция таблицы AUTHS.
type Auth struct {
	// Идентификатор аутентификации пользователя.
	Id int32

	// Идентификатор пользователя, которому была выдана пара токенов.
	UserId int32

	// BCRYPT хэш от REFRESH токена.
	RefreshTokenHash string
}

// Репозиторий таблицы AUTHS.
type Repository struct {
	// Контекст подключения к БД.
	Context data.Context
}

// Получить запись из таблицы AUTHS по идентификатору.
func (s Repository) Get(id int32) (*Auth, error) {
	db, err := s.Context.Open()
	if err != nil {
		return nil, err
	}

	defer db.Close()

	sql := fmt.Sprintf("SELECT * FROM AUTHS WHERE ID = %d", id)

	row := db.QueryRow(sql)

	result := &Auth{}
	err = row.Scan(&result.Id, &result.UserId, &result.RefreshTokenHash)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Удалить из таблицы AUTHS запись с указанным идентификатором.
func (s Repository) Delete(id int32) error {
	db, err := s.Context.Open()
	if err != nil {
		return err
	}

	defer db.Close()

	sql := fmt.Sprintf("DELETE FROM AUTHS WHERE ID = %d", id)

	_, err = db.Exec(sql)
	if err != nil {
		return err
	}

	return nil
}

// Удалить из таблицы AUTHS записи для указанных пользователей
func (s Repository) DeleteByUser(userId int32) error {
	db, err := s.Context.Open()
	if err != nil {
		return err
	}

	defer db.Close()

	sql := fmt.Sprintf("DELETE FROM AUTHS WHERE USER_ID = %d", userId)

	_, err = db.Exec(sql)
	if err != nil {
		return err
	}

	return nil
}

// Создать в таблице AUTHS запись.
func (s Repository) Create(t Auth) (*Auth, error) {
	db, err := s.Context.Open()
	if err != nil {
		return nil, err
	}

	defer db.Close()

	sql := fmt.Sprintf("INSERT INTO AUTHS (USER_ID, REFRESH_TOKEN_HASH) VALUES (%d, '%s') RETURNING *", t.UserId, t.RefreshTokenHash)

	row := db.QueryRow(sql)

	result := &Auth{}
	err = row.Scan(&result.Id, &result.UserId, &result.RefreshTokenHash)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Обновить запись в таблице AUTHS.
func (s Repository) Update(t Auth) error {
	db, err := s.Context.Open()
	if err != nil {
		return err
	}

	defer db.Close()

	sql := fmt.Sprintf("UPDATE AUTHS SET USER_ID = %d, REFRESH_TOKEN_HASH = '%s' WHERE ID = %d", t.UserId, t.RefreshTokenHash, t.Id)

	_, err = db.Exec(sql)
	if err != nil {
		return err
	}

	return nil
}
