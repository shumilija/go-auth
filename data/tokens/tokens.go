package tokens

import (
	"fmt"
	"goauth/data"
)

// Проекция таблицы TOKENS.
type Token struct {
	// Идентификатор токена.
	Id int32

	// значение bcrypt хэш-функции, взятое от REFRESH токена.
	EncodedRefresh string
}

// Репозиторий таблицы TOKENS.
type Repository struct {
	// Контекст подключения к БД.
	Context data.Context
}

// Получить запись из таблицы TOKENS по идентификатору.
func (s Repository) Get(id int32) (*Token, error) {
	db, err := s.Context.Open()
	if err != nil {
		return nil, err
	}

	defer db.Close()

	sql := fmt.Sprintf("SELECT * FROM TOKENS WHERE ID = %d", id)

	row := db.QueryRow(sql)

	result := &Token{}
	err = row.Scan(&result.Id, &result.EncodedRefresh)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Удалить из таблицы TOKENS запись с указанным идентификатором.
func (s Repository) Delete(id int32) error {
	db, err := s.Context.Open()
	if err != nil {
		return err
	}

	defer db.Close()

	sql := fmt.Sprintf("DELETE FROM TOKENS WHERE ID = %d", id)

	_, err = db.Exec(sql)
	if err != nil {
		return err
	}

	return nil
}

// Создать в таблице TOKENS запись.
func (s Repository) Create(t Token) (*Token, error) {
	db, err := s.Context.Open()
	if err != nil {
		return nil, err
	}

	defer db.Close()

	sql := fmt.Sprintf("INSERT INTO TOKENS (ENCODED_REFRESH) VALUES ('%s') RETURNING *", t.EncodedRefresh)

	row := db.QueryRow(sql)

	result := &Token{}
	err = row.Scan(&result.Id, &result.EncodedRefresh)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Обновить запись в таблице TOKENS.
func (s Repository) Update(t Token) error {
	db, err := s.Context.Open()
	if err != nil {
		return err
	}

	defer db.Close()

	sql := fmt.Sprintf("UPDATE TOKENS SET ENCODED_REFRESH = '%s' WHERE ID = %d", t.EncodedRefresh, t.Id)

	_, err = db.Exec(sql)
	if err != nil {
		return err
	}

	return nil
}
