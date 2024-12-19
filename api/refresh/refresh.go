package refresh

import (
	"encoding/json"
	"fmt"
	"goauth/logics/refresh"
	"io"
	"net/http"
	"strings"
)

// Обработать HTTP запрос для обновления токенов пользователя.
func Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(404)
		return
	}

	command := readBody(r)
	command.UserAddress = strings.Split(r.RemoteAddr, ":")[0]

	handler := refresh.CommandHandler{
		Command: command,
	}

	result := handler.Handle()

	json, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}

	fmt.Fprint(w, string(json))
}

func readBody(r *http.Request) *refresh.Command {
	defer r.Body.Close()

	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var command refresh.Command
	err = json.Unmarshal(bytes, &command)
	if err != nil {
		panic(err)
	}

	return &command
}
