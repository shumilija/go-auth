package api

import (
	"encoding/json"
	"fmt"
	"goauth/logics"
	"net/http"
	"strconv"
	"strings"
)

// Обработать HTTP запрос для аутентификации пользователя.
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(404)
		return
	}

	userId, err := strconv.Atoi(r.URL.Query().Get("userId"))
	if err != nil {
		panic(err)
	}

	userIp := strings.Split(r.RemoteAddr, ":")[0]

	command := logics.LoginCommand{
		UserId: int32(userId),
		UserIp: userIp,
	}

	handler := logics.LoginCommandHandler{
		Command: &command,
	}

	result := handler.Handle()

	json, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}

	fmt.Fprint(w, string(json))
}
