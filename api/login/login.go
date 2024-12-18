package login

import (
	"encoding/json"
	"fmt"
	"goauth/logics/login"
	"net/http"
	"strconv"
	"strings"
)

// Обработать HTTP запрос для аутентификации пользователя.
func Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(404)
		return
	}

	userId, err := strconv.Atoi(r.URL.Query().Get("userId"))
	if err != nil {
		panic(err)
	}

	userAddress := strings.Split(r.RemoteAddr, ":")[0]

	command := login.Command{
		UserId:      int32(userId),
		UserAddress: userAddress,
	}

	handler := login.CommandHandler{
		Command: &command,
	}

	result := handler.Handle()

	json, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}

	fmt.Fprint(w, string(json))
}
