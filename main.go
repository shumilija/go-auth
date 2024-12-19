package main

import (
	"fmt"
	"goauth/api/errors"
	"goauth/api/login"
	"goauth/api/refresh"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth/login", login.Handle)
	mux.HandleFunc("/auth/refresh", refresh.Handle)

	handler := errors.NewWrapper(mux)

	fmt.Println("::: Сервер запущен по адресу http://localhost:8080")

	http.ListenAndServe(":8080", handler)
}
