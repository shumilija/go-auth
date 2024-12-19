package main

import (
	"fmt"
	"goauth/api"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth/login", api.HandleLogin)
	mux.HandleFunc("/auth/refresh", api.HandleRefresh)

	handler := api.ErrorsHandler(mux)

	fmt.Println("::: Сервер запущен по адресу http://localhost:8080")

	http.ListenAndServe(":8080", handler)
}
