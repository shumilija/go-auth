package errors

import (
	"fmt"
	"net/http"
)

// Создать обертку над обработчиком запросов для обработки исключений.
func NewWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			recovered := recover()
			if recovered != nil {
				err, ok := recovered.(error)
				if ok {
					w.WriteHeader(500)
					fmt.Fprint(w, err.Error())
				}
			}
		}()

		next.ServeHTTP(w, r)
	})
}
