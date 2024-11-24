package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

var jwtKey = []byte("jwt-secret-key") // secret key

var Users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	jsonDecoder := json.NewDecoder(r.Body)

	// Decode request body into the credentials struct
	err := jsonDecoder.Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate credentials
	expectedPassword, ok := Users[creds.Username]
	if !ok || expectedPassword != creds.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set token expiration time
	expirationTime := time.Now().Add(1 * time.Minute)

	// Create claims with username and expiration time
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Generate the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Set the token as a cookie in the response
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

func HandleHome(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Failed to parse cookie", http.StatusBadRequest)
		return
	}

	tokenString := cookie.Value

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			http.Error(w, "Invalid token signature", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Failed to parse token", http.StatusBadRequest)
		return
	}

	if !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("Hello " + claims.Username))
}

func HandleRefresh(w http.ResponseWriter, r *http.Request) {

}

func main() {
	router := mux.NewRouter()

	server := &http.Server{
		Addr:    ":8123",
		Handler: router,
	}

	router.HandleFunc("/login", HandleLogin).Methods("POST")
	router.HandleFunc("/home", HandleHome).Methods("GET")
	router.HandleFunc("/refresh", HandleRefresh)

	log.Println("Starting server on :8123")
	log.Fatal(server.ListenAndServe())
}
