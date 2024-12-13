package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"Authorization/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

var users = make(map[string]models.User)

const myMail = "jok0821ccc@gmail.com"
const password = "123456"

func sendVerificationEmail(email, token string) {
	m := gomail.NewMessage()
	m.SetHeader("From", myMail)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Подтверждение электронной почты")
	m.SetBody("text/plain", fmt.Sprintf("Пожалуйста, подтвердите свою учетную запись, перейдя по следующей ссылке: http://localhost:8080/verify/%s", token))

	d := gomail.NewDialer("smtp.gmail.com", 587, myMail, password)

	if err := d.DialAndSend(m); err != nil {
		log.Println("Ошибка отправки письма:", err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(hashedPassword)
	user.IsVerified = false

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 1).Unix(),
	})

	tokenString, _ := token.SignedString([]byte("your_jwt_secret"))
	user.VerificationToken = tokenString

	users[user.Email] = user
	sendVerificationEmail(user.Email, tokenString)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode("Пользователь зарегистрирован. Проверьте свою почту для подтверждения.")
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := mux.Vars(r)["token"]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("your_jwt_secret"), nil
	})
	if err != nil {
		http.Error(w, "Неверный или истекший токен", http.StatusBadRequest)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		email := claims["email"].(string)
		user, exists := users[email]

		if !exists {
			http.Error(w, "Пользователь не найден", http.StatusNotFound)
			return
		}

		user.IsVerified = true
		users[email] = user

		w.Write([]byte("Учетная запись подтверждена!"))
	} else {
		http.Error(w, "Неверный или истекший токен", http.StatusBadRequest)
	}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/verify/{token}", verifyHandler).Methods("GET")

	log.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
