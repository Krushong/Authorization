package models

type User struct {
	Email             string
	Password          string
	IsVerified        bool
	VerificationToken string
}
