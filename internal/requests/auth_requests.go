package requests

import "github.com/xamuel98/syncspace-backend/internal/models"

// RegisterUserRequest defines the structure for the USER REGISTER request.
type RegisterUserRequest struct {
	FirstName      string          `json:"first_name"`
	LastName       string          `json:"last_name"`
	Email          string          `json:"email"`
	HashedPassword string          `json:"password"`
	UserType       models.UserType `json:"user_type"`
}

// EmailRequest defines the structure for requests that specifically deal with emails.
type EmailRequest struct {
	Email string `json:"email"`
}

// LoginUserRequest defines the structure for the USER LOGIN request.
type LoginUserRequest struct {
	Email          string `json:"email"`
	HashedPassword string `json:"password"`
}

// ForgotPasswordRequest defines the structure for the USER FORGOT PASSWORD request.
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}
