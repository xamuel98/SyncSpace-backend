package routes

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	handlers "github.com/xamuel98/syncspace-backend/internal/app/handlers"
)

func AuthRoutes(router *gin.Engine) {
	API_VERSION_URL := os.Getenv("API_VERSION_URL")

	if API_VERSION_URL == "" {
		log.Fatal("You must set your 'API_VERSION_URL' environment variable.")
	}

	// All routes related to AUTH comes here
	AUTH := router.Group("/auth/" + API_VERSION_URL)

	// Define endpoints for authentication
	AUTH.POST("/register", handlers.RegisterUser())
	AUTH.POST("/login", handlers.LoginUser())
	AUTH.PUT("/verify-email/:token", handlers.VerifyEmailVerificationToken())
	AUTH.POST("/resend-verification-email", handlers.ResendEmailVerificationToken())
	AUTH.POST("/forgot-password", handlers.ForgotPassword())
	AUTH.PUT("/verify-forgot-password/:token", handlers.VerifyForgotPasswordToken())
	AUTH.POST("/resend-forgot-password-email", handlers.ResendForgotPasswordVerificationToken())
}
