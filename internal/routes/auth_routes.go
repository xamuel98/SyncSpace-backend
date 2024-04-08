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
	AUTH.GET("/verify-email", handlers.VerifyEmailVerificationToken())
	AUTH.POST("/resend-verify-email", handlers.ResendEmailVerificationToken())
}
