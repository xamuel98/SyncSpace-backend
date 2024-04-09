package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/xamuel98/syncspace-backend/internal/responses"
	routes "github.com/xamuel98/syncspace-backend/internal/routes"
	"github.com/xamuel98/syncspace-backend/middleware"
)

func main() {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Get PORT from .env
	port := os.Getenv("PORT")

	// If PORT is not declared, set to 0.0.0.0:8080
	if port == "" {
		port = "8080"
	}

	// Initialize Gin router
	router := gin.Default()
	router.Use(middleware.CORSMiddleware())
	router.Use(gin.Logger())

	// Use the routes
	routes.AuthRoutes(router)

	// Catch all requests that do not match any of the defined routes
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, responses.Response{Status: http.StatusNotFound, Message: "Page not found"})
	})

	// Catch requests to valid routes but with an unsupported HTTP method
	router.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, responses.Response{Status: http.StatusMethodNotAllowed, Message: "Method not allowed"})
	})

	fmt.Printf("Starting server on port: %v\n", port)

	// Start the server
	router.Run(":" + port) // listen and serve on port
}
