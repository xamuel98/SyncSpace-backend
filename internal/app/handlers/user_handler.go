package handlers

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	helper "github.com/xamuel98/syncspace-backend/internal/app/helpers"
	database "github.com/xamuel98/syncspace-backend/internal/database"
	models "github.com/xamuel98/syncspace-backend/internal/models"
	"github.com/xamuel98/syncspace-backend/internal/responses"
	validator "github.com/xamuel98/syncspace-backend/internal/utils"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection

func init() {
	var err error
	userCollection, err = database.OpenCollection(database.Client, "users")
	if err != nil {
		log.Fatalf("Failed to open collection: %v", err)
	}
}

var rootContext = context.Background()

// Handle password hashing
func HashPassword(password string) string {
	// GenerateFromPassword returns the bcrypt hash of the password at the given cost.
	// If the cost given is less than MinCost, the cost will be set to DefaultCost
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), rand.Intn(bcrypt.MaxCost-bcrypt.MinCost)+bcrypt.MinCost)
	if err != nil {
		log.Panic(err)
	}

	return string(bytes)
}

// Register new user
func RegisterUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var newUser models.User

		if err := ctx.ShouldBindJSON(&newUser); err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		// validate if the email, username and password are in correct format
		_, errors := validator.ValidateUser(&newUser)

		if errors != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": errors}})
			return
		}

		// Check if there's a user with the same email address.
		emailExists, err := helper.UserEmailExists(newUser.Email)
		if err != nil {
			log.Panic(err)
			ctx.JSON(http.StatusInternalServerError, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": err.Error()}})
			return
		}

		if emailExists {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": "Email already exists!"}})
		}

		// Hash the password with a random salt
		hashedPassword := HashPassword(newUser.HashedPassword)
		newUser.HashedPassword = string(hashedPassword)

		// Create the user object
		newUser.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		newUser.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		newUser.ID = primitive.NewObjectID().Hex()
		accessToken, refreshToken, _ := helper.GenerateAllTokens(newUser.Email, newUser.FirstName, newUser.LastName, string(newUser.UserType), newUser.ID)
		newUser.Token = &accessToken
		newUser.RefreshToken = &refreshToken

		// Insert newUser into database
		_, insertErr := userCollection.InsertOne(rootContext, newUser)

		if insertErr != nil {
			msg := fmt.Sprintf("User was not created")
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": msg}})
			return
		}

		// Return user
		ctx.IndentedJSON(http.StatusOK, responses.Response{Data: map[string]interface{}{"data": map[string]interface{}{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		}}})
	}
}

func LoginUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {

	}
}
