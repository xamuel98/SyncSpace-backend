package handlers

import (
	"context"
	"log"
	"math/rand"
	"net/http"
	"time"

	helper "github.com/xamuel98/syncspace-backend/internal/app/helpers"
	database "github.com/xamuel98/syncspace-backend/internal/database"
	models "github.com/xamuel98/syncspace-backend/internal/models"
	"github.com/xamuel98/syncspace-backend/internal/responses"
	"github.com/xamuel98/syncspace-backend/internal/service"
	"github.com/xamuel98/syncspace-backend/internal/utils"
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
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": err.Error()}})
			return
		}

		// validate if the email, username and password are in correct format
		_, errors := validator.ValidateUser(&newUser)

		if errors != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": errors}})
			return
		}

		// Check if there's a user with the same email address.
		emailExists, emailExistsError := helper.UserEmailExists(newUser.Email)
		if emailExistsError != nil {
			log.Panic(emailExistsError)
			ctx.JSON(http.StatusInternalServerError, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": emailExistsError}})
			return
		}

		if emailExists {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Email already exists!"}})
			return
		}

		// Generate a verification token
		verificationToken, err := utils.GenerateVerificationToken()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, responses.Response{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to generate verification token"}})
			return
		}

		// Hash the password with a random salt
		hashedPassword := HashPassword(newUser.HashedPassword)
		newUser.HashedPassword = string(hashedPassword)

		// Create the user object
		newUser.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		newUser.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		newUser.ID = primitive.NewObjectID().Hex()
		newUser.EmailVerified = false
		accessToken, refreshToken, _ := helper.GenerateAllTokens(newUser.Email, newUser.FirstName, newUser.LastName, string(newUser.UserType), newUser.ID)
		newUser.Token = &accessToken
		newUser.RefreshToken = &refreshToken

		// Insert newUser into database
		_, insertErr := userCollection.InsertOne(rootContext, newUser)

		if insertErr != nil {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "User was not created"}})
			return
		}

		// Store the generated verification token in the user object
		if err := helper.StoreVerificationToken(newUser.ID, verificationToken); err != nil {
			ctx.JSON(http.StatusInternalServerError, responses.Response{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to store verification token"}})
			return
		}

		// Send verification email
		if err := service.SendVerificationEmail(newUser.Email, newUser.FirstName, verificationToken); err != nil {
			ctx.JSON(http.StatusInternalServerError, responses.Response{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to send verification email"}})
			return
		}

		// Return user
		userResponse := map[string]interface{}{
			"id":                newUser.ID,
			"first_name":        newUser.FirstName,
			"last_name":         newUser.LastName,
			"email":             newUser.Email,
			"user_type":         newUser.UserType,
			"email_verified":    newUser.EmailVerified,
			"profile_photo_url": newUser.ProfilePhotoURL,
			"access_token":      accessToken,
			"refresh_token":     refreshToken,
		}

		ctx.IndentedJSON(http.StatusOK, responses.Response{Data: map[string]interface{}{"data": userResponse}})
	}
}

func LoginUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {

	}
}
