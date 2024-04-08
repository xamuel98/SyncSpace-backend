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
	"github.com/xamuel98/syncspace-backend/internal/requests"
	"github.com/xamuel98/syncspace-backend/internal/responses"
	"github.com/xamuel98/syncspace-backend/internal/service"
	"github.com/xamuel98/syncspace-backend/internal/utils"
	validator "github.com/xamuel98/syncspace-backend/internal/utils"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
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

// RegisterUser creates a new user and adds the user to the DB
func RegisterUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Define a struct to parse the request body
		var newUser requests.RegisterUserRequest
		var userModel models.User // User model

		if err := ctx.ShouldBindJSON(&newUser); err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": err.Error()}})
			return
		}

		// validate if the email, firstname, lastname, userType, and password are in correct format
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

		// Create the user object
		userModel.ID = primitive.NewObjectID().Hex()
		userModel.FirstName = newUser.FirstName
		userModel.LastName = newUser.LastName
		userModel.Email = newUser.Email
		userModel.EmailVerified = false
		userModel.HashedPassword = string(hashedPassword)
		userModel.UserType = newUser.UserType
		accessToken, refreshToken, _ := helper.GenerateAllTokens(newUser.Email, newUser.FirstName, newUser.LastName, string(newUser.UserType), userModel.ID)
		userModel.Token = &accessToken
		userModel.RefreshToken = &refreshToken
		userModel.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		userModel.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		// Insert userModel into database
		_, insertErr := userCollection.InsertOne(rootContext, userModel)

		if insertErr != nil {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "User was not created"}})
			return
		}

		// Store the generated verification token in the user object
		go func() {
			if err := helper.StoreVerificationToken(userModel.ID, verificationToken); err != nil {
				ctx.JSON(http.StatusInternalServerError, responses.Response{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to store verification token"}})
				return
			}
		}()

		// Send verification email
		go func() {
			if err := service.SendVerificationEmail(newUser.Email, newUser.FirstName, verificationToken); err != nil {
				ctx.JSON(http.StatusInternalServerError, responses.Response{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to send verification email"}})
				return
			}
		}()

		// Return user
		userResponse := map[string]interface{}{
			"id":                userModel.ID,
			"first_name":        newUser.FirstName,
			"last_name":         newUser.LastName,
			"email":             newUser.Email,
			"user_type":         newUser.UserType,
			"email_verified":    userModel.EmailVerified,
			"profile_photo_url": userModel.ProfilePhotoURL,
			"access_token":      accessToken,
			"refresh_token":     refreshToken,
		}

		ctx.IndentedJSON(http.StatusOK, responses.Response{Data: map[string]interface{}{"data": userResponse}})
	}
}

// VerifyEmailVerificationToken verifies the token sent to the user's email and updates the email_verified flag.
func VerifyEmailVerificationToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token := ctx.Query("token") // Token is sent as a query parameter
		if token == "" {
			ctx.JSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Verification token is required"}})
			return
		}

		// Retrieve user ID from the token.
		// Validate the token and extract the user ID.
		userID, err := helper.ValidateVerificationToken(token)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Invalid or expired token"}})
			return
		}

		// Update the user's email_verified field in the database
		filter := bson.M{"_id": userID}
		update := bson.M{"$set": bson.M{"email_verified": true}}

		rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		result, err := userCollection.UpdateOne(rootContext, filter, update)
		if err != nil || result.ModifiedCount == 0 {
			ctx.JSON(http.StatusInternalServerError, responses.Response{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to verify email"}})
			return
		}

		ctx.JSON(http.StatusOK, responses.Response{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"message": "Email verified successfully"}})
	}
}

// ResendEmailVerificationToken resends the email verification token
func ResendEmailVerificationToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Define a struct to parse the request body
		var requestBody requests.EmailRequest

		if err := ctx.ShouldBindJSON(&requestBody); err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": err.Error()}})
			return
		}

		if requestBody.Email == "" {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "User email is required"}})
			return
		}

		// Retrieve the user's details from the database using the provided email
		var user models.User
		filter := bson.M{"email": requestBody.Email}

		rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := userCollection.FindOne(rootContext, filter).Decode(&user)
		if err != nil {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to retrieve user"}})
			return
		}

		// Generate a verification token
		verificationToken, err := utils.GenerateVerificationToken()
		if err != nil {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to generate verification token"}})
			return
		}

		// Store the generated verification token in the user object
		go func() {
			if err := helper.StoreVerificationToken(user.ID, verificationToken); err != nil {
				ctx.JSON(http.StatusInternalServerError, responses.Response{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to store verification token"}})
				return
			}
		}()

		// Send verification email
		go func() {
			if err := service.SendVerificationEmail(user.Email, user.FirstName, verificationToken); err != nil {
				ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to send verification email"}})
				return
			}
		}()

		ctx.IndentedJSON(http.StatusOK, responses.Response{Status: http.StatusOK, Data: map[string]interface{}{"message": "Verification email resent successfully"}})
	}
}

func LoginUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {

	}
}
