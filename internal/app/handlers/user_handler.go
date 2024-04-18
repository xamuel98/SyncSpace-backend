package handlers

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xamuel98/syncspace-backend/internal/app/helpers"
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
var FOR_VERIFY_EMAIL string = os.Getenv("FOR_VERIFY_EMAIL")
var FOR_FORGOT_PASSWORD string = os.Getenv("FOR_FORGOT_PASSWORD")

const FAILED_TOKEN_GENERATION_MESSAGE string = "Failed to generate verification token"
const FAILED_TOKEN_STORAGE_MESSAGE string = "Failed to store verification token"

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
		var newUser requests.RegisterUserRequest

		// Bind JSON and validate request
		if err := bindAndValidateUserRequest(ctx, &newUser); err != nil {
			return // Response is handled within the function
		}

		// Check if email exists
		if emailExists, _ := helper.UserEmailExists(newUser.Email); emailExists {
			responses.SendErrorResponse(ctx, http.StatusBadRequest, "BAD_REQUEST", "Email already exists!")
			return
		}

		// Create user and handle errors
		userModel, err := createUserModel(&newUser)
		if err != nil {
			responses.SendErrorResponse(ctx, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", err.Error())
			return
		}

		// Insert userModel into database
		if err := insertUserModel(ctx, userModel); err != nil {
			return // Response is handled within the function
		}

		// Asynchronously handle verification token and email sending
		handleVerificationProcess(ctx, userModel, &newUser)

		// Return user response
		sendUserResponse(ctx, userModel, &newUser)
	}
}

func bindAndValidateUserRequest(ctx *gin.Context, newUser *requests.RegisterUserRequest) error {
	if err := ctx.ShouldBindJSON(newUser); err != nil {
		responses.SendErrorResponse(ctx, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return err
	}

	_, errors_ := validator.ValidateUser(newUser)
	if errors_ != nil {
		// Convert the slice of strings (errors_) into a single string
		errorMessage := strings.Join(errors_, ", ")
		responses.SendErrorResponse(ctx, http.StatusBadRequest, "BAD_REQUEST", errorMessage)
		return errors.New(errorMessage)
	}

	return nil
}

func createUserModel(newUser *requests.RegisterUserRequest) (models.User, error) {
	primitiveID := primitive.NewObjectID().Hex()
	accessToken, refreshToken, _ := helper.GenerateAllTokens(newUser.Email, newUser.FirstName, newUser.LastName, string(newUser.UserType), primitiveID)
	CreatedAt, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	UpdatedAt, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	hashedPassword := HashPassword(newUser.HashedPassword)
	userModel := models.User{
		ID:             primitiveID,
		FirstName:      newUser.FirstName,
		LastName:       newUser.LastName,
		Email:          newUser.Email,
		EmailVerified:  false,
		HashedPassword: hashedPassword,
		UserType:       newUser.UserType,
		Token:          &accessToken,
		RefreshToken:   &refreshToken,
		CreatedAt:      CreatedAt,
		UpdatedAt:      UpdatedAt,
	}
	return userModel, nil
}

func insertUserModel(ctx *gin.Context, userModel models.User) error {
	rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := userCollection.InsertOne(rootContext, userModel)
	if err != nil {
		responses.SendErrorResponse(ctx, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "User was not created")
		return err
	}

	return nil
}

func handleVerificationProcess(ctx *gin.Context, userModel models.User, newUser *requests.RegisterUserRequest) {
	go func() {
		verificationToken, err := utils.GenerateVerificationToken()
		if err != nil {
			log.Printf("Error generating verification token: %v", err)
			return
		}

		if err := helper.StoreVerificationToken(userModel.ID, verificationToken); err != nil {
			log.Printf("Error storing verification token: %v", err)
			return
		}

		if err := service.SendVerificationEmail(FOR_VERIFY_EMAIL, newUser.Email, newUser.FirstName, verificationToken); err != nil {
			log.Printf("Error sending verification email: %v", err)
			return
		}
	}()
}

func sendUserResponse(ctx *gin.Context, userModel models.User, newUser *requests.RegisterUserRequest) {
	userResponse := map[string]interface{}{
		"id":             userModel.ID,
		"first_name":     newUser.FirstName,
		"last_name":      newUser.LastName,
		"email":          newUser.Email,
		"user_type":      newUser.UserType,
		"email_verified": userModel.EmailVerified,
	}
	ctx.IndentedJSON(http.StatusOK, responses.Response{Success: true, Status: "OK", StatusCode: http.StatusOK, Message: "User account created successfully", Data: map[string]interface{}{"data": userResponse}})
}

// VerifyEmailVerificationToken verifies the token sent to the user's email and updates the email_verified flag.
func VerifyEmailVerificationToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token := ctx.Param("token") // Token is sent as a slug
		if token == "" {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Verification token is required"}})
			return
		}

		// Retrieve user ID from the token.
		// Validate the token and extract the user ID.
		userID, err := helper.ValidateVerificationToken(token)
		if err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Invalid or expired token"}})
			return
		}

		// After successfully verifying the token and updating the user's email_verified field
		// Assuming helper.DeleteVerificationToken is a function that deletes the token from the database
		deleteErr := helper.DeleteVerificationToken(token)
		if deleteErr != nil {
			// Handle the error, maybe log it or return an internal server error response
			log.Printf("Failed to delete verification token: %v", deleteErr)
		}

		// Update the user's email_verified field in the database
		filter := bson.M{"_id": userID}
		update := bson.M{"$set": bson.M{"email_verified": true}}

		rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		result, err := userCollection.UpdateOne(rootContext, filter, update)
		if err != nil || result.ModifiedCount == 0 {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to verify email"}})
			return
		}

		ctx.IndentedJSON(http.StatusOK, responses.Response{Success: true, Status: "OK", StatusCode: http.StatusOK, Message: "Email verified successfully"})
	}
}

// ResendEmailVerificationToken resends the email verification token
func ResendEmailVerificationToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Define a struct to parse the request body
		var requestBody requests.EmailRequest

		if err := ctx.ShouldBindJSON(&requestBody); err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": err.Error()}})
			return
		}

		if requestBody.Email == "" {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "User email is required"}})
			return
		}

		// Retrieve the user's details from the database using the provided email
		var user models.User
		filter := bson.M{"email": requestBody.Email}

		rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := userCollection.FindOne(rootContext, filter).Decode(&user)
		if err != nil {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to retrieve user"}})
			return
		}

		// Generate a verification token
		verificationToken, err := utils.GenerateVerificationToken()
		if err != nil {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": FAILED_TOKEN_GENERATION_MESSAGE}})
			return
		}

		// Store the generated verification token in the user object
		go func() {
			if err := helper.StoreVerificationToken(user.ID, verificationToken); err != nil {
				ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": FAILED_TOKEN_STORAGE_MESSAGE}})
				return
			}
		}()

		// Send verification email
		go func() {
			if err := service.SendVerificationEmail(FOR_VERIFY_EMAIL, user.Email, user.FirstName, verificationToken); err != nil {
				ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to send verification email"}})
				return
			}
		}()

		ctx.IndentedJSON(http.StatusOK, responses.Response{Success: true, Status: "OK", StatusCode: http.StatusOK, Message: "Verification email resent successfully"})
	}
}

// LoginUser logs in an existing user in the DB into the system
func LoginUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var user requests.LoginUserRequest // Define a struct to parse the request body
		var foundUser models.User

		if err := ctx.ShouldBindJSON(&user); err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": err.Error()}})
			return
		}

		// Validate if the email and password are in correct format
		_, errors := validator.ValidateUserLogin(&user)
		if errors != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": errors}})
			return
		}

		filter := bson.M{"email": user.Email}

		rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		// Check if a user with the email is already in the database
		err := userCollection.FindOne(rootContext, filter).Decode(&foundUser)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Email or password is incorrect"}})
				return
			}

			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": err}})
			return
		}

		// Verify if the passwords match
		passwordIsValid, err := helpers.VerifyPassword(user.HashedPassword, foundUser.HashedPassword)
		// Password is invalid
		if !passwordIsValid {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": err.Error()}})
			return
		}

		// Email address does not exist
		if foundUser.Email == "" {
			ctx.IndentedJSON(http.StatusNotFound, responses.Response{Success: false, Status: "NOT_FOUND", StatusCode: http.StatusNotFound, Message: "error", Data: map[string]interface{}{"message": "User not found"}})
			return
		}

		// User's Email is yet to be verified
		if !foundUser.EmailVerified {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "User Email is not verified"}})
			return
		}

		// Generate tokens
		token, refreshToken, _ := helper.GenerateAllTokens(foundUser.Email, foundUser.FirstName, foundUser.LastName, string(foundUser.UserType), *&foundUser.ID)
		helper.UpdateAllTokens(token, refreshToken, foundUser.ID)

		err = userCollection.FindOne(rootContext, bson.M{"_id": foundUser.ID}).Decode(&foundUser)
		if err != nil {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": err.Error()}})
			return
		}

		// Explicitly exclude the password from the response
		foundUser.HashedPassword = ""

		// Return logged in user
		ctx.IndentedJSON(http.StatusOK, responses.Response{Success: true, Status: "OK", StatusCode: http.StatusOK, Message: "User login successful", Data: map[string]interface{}{"data": foundUser}})
	}
}

// ForgotPassword sends an existing user ian email to reset their account's password
func ForgotPassword() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var user requests.ForgotPasswordRequest // Define a struct to parse the request body
		var foundUser models.User

		if err := ctx.ShouldBindJSON(&user); err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": err.Error()}})
			return
		}

		// Validate if the email are in correct format
		_, errors := validator.ValidateUserForgotPassword(&user)
		if errors != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": errors}})
			return
		}

		// Check if there's a user with the same email address.
		_, emailExistsError := helper.UserEmailExists(user.Email)
		if emailExistsError != nil {
			log.Panic(emailExistsError)
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": emailExistsError}})
			return
		}

		// Get the user's details from the database using the email
		filter := bson.M{"email": user.Email}

		rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := userCollection.FindOne(rootContext, filter).Decode(&foundUser)
		if err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Failed to get user with email"}})
			return
		}

		// Generate a verification token
		verificationToken, err := utils.GenerateVerificationToken()
		if err != nil {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": FAILED_TOKEN_GENERATION_MESSAGE}})
			return
		}

		// Store the generated verification token in the verificationTokens collection
		go func() {
			if err := helper.StoreVerificationToken(foundUser.ID, verificationToken); err != nil {
				ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": FAILED_TOKEN_STORAGE_MESSAGE}})
				return
			}
		}()

		// Send verification email
		go func() {
			if err := service.SendVerificationEmail(FOR_FORGOT_PASSWORD, foundUser.Email, foundUser.FirstName, verificationToken); err != nil {
				ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to send verification email"}})
				return
			}
		}()

		ctx.IndentedJSON(http.StatusOK, responses.Response{Success: true, Status: "OK", StatusCode: http.StatusOK, Message: "Forgot password verification email sent successfully"})
	}
}

// VerifyForgotPasswordToken verifies the forgot password token sent to the user's email
func VerifyForgotPasswordToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token := ctx.Param("token") // Token is sent as a slug
		if token == "" {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Verification token is required"}})
			return
		}

		// Retrieve user ID from the token.
		// Validate the token and extract the user ID.
		_, err := helper.ValidateVerificationToken(token)
		if err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Invalid or expired token"}})
			return
		}

		ctx.IndentedJSON(http.StatusOK, responses.Response{Success: true, Status: "OK", StatusCode: http.StatusOK, Message: "Token verified successfully. Proceed to reset password."})
	}
}

// ResendForgotPasswordVerificationToken resends the forgot password email verification token
func ResendForgotPasswordVerificationToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Define a struct to parse the request body
		var requestBody requests.EmailRequest

		if err := ctx.ShouldBindJSON(&requestBody); err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": err.Error()}})
			return
		}

		if requestBody.Email == "" {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "User email is required"}})
			return
		}

		// Retrieve the user's details from the database using the provided email
		var user models.User
		filter := bson.M{"email": requestBody.Email}

		rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := userCollection.FindOne(rootContext, filter).Decode(&user)
		if err != nil {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to retrieve user"}})
			return
		}

		// Generate a verification token
		verificationToken, err := utils.GenerateVerificationToken()
		if err != nil {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": FAILED_TOKEN_GENERATION_MESSAGE}})
			return
		}

		// Store the generated verification token in the user object
		go func() {
			if err := helper.StoreVerificationToken(user.ID, verificationToken); err != nil {
				ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": FAILED_TOKEN_STORAGE_MESSAGE}})
				return
			}
		}()

		// Send verification email
		go func() {
			if err := service.SendVerificationEmail(FOR_FORGOT_PASSWORD, user.Email, user.FirstName, verificationToken); err != nil {
				ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to send verification email"}})
				return
			}
		}()

		ctx.IndentedJSON(http.StatusOK, responses.Response{Success: true, Status: "OK", StatusCode: http.StatusOK, Message: "Forgot password verification email resent successfully"})
	}
}

// ResetPassword resets the user's password
func ResetPassword() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Define a struct to parse the request body
		var requestBody requests.ResetPasswordRequest

		if err := ctx.ShouldBindJSON(&requestBody); err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": err.Error()}})
			return
		}

		token := ctx.Param("token")
		if token == "" {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Reset token is required"}})
			return
		}

		userID, err := helper.ValidateVerificationToken(token)
		if err != nil {
			ctx.IndentedJSON(http.StatusBadRequest, responses.Response{Success: false, Status: "BAD_REQUEST", StatusCode: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"message": "Invalid or expired token"}})
			return
		}

		// After successfully verifying the token
		// Deletes the token from the database
		deleteErr := helper.DeleteVerificationToken(token)
		if deleteErr != nil {
			// Handle the error, maybe log it or return an internal server error response
			log.Printf("Failed to delete reset password verification token: %v", deleteErr)
		}

		hashedPassword := HashPassword(requestBody.HashedPassword)
		filter := bson.M{"_id": userID}
		update := bson.M{"$set": bson.M{"password": hashedPassword}}

		rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		result, err := userCollection.UpdateOne(rootContext, filter, update)
		if err != nil || result.ModifiedCount == 0 {
			ctx.IndentedJSON(http.StatusInternalServerError, responses.Response{Success: false, Status: "INTERNAL_SERVER_ERROR", StatusCode: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Failed to reset password"}})
			return
		}

		ctx.IndentedJSON(http.StatusOK, responses.Response{Success: true, Status: "OK", StatusCode: http.StatusOK, Message: "Password reset successful"})
	}
}
