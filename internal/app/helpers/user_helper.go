package helpers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/xamuel98/syncspace-backend/internal/database"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type SignedDetails struct {
	FirstName string
	LastName  string
	Email     string
	UserType  string
	ID        string
	jwt.RegisteredClaims
}

var userCollection *mongo.Collection

func init() {
	var err error
	userCollection, err = database.OpenCollection(database.Client, "users")
	if err != nil {
		log.Fatalf("Failed to open collection: %v", err)
	}
}

var SECRET_KEY = os.Getenv("SECRET_KEY")

// Handle matching of user type to user `role`
func CheckUserType(ctx *gin.Context, role string) (err error) {
	userType := ctx.GetString("user_type")
	err = nil

	if userType != role {
		err = errors.New("Unauthorized to access this resource.")
		return err
	}

	return err
}

// Handle verification of user type to user_id matching
func MatchUserTypeToUid(ctx *gin.Context, userId string) (err error) {
	userType := ctx.GetString("user_type")
	uid := ctx.GetString("uid")
	err = nil

	if userType == "USER" && uid != userId {
		err = errors.New("Unauthorized to access this resource.")
		return err
	}

	err = CheckUserType(ctx, userType)
	return err
}

// Handle the generation and refresh of token & refreshToken using JWT
func GenerateAllTokens(emailAddress, firstName, lastName, userType, userId string) (signedToken, signedRefreshToken string, err error) {
	nowTime := time.Now()
	expireTokenTime := nowTime.Local().Add(time.Hour * time.Duration(24)).Unix()
	expireRefreshTokenTime := nowTime.Local().Add(time.Hour * time.Duration(168)).Unix()

	claims := &SignedDetails{
		Email:     emailAddress,
		FirstName: firstName,
		LastName:  lastName,
		UserType:  userType,
		ID:        userId,
		RegisteredClaims: jwt.RegisteredClaims{
			// Use time.Unix to convert Unix timestamp value in int64 (expireTokenTime) to a time.Time value
			ExpiresAt: jwt.NewNumericDate(time.Unix(expireTokenTime, 0)),
		},
	}

	refreshClaims := &SignedDetails{
		RegisteredClaims: jwt.RegisteredClaims{
			// Use time.Unix to convert Unix timestamp value in int64 (expireRefreshTokenTime) to a time.Time value
			ExpiresAt: jwt.NewNumericDate(time.Unix(expireRefreshTokenTime, 0)),
		},
	}

	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenClaims.SignedString([]byte(SECRET_KEY))

	refreshTokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err := refreshTokenClaims.SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}

	return token, refreshToken, err
}

// Handles token validation
func ValidateToken(signedToken string) (claims *SignedDetails, msg string) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)

	if err != nil {
		msg = err.Error()
		return
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = fmt.Sprintf("The token is invalid")
		msg = err.Error()
		return
	}

	if claims.ExpiresAt != nil {
		expireTime := (*claims.ExpiresAt).Time

		if expireTime.Before(time.Now().Local()) {
			msg = fmt.Sprintf("Token is expired")
			msg = err.Error()
			return
		}
	}

	return claims, msg
}

// Handles token update
func UpdateAllTokens(signedToken, signedRefreshToken, userId string) {
	var updateObj primitive.D

	updateObj = append(updateObj, bson.E{Key: "token", Value: signedToken})
	updateObj = append(updateObj, bson.E{Key: "refresh_token", Value: signedRefreshToken})

	UpdatedAt, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{Key: "updated_at", Value: UpdatedAt})

	upsert := true
	filter := bson.M{"_id": userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	update := bson.D{{Key: "$set", Value: updateObj}}

	_, err := userCollection.UpdateOne(
		context.Background(),
		filter,
		update,
		&opt,
	)
	if err != nil {
		log.Panic(err)
		return
	}

	return
}

// UserEmailExists checks if the email address exists in the database.
func UserEmailExists(email string) (exists bool, err error) {
	count, err := userCollection.CountDocuments(context.Background(), bson.M{"email": email})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Update the user document in MongoDB to include the verification token.
func StoreVerificationToken(userId, verificationToken string) error {
	filter := bson.M{"_id": userId}
	update := bson.M{"$set": bson.M{"verification_token": verificationToken}}

	_, err := userCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		log.Printf("Failed to store verification token for user %s: %v", userId, err)
		return err
	}

	return nil
}
