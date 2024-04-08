package models

import (
	"time"
)

// User represents a user in the application.
type User struct {
	ID              string        `json:"id"bson:"_id"` // Unique identifier for the user
	FirstName       string        `json:"first_name"validate:"required,min=2,max=255"`
	LastName        string        `json:"last_name"validate:"required,min=2,max=255"`
	Email           string        `json:"email"validate:"required,email"`
	EmailVerified   bool          `json:"email_verified"`
	HashedPassword  string        `json:"password,omitempty"bson:"password,omitempty"validate:"required,min=8"` // Stored hashed password, not returned in API responses
	ProfilePhotoURL string        `json:"profile_photo_url"bson:"profile_photo_url,omitempty"`
	UserType        UserType      `json:"user_type"`      // Enum for user type (Admin, User)
	Status          UserStatus    `json:"status"`         // Enum for user status (Online, Offline, InACall)
	VideoSettings   VideoSettings `json:"video_settings"` // User's video preferences
	AudioSettings   AudioSettings `json:"audio_settings"` // User's audio preferences
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
	Token           *string       `json:"token"`
	RefreshToken    *string       `json:"refresh_token"`
}

// UserType defines the role of a user in the video conferencing application.
type UserType string

const (
	ADMIN UserType = "admin"
	USER  UserType = "user"
)

// UserStatus represents the current status of a user.
type UserStatus string

const (
	Online  UserStatus = "online"
	Offline UserStatus = "offline"
	InACall UserStatus = "in_a_call"
)

// VideoSettings stores user preferences for video.
type VideoSettings struct {
	Resolution string `json:"resolution"` // e.g., "1080p", "720p"
	FrameRate  int    `json:"frame_rate"` // Frames per second
}

// AudioSettings stores user preferences for audio.
type AudioSettings struct {
	MicrophoneVolume int  `json:"microphone_volume"` // 0-100
	SpeakerVolume    int  `json:"speaker_volume"`    // 0-100
	EchoCancellation bool `json:"echo_cancellation"` // Enable or disable echo cancellation
}

// Example function to create a new user (simplified and without actual storage logic)
func NewUser(firstName, lastName, email, password string) *User {
	// Here you would hash the password and create the user object
	return &User{
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
		// HashedPassword: hashPassword(password), // Assuming a function that hashes the password
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
