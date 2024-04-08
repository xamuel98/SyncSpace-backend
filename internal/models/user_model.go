package models

import (
	"time"
)

// User represents a user in the application.
type User struct {
	ID              string        `json:"id" bson:"_id"` // Unique identifier for the user
	FirstName       string        `json:"first_name" bson:"first_name" validate:"required,min=2,max=255"`
	LastName        string        `json:"last_name" bson:"last_name" validate:"required,min=2,max=255"`
	Email           string        `json:"email" bson:"email" validate:"required,email"`
	EmailVerified   bool          `json:"email_verified" bson:"email_verified"`
	HashedPassword  string        `json:"password,omitempty" bson:"password" validate:"required,min=8"` // Stored hashed password, not returned in API responses
	ProfilePhotoURL string        `json:"profile_photo_url" bson:"profile_photo_url"`
	UserType        UserType      `json:"user_type" bson:"user_type"`           // Enum for user type (Admin, User)
	Status          UserStatus    `json:"status" bson:"status"`                 // Enum for user status (Online, Offline, InACall)
	VideoSettings   VideoSettings `json:"video_settings" bson:"video_settings"` // User's video preferences
	AudioSettings   AudioSettings `json:"audio_settings" bson:"audio_settings"` // User's audio preferences
	CreatedAt       time.Time     `json:"created_at" bson:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at" bson:"updated_at"`
	Token           *string       `json:"token" bson:"token"`
	RefreshToken    *string       `json:"refresh_token" bson:"refresh_token"`
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
	Resolution string `json:"resolution" bson:"resolution"` // e.g., "1080p", "720p"
	FrameRate  int    `json:"frame_rate" bson:"frame_rate"` // Frames per second
}

// AudioSettings stores user preferences for audio.
type AudioSettings struct {
	MicrophoneVolume int  `json:"microphone_volume" bson:"microphone_volume"` // 0-100
	SpeakerVolume    int  `json:"speaker_volume" bson:"speaker_volume"`       // 0-100
	EchoCancellation bool `json:"echo_cancellation" bson:"echo_cancellation"` // Enable or disable echo cancellation
}
