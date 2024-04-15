package utils

import (
	"regexp"
	"strings"

	valid "github.com/asaskevich/govalidator"
	"github.com/xamuel98/syncspace-backend/internal/requests"
)

// IsEmpty checks if a string is empty
func IsEmpty(str string) (bool, string) {
	// Trim leading and trailing white spaces
	trimmedStr := strings.Trim(str, "")
	if trimmedStr == "" {
		return true, "must not be empty"
	}

	return false, ""
}

// ValidateRegister func validates the body of user for registration
func ValidateUser(newUser *requests.RegisterUserRequest) (bool, []string) {
	var errors []string

	// Validate the user first name
	if isFirstNameEmpty, errMsg := IsEmpty(newUser.FirstName); isFirstNameEmpty {
		errors = append(errors, "First name "+errMsg)
	}

	// Validate the user last name
	if isLastNameEmpty, errMsg := IsEmpty(newUser.LastName); isLastNameEmpty {
		errors = append(errors, "Last name "+errMsg)
	}

	// Validate the user email
	if isEmailEmpty, errMsg := IsEmpty(newUser.Email); isEmailEmpty {
		errors = append(errors, "Email "+errMsg)
	} else if !valid.IsEmail(newUser.Email) {
		errors = append(errors, "Must be a valid email address")
	}

	// Validate the user last name
	if isUserTypeEmpty, errMsg := IsEmpty(string(newUser.UserType)); isUserTypeEmpty {
		errors = append(errors, "User type "+errMsg)
	}

	// Validate the user password
	re := regexp.MustCompile("\\d") // regex check for at least one integer in string

	if isPasswordEmpty, errMsg := IsEmpty(newUser.HashedPassword); isPasswordEmpty {
		errors = append(errors, "Password "+errMsg)
	} else if !(len(newUser.HashedPassword) >= 8 && valid.HasLowerCase(newUser.HashedPassword) && valid.HasUpperCase(newUser.HashedPassword) && re.MatchString(newUser.HashedPassword)) {
		errors = append(errors, "Length of password should be at least 8 and it must be a combination of uppercase letters, lowercase letters and numbers")
	}

	if len(errors) > 0 {
		return false, errors
	}

	return true, nil
}

// ValidateUserLogin func validates the body of user for login
func ValidateUserLogin(existingUser *requests.LoginUserRequest) (bool, []string) {
	var errors []string

	// Validate the user email
	if isEmailEmpty, errMsg := IsEmpty(existingUser.Email); isEmailEmpty {
		errors = append(errors, "Email "+errMsg)
	} else if !valid.IsEmail(existingUser.Email) {
		errors = append(errors, "Must be a valid email address")
	}

	// Validate the user password
	if isPasswordEmpty, errMsg := IsEmpty(existingUser.HashedPassword); isPasswordEmpty {
		errors = append(errors, "Password "+errMsg)
	}

	if len(errors) > 0 {
		return false, errors
	}

	return true, nil
}

// ValidateUserForgotPassword func validates the body of user for forgot password
func ValidateUserForgotPassword(existingUser *requests.ForgotPasswordRequest) (bool, []string) {
	var errors []string

	// Validate the user email
	if isEmailEmpty, errMsg := IsEmpty(existingUser.Email); isEmailEmpty {
		errors = append(errors, "Email "+errMsg)
	} else if !valid.IsEmail(existingUser.Email) {
		errors = append(errors, "Must be a valid email address")
	}

	if len(errors) > 0 {
		return false, errors
	}

	return true, nil
}
