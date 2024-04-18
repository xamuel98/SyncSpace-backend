package service

import (
	"context"
	"fmt"
	"log"
	"os"

	mailslurp "github.com/mailslurp/mailslurp-client-go"
)

var MAILSLURP_API_KEY = os.Getenv("MAILSLURP_API_KEY")
var SYNCSPACE_URL = os.Getenv("SYNCSPACE_URL")
var FOR_VERIFY_EMAIL = os.Getenv("FOR_VERIFY_EMAIL")
var FOR_FORGOT_PASSWORD = os.Getenv("FOR_FORGOT_PASSWORD")

func init() {
	if MAILSLURP_API_KEY == "" {
		log.Fatal("MAILSLURP_API_KEY environment variable is not set")
	}

	if SYNCSPACE_URL == "" {
		log.Fatal("SYNCSPACE_URL environment variable is not set")
	}

	if FOR_VERIFY_EMAIL == "" {
		log.Fatal("FOR_VERIFY_EMAIL environment variable is not set")
	}

	if FOR_FORGOT_PASSWORD == "" {
		log.Fatal("FOR_FORGOT_PASSWORD environment variable is not set")
	}
}

func getMailSlurpClient() (*mailslurp.APIClient, context.Context) {
	// Create a context with your api key
	ctx := context.WithValue(context.Background(), mailslurp.ContextAPIKey, mailslurp.APIKey{Key: MAILSLURP_API_KEY})

	// create mailslurp client
	config := mailslurp.NewConfiguration()
	config.AddDefaultHeader("x-api-key", MAILSLURP_API_KEY)

	client := mailslurp.NewAPIClient(config)

	return client, ctx
}

// SendVerificationEmail sends a verification email to the user's email address with a unique verification link.
func SendVerificationEmail(flag, userEmail, firstName, verificationToken string) error {
	client, ctx := getMailSlurpClient()

	var verificationURL string = ""
	var subject string = ""
	var body string = ""
	var sendStrategy string = ""
	var IsHTML bool = false

	if flag == FOR_VERIFY_EMAIL {
		// Construct the verification URL with the token
		verificationURL = fmt.Sprintf(SYNCSPACE_URL+"/verify?token=%s", verificationToken)

		// Email subject and body
		subject = "Please verify your email address"
		body = fmt.Sprintf("<h6>Hello %s,\n\n</h6><br/><p>Please verify your email address by clicking on the link below:\n<a href='%s' target='_blank' rel='noreferrer noopener'>Verify Email</a></p>\n\n<br/><p>If you did not request this, please ignore this email.</p>", firstName, verificationURL)
		sendStrategy = "SINGLE_MESSAGE"
		IsHTML = true
	} else if flag == FOR_FORGOT_PASSWORD {
		// Construct the verification URL with the token
		verificationURL = fmt.Sprintf(SYNCSPACE_URL+"/verify-forgot-password?token=%s", verificationToken)

		// Email subject and body
		subject = "Reset password token"
		body = fmt.Sprintf("<h6>Hello %s,\n\n</h6><br/><p>Please reset your account's password by clicking on the link below:\n<a href='%s' target='_blank' rel='noreferrer noopener'>Reset Password</a></p>\n\n<br/><p>If you did not request this, please ignore this email.</p>", firstName, verificationURL)
		sendStrategy = "SINGLE_MESSAGE"
		IsHTML = true
	}

	// create an inbox we can send email from
	inbox, _, createInboxErrorMsg := client.InboxControllerApi.CreateInbox(ctx, nil)
	if createInboxErrorMsg != nil {
		// Handle the error appropriately
		log.Printf("Failed to create inbox: %v", createInboxErrorMsg)
		return createInboxErrorMsg
	}

	// Create the send email options
	sendEmailOptions := mailslurp.SendEmailOptions{
		To:           &[]string{userEmail},
		Subject:      &subject,
		Body:         &body,
		IsHTML:       &IsHTML,
		SendStrategy: &sendStrategy, // or use another appropriate send strategy
	}

	// Send the email
	_, sendEmailErrorMsg := client.InboxControllerApi.SendEmail(ctx, inbox.Id, sendEmailOptions)

	if sendEmailErrorMsg != nil {
		return sendEmailErrorMsg
	}

	return nil
}
