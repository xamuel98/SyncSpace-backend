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

func init() {
	if MAILSLURP_API_KEY == "" {
		log.Fatal("MAILSLURP_API_KEY environment variable is not set")
	}

	if SYNCSPACE_URL == "" {
		log.Fatal("SYNCSPACE_URL environment variable is not set")
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
func SendVerificationEmail(userEmail, firstName, verificationToken string) error {
	client, ctx := getMailSlurpClient()

	// Construct the verification URL with the token
	verificationURL := fmt.Sprintf(SYNCSPACE_URL+"/verify?token=%s", verificationToken)

	// Email subject and body
	subject := "Please verify your email address"
	body := fmt.Sprintf("Hello %s,\n\nPlease verify your email address by clicking on the link below:\n%s\n\nIf you did not request this, please ignore this email.", firstName, verificationURL)
	sendStrategy := "SINGLE_MESSAGE"
	isHTML := false

	// create an inbox we can send email from
	inbox, _, createInboxErrorMsg := client.InboxControllerApi.CreateInbox(ctx, nil)
	if createInboxErrorMsg != nil {
		// Handle the error appropriately
		log.Fatalf("Failed to create inbox: %v", createInboxErrorMsg)
		return createInboxErrorMsg
	}

	// Create the send email options
	sendEmailOptions := mailslurp.SendEmailOptions{
		To:           &[]string{userEmail},
		Subject:      &subject,
		Body:         &body,
		IsHTML:       &isHTML,
		SendStrategy: &sendStrategy, // or use another appropriate send strategy
	}

	// Send the email
	_, sendEmailErrorMsg := client.InboxControllerApi.SendEmail(ctx, inbox.Id, sendEmailOptions)

	if sendEmailErrorMsg != nil {
		return sendEmailErrorMsg
	}

	return nil
}
