package responses

import "github.com/gin-gonic/gin"

type Data map[string]interface{}
type MetaData interface{}

type Response struct {
	Success    bool     `json:"success"`
	Status     string   `json:"status"`
	StatusCode int      `json:"statusCode"`
	Message    string   `json:"message"`
	Data       Data     `json:"data"`
	MetaData   MetaData `json:"meta_data"`
}

// This function abstracts the error response generation.
func SendErrorResponse(ctx *gin.Context, statusCode int, status, message string) {
	ctx.IndentedJSON(statusCode, Response{
		Success: false, Status: status, StatusCode: statusCode, Message: message, Data: map[string]interface{}{"message": message},
	})
}
