package responses

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
