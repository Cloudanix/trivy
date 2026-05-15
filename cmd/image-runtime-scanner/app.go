package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	StatusSuccess = "SUCCESS"
	StatusFailure = "FAILURE"
)

type Response struct {
	Status    string `json:"status,omitempty"`
	ErrorCode string `json:"errorCode,omitempty"`
	Message   string `json:"message,omitempty"`
}

func logMessage(msg string) {
	fmt.Println(time.Now().Format("2006-01-02 15:04:05"), "-", msg)
}

func readEnv(envKey, defaultValue string) string {
	val := os.Getenv(envKey)

	if val == "" {
		val = defaultValue
	}

	return val
}

func readRequest(r *http.Request) (ScanConfig, error) {
	// Read the request body as JSON
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return ScanConfig{}, err
	}

	scanConfig := ScanConfig{
		APIEndpoint: os.Getenv("API_ENDPOINT"),
		AuthZToken:  os.Getenv("AUTHZ_TOKEN"),
		Identifier:  os.Getenv("IDENTIFIER"),
		Env:         readEnv("ENV", "LIVE"),
	}
	err = json.Unmarshal(body, &scanConfig)
	if err != nil {
		return ScanConfig{}, err
	}

	// Process the JSON data (for example, print the name and age)
	logMessage(fmt.Sprintf("Received JSON: %+v", scanConfig))

	return scanConfig, nil
}

func sendResponse(w http.ResponseWriter, resp Response) {
	// Convert the response object to JSON
	jsonResp, _ := json.Marshal(resp)

	// Set the Content-Type header to indicate JSON response
	w.Header().Set("Content-Type", "application/json")

	// Write the JSON response to the HTTP response
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResp)
}

func home(w http.ResponseWriter, r *http.Request) {
	logMessage("home - request received")

	// Create a response object
	resp := Response{
		Status:  StatusSuccess,
		Message: "Welcome Home!",
	}

	logMessage("home - sending response")
	sendResponse(w, resp)
}

func scan(w http.ResponseWriter, r *http.Request) {
	logMessage("scan - request received")

	var resp Response

	// Check if the request method is POST
	if r.Method != http.MethodPost {
		resp = Response{
			Status:  StatusFailure,
			Message: "Invalid Request",
		}

		sendResponse(w, resp)
		return
	}

	logMessage("scan - processing input request")
	scanConfig, err := readRequest(r)
	if err != nil {
		resp = Response{
			Status:  StatusFailure,
			Message: err.Error(),
		}

		sendResponse(w, resp)
		return
	}

	logMessage(fmt.Sprintf("%v", scanConfig))

	logMessage("scan - scanning image for vulnerabilities")
	err = scanImage(scanConfig)
	if err != nil {
		resp = Response{
			Status:  StatusFailure,
			Message: err.Error(),
		}

		sendResponse(w, resp)
		return
	} else {
		resp = Response{
			Status:  StatusSuccess,
			Message: "Results Published Successfully!",
		}
	}

	logMessage("scan - sending response")
	sendResponse(w, resp)
}

func updateDB(w http.ResponseWriter, r *http.Request) {
	logMessage("updateDB - request received")

	var resp Response

	logMessage("updateDB - resetting vulnerabilities db")
	scanConfig := ScanConfig{
		ResetDB: true,
	}

	err := scanImage(scanConfig)
	if err != nil {
		resp = Response{
			Status:  StatusFailure,
			Message: err.Error(),
		}

		sendResponse(w, resp)
		return
	}

	// logMessage("updateDB - updating vulnerabilities db")
	// scanConfig = ScanConfig {
	// 	DownloadDB: true,
	// }

	// err = scanImage(scanConfig)
	// if err != nil {
	// 	resp = Response{
	// 		Status:  StatusFailure,
	// 		Message: err.Error(),
	// 	}

	// 	sendResponse(w, resp)
	// 	return
	// }

	resp = Response{
		Status:  StatusSuccess,
		Message: "Vulnerability DB Updated Successfully!",
	}

	logMessage("updateDB - sending response")
	sendResponse(w, resp)
}

func main() {
	if readEnv("ENV", "LIVE") == "DEBUG" {
		// fetch all env variables
		for _, element := range os.Environ() {
			variable := strings.Split(element, "=")
			fmt.Println(variable[0], "=>", variable[1])
		}
	}
	http.HandleFunc("/", home)
	http.HandleFunc("/scan", scan)
	http.HandleFunc("/updatedb", updateDB)

	logMessage("Server is listening on 8080")
	http.ListenAndServe(":8080", nil)
}
