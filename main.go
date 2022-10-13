package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	portStr, err := requiredEnvVar("PORT")
	if err != nil {
		log.Fatal(err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatal(err)
	}

	hdl, err := newHandler()
	if err != nil {
		log.Fatal(err)
	}

	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.GET("/", hdl.index)

	// Start server
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))
}

type myHandler struct {
	certs map[string]string
	aud   string
}

func newHandler() (*myHandler, error) {
	certs, err := certificates()
	if err != nil {
		return nil, err
	}
	aud, err := audience()
	if err != nil {
		return nil, err
	}
	return &myHandler{certs, aud}, nil
}

const jwtHeader = "X-Goog-IAP-JWT-Assertion"

// Handler
func (h *myHandler) index(c echo.Context) error {
	assertion := c.Request().Header.Get(jwtHeader)
	if assertion == "" {
		return fmt.Errorf("%s header does not exist", jwtHeader)
	}
	email, _, err := validateAssertion(assertion, h.certs, h.aud)
	if err != nil {
		return err
	}
	return c.String(http.StatusOK, "Hello "+email)
}

// validateAssertion validates assertion was signed by Google and returns the
// associated email and userID.
func validateAssertion(assertion string, certs map[string]string, aud string) (email string, userID string, err error) {
	token, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		keyID := token.Header["kid"].(string)

		_, ok := token.Method.(*jwt.SigningMethodECDSA)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %q", token.Header["alg"])
		}

		cert := certs[keyID]
		return jwt.ParseECPublicKeyFromPEM([]byte(cert))
	})

	if err != nil {
		return "", "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", fmt.Errorf("could not extract claims (%T): %+v", token.Claims, token.Claims)
	}

	if claims["aud"].(string) != aud {
		return "", "", fmt.Errorf("mismatched audience. aud field %q does not match %q", claims["aud"], aud)
	}
	return claims["email"].(string), claims["sub"].(string), nil
}

func audience() (string, error) {
	projectNumber, err := metadata.NumericProjectID()
	if err != nil {
		return "", fmt.Errorf("metadata.NumericProjectID failed; %w", err)
	}
	projectID, err := metadata.ProjectID()
	if err != nil {
		return "", fmt.Errorf("metadata.ProjectID failed; %w", err)
	}
	return fmt.Sprintf("/projects/%s/apps/%s/", projectNumber, &projectID), nil
}

func certificates() (map[string]string, error) {
	const url = "https://www.gstatic.com/iap/verify/public_key"
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http.Get failed; %w", err)
	}
	defer resp.Body.Close()
	var certs map[string]string
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&certs); err != nil {
		return nil, fmt.Errorf("json.Decode failed; %w", err)
	}
	return certs, nil
}

func requiredEnvVar(key string) (string, error) {
	val := os.Getenv(key)
	if val == "" {
		return "", fmt.Errorf("you must define %s env var", key)
	}
	return val, nil
}
