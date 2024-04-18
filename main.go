package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

type userInfo struct {
	Email string `json:"email"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("")
		os.Exit(1)
	}

	app := fiber.New()

	app.Static("/", "./index.html")

	app.Get("/oauth/google", func(c *fiber.Ctx) error {
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			return c.SendStatus(fiber.ErrFailedDependency.Code)
		}
		state := hex.EncodeToString(bytes)
		queryParams := url.Values{
			"response_type": []string{"code"},
			"client_id":     []string{os.Getenv("CLIENT_ID")},
			"redirect_uri":  []string{"http://localhost:8080/oauth/google/callback"},
			"scope":         []string{"email"},
			"access_type":   []string{"online"},
			"state":         []string{state},
		}

		url := fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?%s", queryParams.Encode())

		c.Cookie(&fiber.Cookie{
			Name:     "oauth_state",
			Value:    state,
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Lax",
		})

		return c.Redirect(url)
	})

	app.Get("/oauth/google/callback", func(c *fiber.Ctx) error {
		oauthState := c.Cookies("oauth_state")
		queries := c.Queries()
		code := queries["code"]
		state := queries["state"]
		if len(code) == 0 || len(state) == 0 || oauthState != state {
			return c.SendStatus(fiber.ErrBadRequest.Code)
		}

		token := getToken(code, c)
		userInfo := getUserInfo(token, c)

		return c.JSON(userInfo)
	})

	app.Listen(":8080")
}

func getToken(code string, c *fiber.Ctx) string {
	fiber.AcquireClient()
	agent := fiber.AcquireAgent()
	req := agent.Request()
	req.Header.SetMethod(fiber.MethodPost)
	req.SetRequestURI("https://oauth2.googleapis.com/token")
	agent = agent.JSON(fiber.Map{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  "http://localhost:8080/oauth/google/callback",
		"client_id":     os.Getenv("CLIENT_ID"),
		"client_secret": os.Getenv("CLIENT_SECRET"),
	})
	if err := agent.Parse(); err != nil {
		panic(err)
	}

	tokenReqOutput := struct {
		AccessToken string `json:"access_token"`
	}{}
	if statusCode, body, errs := agent.Struct(&tokenReqOutput); len(errs) > 0 {
		fmt.Printf("%d\nreceived: %v\n", statusCode, string(body))
		fmt.Printf("could not send HTTP request: %v\n", errs)
		c.SendStatus(fiber.StatusInternalServerError)
	}

	return tokenReqOutput.AccessToken
}

func getUserInfo(token string, c *fiber.Ctx) userInfo {
	agent := fiber.Get("https://www.googleapis.com/oauth2/v2/userinfo").Set("Authorization", fmt.Sprintf("Bearer %s", token))

	var userInfoOutput userInfo
	if statusCode, body, errs := agent.Struct(&userInfoOutput); len(errs) > 0 {
		fmt.Printf("%d\nreceived: %v\n", statusCode, string(body))
		fmt.Printf("could not send HTTP request: %v\n", errs)
		c.SendStatus(fiber.StatusInternalServerError)
	}

	return userInfoOutput
}
