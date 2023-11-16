package yandexauth

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/joho/godotenv"
)

func TestMain(m *testing.M) {
	if err := godotenv.Load(); err != nil {
		panic("load env: " + err.Error())
	}
	code := m.Run()
	os.Exit(code)
}

func TestNew(t *testing.T) {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	token, err := New(context.Background(), clientID, clientSecret, "abcdefg", "testing", func(url, code string) {
		fmt.Printf("URL: %s, CODE: %s", url, code)
	})

	// tokErr := TokensError{}
	// if errors.As(err, &tokErr) {
	// 	tokErr.IsInvalidGrant() = auth expired
	// 	etc...
	// }

	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	if len(token.AccessToken) == 0 ||
		len(token.TokenType) == 0 ||
		len(token.RefreshToken) == 0 || token.Expiry.Unix() == 0 {
		t.Fatalf("invalid token")
	}
}

func TestRefresh(t *testing.T) {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	refreshToken := os.Getenv("REFRESH_TOKEN")

	refreshed, err := Refresh(context.Background(), refreshToken, clientID, clientSecret)
	if err != nil {
		t.Fatalf(err.Error())
	}
	fmt.Printf("%s", refreshed.TokenType)
}
