package yandexauth

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/joho/godotenv"
)

func TestNew(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		t.Fatalf("load env: %s", err.Error())
	}

	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	login := os.Getenv("LOGIN")
	hostname := os.Getenv("HOSTNAME")

	token, err := New(context.Background(), clientID, clientSecret, login, hostname, func(url, code string) {
		fmt.Printf("go to %s and type %s", url, code)
	})

	if err != nil {
		t.Fatalf("new: %s", err.Error())
	}

	if len(token.AccessToken) == 0 ||
		len(token.TokenType) == 0 ||
		len(token.RefreshToken) == 0 || token.Expiry.Unix() == 0 {
		t.Fatalf("invalid token")
	}
}

func TestRefresh(t *testing.T) {
	if err := godotenv.Load(); err != nil {
		t.Fatalf("load env: %s", err.Error())
	}

	refreshToken := os.Getenv("REFRESH_TOKEN")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	refreshed, err := Refresh(context.Background(), refreshToken, clientID, clientSecret)
	if err != nil {
		t.Fatalf(err.Error())
	}
	fmt.Printf("%s", refreshed.TokenType)
}
