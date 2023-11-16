package yandexauth

import (
	"context"
	"net/url"
	"time"

	"github.com/oklookat/vantuz"
	"golang.org/x/oauth2"
)

// Приложение начинает периодически запрашивать OAuth-токен, передавая device_code.
func requestTokens(ctx context.Context, deviceCode string, interval int64, clientID, clientSecret string) (*oauth2.Token, error) {
	vals := url.Values{}
	vals.Set("grant_type", "device_code")
	vals.Set("code", deviceCode)
	vals.Set("client_id", clientID)
	vals.Set("client_secret", clientSecret)

	tokensErr := &TokensError{}

	response := &tokensResponse{}
	request := vantuz.C().R().
		SetFormUrlValues(vals).
		SetResult(response).SetError(tokensErr)

	sleepFor := time.Duration(interval) * time.Second
	requestSleep := time.NewTicker(sleepFor)
	defer requestSleep.Stop()

	for {
		<-requestSleep.C
		resp, err := request.Post(ctx, _tokenEndpoint)
		if err != nil {
			return nil, err
		}
		if resp.IsSuccess() {
			result := newOAuthToken(*response)
			return &result, err
		}
		if tokensErr.IsAuthorizationPending() {
			continue
		}
		return nil, tokensErr
	}
}

// Если выдать токен не удалось, то ответ содержит описание ошибки.
type TokensError struct {
	// Описание ошибки.
	ErrorDescription string `json:"error_description"`

	// Код ошибки.
	HError string `json:"error"`
}

func (e TokensError) Error() string {
	return e.HError + ": " + e.ErrorDescription
}

// Пользователь еще не ввел код подтверждения.
func (e TokensError) IsAuthorizationPending() bool {
	return e.HError == "authorization_pending"
}

// Приложение с указанным идентификатором (параметр client_id) не найдено или заблокировано.
//
// Этот код также возвращается, если в параметре client_secret передан неверный пароль приложения.
func (e TokensError) IsInvalidClient() bool {
	return e.HError == "invalid_client"
}

// Неверный или просроченный код подтверждения.
func (e TokensError) IsInvalidGrant() bool {
	return e.HError == "invalid_grant"
}

// Яндекс.OAuth возвращает OAuth-токен, refresh-токен и время их жизни в JSON-формате.
//
// https://yandex.ru/dev/id/doc/dg/oauth/reference/simple-input-client.html#simple-input-client__token-body-title
type tokensResponse struct {
	// Тип выданного токена. Всегда принимает значение «bearer».
	TokenType string `json:"token_type"`

	// OAuth-токен с запрошенными правами или с правами, указанными при регистрации приложения.
	AccessToken string `json:"access_token"`

	// Время жизни токена в секундах.
	ExpiresIn int64 `json:"expires_in"`

	// Токен, который можно использовать для продления срока жизни соответствующего OAuth-токена.
	// Время жизни refresh-токена совпадает с временем жизни OAuth-токена.
	RefreshToken string `json:"refresh_token"`
}

func newOAuthToken(from tokensResponse) oauth2.Token {
	return oauth2.Token{
		AccessToken:  from.AccessToken,
		TokenType:    from.TokenType,
		RefreshToken: from.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(from.ExpiresIn) * time.Second),
	}
}
