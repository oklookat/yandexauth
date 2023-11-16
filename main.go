package yandexauth

import (
	"context"
	"errors"

	"github.com/oklookat/vantuz"
	"golang.org/x/oauth2"
)

/**
https://yandex.ru/dev/id/doc/ru/codes/screen-code-oauth#simple-input-client__get-codes
**/

const (
	_errPrefix     = "yandexauth: "
	_tokenEndpoint = "https://oauth.yandex.ru/token"
	_codeEndpoint  = "https://oauth.yandex.ru/device/code"
)

var (
	ErrNilOnUrlCode = errors.New(_errPrefix + "nil onUrlCode")
)

// ClientID - ID приложения.
//
// ClientSecret - Secret приложения.
//
// Login - логин / почта на Яндексе.
//
// Hostname - имя устройства (будет отображаться в списке авторизованных устройств).
//
// onUrlCode - перейти по URL Яндекса, войти в аккаунт, ввести код.
// Спустя несколько секунд будут получены токены.
func New(
	ctx context.Context,
	clientID,
	clientSecret,
	login,
	hostname string,
	onUrlCode func(url string, code string)) (*oauth2.Token, error) {

	if onUrlCode == nil {
		return nil, ErrNilOnUrlCode
	}

	// Запрашиваем коды.
	codes, err := sendConfirmationCodes(ctx, clientID, login, hostname)
	if err != nil {
		return nil, err
	}

	// Пользователь идет вводить код на странице Яндекса...
	go onUrlCode(codes.VerificationUrl, codes.UserCode)

	// Проверяем ввод. Если пользователь ввел верный код, выдаем токен.
	return requestTokens(ctx, codes, clientID, clientSecret)
}

// Обновить токены.
//
// https://yandex.ru/dev/id/doc/ru/tokens/refresh-client
func Refresh(ctx context.Context, refreshToken, clientID, clientSecret string) (*oauth2.Token, error) {
	form := map[string]string{
		// Способ запроса OAuth-токена.
		// Если вы используете refresh-токен, укажите значение «refresh_token»
		"grant_type": "refresh_token",

		// Refresh-токен, полученный от Яндекс.OAuth вместе с OAuth-токеном. Время жизни токенов совпадает.
		"refresh_token": refreshToken,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}

	refreshed := &tokensResponse{}
	tokenErr := &tokensError{}
	request := vantuz.C().R().
		SetFormUrlMap(form).
		SetResult(refreshed).SetError(tokenErr)

	resp, err := request.Post(ctx, _tokenEndpoint)
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, wrapErrStr(tokenErr.Error)
	}

	result := newOAuthToken(*refreshed)
	return &result, err
}
