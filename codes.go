package yandexauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// Приложение запрашивает два кода — device_code для устройства и user_code для пользователя.
//
// Время жизни предоставленных кодов — 10 минут. По истечении этого времени коды нужно запросить заново.
//
// https://yandex.ru/dev/id/doc/dg/oauth/reference/simple-input-client.html#simple-input-client__get-codes
func sendConfirmationCodes(
	ctx context.Context,
	client *http.Client,
	clientID,
	deviceID,
	deviceName string) (*confirmationCodesResponse, error) {

	codes := &confirmationCodesResponse{}
	tokensErr := &TokensError{}

	vals := url.Values{}
	vals.Set("client_id", clientID)
	vals.Set("device_id", deviceID)
	vals.Set("device_name", deviceName)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, _codeEndpoint, strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode <= 399 {
		if err = json.NewDecoder(resp.Body).Decode(codes); err != nil {
			return nil, err
		}
		return codes, err
	}

	if err = json.NewDecoder(resp.Body).Decode(tokensErr); err != nil {
		return nil, err
	}
	return codes, tokensErr
}

// Яндекс.OAuth возвращает код для пользователя и информацию для запроса токена.
type confirmationCodesResponse struct {
	// Код, с которым следует запрашивать OAuth-токен на следующем шаге.
	DeviceCode string `json:"device_code"`

	// Код, который должен ввести пользователь, чтобы разрешить доступ к своим данным.
	UserCode string `json:"user_code"`

	// Адрес страницы, на которой пользователь должен ввести код из свойства user_code.
	VerificationUrl string `json:"verification_url"`

	// Минимальный интервал, с которым приложение должно запрашивать OAuth-токен.
	// Если запросы будут приходить чаще, Яндекс.OAuth может ответить ошибкой.
	Interval int64 `json:"interval"`

	// Срок действия пары кодов.
	// По истечению этого срока получить токен для них будет невозможно — нужно будет начать процедуру сначала.
	ExpiresIn int64 `json:"expires_in"`
}
