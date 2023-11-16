package yandexauth

import (
	"context"
	"net/url"

	"github.com/oklookat/vantuz"
)

// Приложение запрашивает два кода — device_code для устройства и user_code для пользователя.
//
// Время жизни предоставленных кодов — 10 минут. По истечении этого времени коды нужно запросить заново.
//
// https://yandex.ru/dev/id/doc/dg/oauth/reference/simple-input-client.html#simple-input-client__get-codes
func sendConfirmationCodes(ctx context.Context, clientID, deviceID, deviceName string) (*confirmationCodesResponse, error) {
	vals := url.Values{}
	vals.Set("client_id", clientID)
	vals.Set("device_id", deviceID)
	vals.Set("device_name", deviceName)

	codes := &confirmationCodesResponse{}
	tokensErr := &TokensError{}

	request := vantuz.C().R().
		SetFormUrlValues(vals).
		SetResult(codes).
		SetError(tokensErr)

	resp, err := request.Post(ctx, _codeEndpoint)
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		err = tokensErr
	}

	return codes, err
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
