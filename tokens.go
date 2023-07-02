package yandexauth

import (
	"context"
	"errors"
	"time"

	"github.com/oklookat/vantuz"
	"golang.org/x/oauth2"
)

var (
	ErrNilCodes        = errors.New(_errPrefix + "nil codes")
	ErrInvalidGrant    = errors.New(_errPrefix + "incorrect or expired confirmation code")
	ErrBrokenTokensErr = errors.New(_errPrefix + "statusCode != 200, but tokensError is empty (API changed?)")
	ErrBrokenClient    = errors.New(_errPrefix + "broken client_id or client_secret (OAuth App changed?)")
)

const (
	// Пользователь еще не ввел код подтверждения.
	_errAuthorizationPending = "authorization_pending"

	// Приложение с указанным идентификатором (параметр client_id) не найдено или заблокировано.
	//
	// Этот код также возвращается, если в параметре client_secret передан неверный пароль приложения.
	//
	// P.S: в нашем случае эта ошибка может появиться,
	// если Яндекс сменит коды (id, secret) для своего приложения под Windows.
	//
	// В таком случае надо брать в руки анализатор трафика,
	// и идти искать новые коды.
	_errInvalidClient = "invalid_client"

	// Неверный или просроченный код подтверждения.
	_errInvalidGrant = "invalid_grant"
)

type (
	// Если выдать токен не удалось, то ответ содержит описание ошибки.
	tokensError struct {
		// Описание ошибки.
		ErrorDescription string `json:"error_description"`

		// Код ошибки.
		Error string `json:"error"`
	}
)

// Приложение начинает периодически запрашивать OAuth-токен, передавая device_code.
func requestTokens(ctx context.Context, codes *confirmationCodesResponse, clientID, clientSecret string) (*oauth2.Token, error) {
	if codes == nil {
		return nil, ErrNilCodes
	}

	form := map[string]string{
		// Способ запроса OAuth-токена.
		// Если вы используете код подтверждения, укажите значение «authorization_code».
		"grant_type": "device_code",

		// Код подтверждения, полученный от Яндекс.OAuth.
		// Время жизни предоставленного кода — 10 минут. По истечении этого времени код нужно запросить заново.
		"code": codes.DeviceCode,

		"client_id":     clientID,
		"client_secret": clientSecret,
	}

	tokensErr := &tokensError{}

	response := &tokensResponse{}
	request := vantuz.C().R().
		SetFormUrlMap(form).
		SetResult(response).SetError(tokensErr)

	// таймер когда токены истекут.
	expiredDur := time.Duration(codes.ExpiresIn-4) * time.Second
	ctx, cancel := context.WithTimeout(ctx, expiredDur)
	defer cancel()

	// ждем *интервал* перед отправкой нового запроса...
	// (+2 секунды на всякий случай)
	sleepFor := time.Duration(codes.Interval+2) * time.Second
	requestSleep := time.NewTicker(sleepFor)
	defer requestSleep.Stop()

	for {
		select {
		// Cancelled.
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-requestSleep.C:
			resp, err := request.Post(ctx, _tokenEndpoint)
			if err != nil {
				return nil, err
			}

			if resp.IsSuccess() {
				result := newOAuthToken(*response)
				return &result, err
			}

			if len(tokensErr.Error) < 1 {
				// ???
				return nil, ErrBrokenTokensErr
			}

			switch tokensErr.Error {
			default:
				return nil, wrapErrStr(tokensErr.Error)
			case _errAuthorizationPending:
				continue
			case _errInvalidClient:
				return nil, ErrBrokenClient
			case _errInvalidGrant:
				return nil, ErrInvalidGrant
			}
		}
	}
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

	// Это поле не входит в ответ Яндекса.
	//
	// Дата в формате unix.
	// После этой даты надо обновить токены.
	RefreshAfter int64 `json:"refresh_after"`
}

func newOAuthToken(from tokensResponse) oauth2.Token {
	return oauth2.Token{
		AccessToken:  from.AccessToken,
		TokenType:    from.TokenType,
		RefreshToken: from.RefreshToken,
		Expiry:       time.Now().Add(-24 * time.Hour).Add(time.Duration(from.ExpiresIn) * time.Second),
	}
}
