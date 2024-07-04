package yandexauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// https://yandex.ru/dev/id/doc/ru/codes/screen-code-oauth#simple-input-client__get-codes

const (
	_tokenEndpoint = "https://oauth.yandex.ru/token"
	_codeEndpoint  = "https://oauth.yandex.ru/device/code"
)

// clientID: идентификатор приложения. Доступен в свойствах приложения. Чтобы открыть свойства, перейдите в Яндекс OAuth и нажмите на название приложения.
//
// deviceID:
//
// Уникальный идентификатор устройства, для которого запрашивается токен. Чтобы обеспечить уникальность, достаточно один раз сгенерировать UUID и использовать его при каждом запросе нового токена с данного устройства.
//
// Идентификатор должен быть не короче 6 символов и не длиннее 50. Допускается использовать только печатаемые ASCII-символы (с кодами от 32 до 126).
//
// Подробнее о работе с токенами для отдельных устройств читайте на странице Отзыв токена для устройства.
//
// Если параметр device_id передан без параметра device_name, в пользовательском интерфейсе токен будет помечен как выданный для неизвестного устройства.
//
// deviceName:
//
// Имя устройства, которое следует показывать пользователям. Не длиннее 100 символов. Для мобильных устройств рекомендуется передавать имя устройства, заданное пользователем. Если такого имени нет, его можно собрать из модели устройства, названия и версии ОС и т. д. Если параметр device_name передан без параметра device_id, он будет проигнорирован. Яндекс OAuth сможет выдать только обычный токен, не привязанный к устройству.
//
// clientSecret: Секретный ключ. Доступен в свойствах приложения. Чтобы открыть свойства, перейдите в Яндекс OAuth и нажмите на название приложения.
//
// onUrlCode: перейти по URL, войти в аккаунт, ввести код.
// Спустя несколько секунд вернется токен.
func New(
	ctx context.Context,
	client *http.Client,
	clientID, clientSecret, deviceID, deviceName string,
	onUrlCode func(url string, code string),
) (*oauth2.Token, error) {

	if onUrlCode == nil {
		return nil, errors.New("nil onUrlCode")
	}
	if client == nil {
		return nil, errors.New("nil http.Client")
	}

	// Запрашиваем коды.
	codes, err := sendConfirmationCodes(ctx, client, clientID, deviceID, deviceName)
	if err != nil {
		return nil, err
	}

	// Пользователь идет вводить код на странице Яндекса...
	go onUrlCode(codes.VerificationUrl, codes.UserCode)

	// Проверяем ввод. Если пользователь ввел верный код, выдаем токен.
	return requestTokens(ctx, client, codes.DeviceCode, codes.Interval, clientID, clientSecret)
}

// Обновить токены.
//
// https://yandex.ru/dev/id/doc/ru/tokens/refresh-client
func Refresh(ctx context.Context,
	client *http.Client,
	refreshToken,
	clientID,
	clientSecret string) (*oauth2.Token, error) {

	refreshed := &tokensResponse{}
	tokenErr := &TokensError{}

	vals := url.Values{}
	vals.Set("grant_type", "refresh_token")
	vals.Set("refresh_token", refreshToken)
	vals.Set("client_id", clientID)
	vals.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, _tokenEndpoint, strings.NewReader(vals.Encode()))
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
		if err = json.NewDecoder(resp.Body).Decode(refreshed); err != nil {
			return nil, err
		}
		result := newOAuthToken(*refreshed)
		return &result, err
	}

	if err = json.NewDecoder(resp.Body).Decode(tokenErr); err != nil {
		return nil, err
	}

	return nil, tokenErr
}
