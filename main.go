package yandexauth

import (
	"context"
	"errors"
	"net/url"

	"github.com/oklookat/vantuz"
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
	ctx context.Context, clientID, clientSecret, deviceID, deviceName string,
	onUrlCode func(url string, code string),
) (*oauth2.Token, error) {

	if onUrlCode == nil {
		return nil, errors.New("nil onUrlCode")
	}

	// Запрашиваем коды.
	codes, err := sendConfirmationCodes(ctx, clientID, deviceID, deviceName)
	if err != nil {
		return nil, err
	}

	// Пользователь идет вводить код на странице Яндекса...
	go onUrlCode(codes.VerificationUrl, codes.UserCode)

	// Проверяем ввод. Если пользователь ввел верный код, выдаем токен.
	return requestTokens(ctx, codes.DeviceCode, codes.Interval, clientID, clientSecret)
}

// Обновить токены.
//
// https://yandex.ru/dev/id/doc/ru/tokens/refresh-client
func Refresh(ctx context.Context, refreshToken, clientID, clientSecret string) (*oauth2.Token, error) {
	vals := url.Values{}
	vals.Set("grant_type", "refresh_token")
	vals.Set("refresh_token", refreshToken)
	vals.Set("client_id", clientID)
	vals.Set("client_secret", clientSecret)

	refreshed := &tokensResponse{}
	tokenErr := &TokensError{}
	request := vantuz.C().R().
		SetFormUrlValues(vals).
		SetResult(refreshed).SetError(tokenErr)

	resp, err := request.Post(ctx, _tokenEndpoint)
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, tokenErr
	}

	result := newOAuthToken(*refreshed)
	return &result, err
}
