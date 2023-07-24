package vkm2fa

import (
	"context"
	"fmt"
)

func validatePhone(ctx context.Context, phone string, by *anonymousToken) (*validatePhoneResponse, error) {

	form := map[string]string{
		"access_token":   by.Token,
		"device_id":      by.DeviceId,
		"phone":          phone,
		"supported_ways": _authSupportedWays.Join(","),
		"sak_version":    _sakVersion,
		"v":              _apiVersion,
		"api_id":         _apiId,
	}

	// В форме есть еще параметр "sid", куда можно вставить id сессии.
	// То есть по идее можно выполнить запрос без него,
	// получить sid,
	// снова отправить запрос, но уже с sid,
	// и тогда по идее в ответе изменится ValidationResend и ValidationType.
	// Т.е таким образом можно изменять метод доставки кода.

	result := &validatePhoneResponse{}

	cl := getClient()
	resp, err := cl.R().
		SetFormUrlMap(form).
		SetResult(&result).
		Post(ctx, _vkApiUrl+"/method/auth.validatePhone")

	if err != nil {
		return nil, err
	}

	if result.IsError() {
		return nil, result
	}

	if resp.IsError() {
		return nil, newError(fmt.Sprintf("%d", resp.StatusCode), "validatePhone resp.IsError()")
	}

	return result, err
}

type validatePhoneResponse struct {
	ResponseWithError

	Response struct {
		// "general"?
		Type string `json:"type"`
		// Session ID?
		Sid              string `json:"sid"`
		Delay            int    `json:"delay"`
		LibverifySupport bool   `json:"libverify_support"`
		// Type code by this way.
		ValidationType AuthSupportedWay `json:"validation_type"`
		// If resend, code will be resended by this way.
		ValidationResend AuthSupportedWay `json:"validation_resend"`
		CodeLength       int              `json:"code_length"`
	} `json:"response"`
}
