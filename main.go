package vkmauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oklookat/vantuz"
	"golang.org/x/oauth2"
)

const (
	_clientId     = "6767438"
	_clientSecret = "ppBOmwQYYOMGulmaiPyK"
	_apiId        = _clientId

	// VK API version?
	_apiVersion = "5.209"

	// VK Music app version?
	_sakVersion = "1.107"
)

const (
	_vkApiUrl                = "https://api.vk.com"
	_vkOAuthUrl              = _vkApiUrl + "/oauth"
	_moosicApiUrl            = "https://api.moosic.io"
	_moosicVkConnectTokenUrl = _moosicApiUrl + "/oauth/vkconnect/vk/token"
)

const (
	_errPrefix = "vkmauth"
)

var (
	_authSupportedWays = authSupportedWaySlice{AuthSupportedWayPush, AuthSupportedWayEmail}
)

// Токен истекает через ~80 дней.
//
// Phone: полный номер телефона VK (+7 и так далее).
//
// Password: пароль от VK.
//
// # onCodeWaiting
//
// На вход приходит CodeSended.
// Поле Current означает куда был отправлен код.
// Поле Resend означает куда можно еще отправить код.
//
// # Чтобы отправить код другим методом
//
// Функция должна вернуть GotCode.
// Либо вы передаете код, либо делаете поле Resend = true,
// чтобы получить код другим методом (см. CodeSended).
// Но перед Resend проверьте, CodeSended.Resend.
// Если поле будет пустым, то код больше некуда отправлять.
func New(
	ctx context.Context,
	phone, password string,
	onCodeWaiting func(by CodeSended) (GotCode, error),
) (*oauth2.Token, error) {

	anTokens, err := getAnonymousToken(ctx)
	if err != nil {
		return nil, err
	}

	var (
		sid     string
		code    string
		valResp *validatePhoneResponse
	)
	resend := true

	for resend {
		valResp, err = validatePhone(ctx, phone, sid, anTokens)
		if err != nil {
			return nil, err
		}
		valRespReal := valResp.Response

		sid = valRespReal.Sid

		sended := CodeSended{
			Current: valRespReal.ValidationType,
			Resend:  valRespReal.ValidationResend,
		}

		gotCode, err := onCodeWaiting(sended)
		if err != nil {
			return nil, err
		}

		resend = gotCode.Resend

		if resend && len(sended.Resend) == 0 {
			return nil, newError("no available resend method", "New()")
		}

		code = gotCode.Code

		if !resend {
			break
		}
	}

	if len(code) == 0 {
		return nil, newError("empty code", "New()")
	}

	conf, err := validatePhoneConfirm(ctx, anTokens.DeviceId, code, phone, anTokens.Token, valResp.Response.Sid)
	if err != nil {
		return nil, err
	}

	silentToken, err := getSilentToken(ctx,
		conf.Response.Sid, phone, password, anTokens.Token,
		anTokens.DeviceId, conf.Response.Profile.Has2Fa)
	if err != nil {
		return nil, err
	}

	silentTokenChecked, err := checkSilentToken(ctx,
		silentToken.SilentToken,
		silentToken.SilentTokenUUID,
		anTokens.Token, anTokens.DeviceId)
	if err != nil {
		return nil, err
	}

	tokensResp, err := getToken(ctx, anTokens.DeviceId,
		silentTokenChecked.SilentTokenUUID, silentTokenChecked.SilentToken)
	if err != nil {
		return nil, err
	}

	tokens := &oauth2.Token{
		TokenType:    "Bearer",
		AccessToken:  tokensResp.AccessToken,
		RefreshToken: tokensResp.RefreshToken,
		// -1 hour for sure.
		Expiry: time.Now().Add(time.Duration(tokensResp.ExpiresIn-3600) * time.Second),
	}

	return tokens, err
}

func getClient() *vantuz.Client {
	cl := vantuz.C()
	cl.SetUserAgent(fmt.Sprintf("SAK_%s(com.uma.musicvk)/6.1.229-10477", _sakVersion))
	return cl
}

type AuthSupportedWay string

func (e AuthSupportedWay) String() string {
	return string(e)
}

const (
	AuthSupportedWayPush  AuthSupportedWay = "push"
	AuthSupportedWayEmail AuthSupportedWay = "email"
	AuthSupportedWaySms   AuthSupportedWay = "sms"
)

type authSupportedWaySlice []AuthSupportedWay

func (e authSupportedWaySlice) ToSlice() []string {
	var result []string
	for _, v := range e {
		result = append(result, v.String())
	}
	return result
}

func (e authSupportedWaySlice) Join(sep string) string {
	return strings.Join(e.ToSlice(), sep)
}

type ResponseWithError struct {
	Errord *struct {
		ErrorCode int    `json:"error_code"`
		ErrorMsg  string `json:"error_msg"`
	} `json:"error"`
}

func (e ResponseWithError) IsError() bool {
	return e.Errord != nil && len(e.Error()) > 0
}

func (e ResponseWithError) Error() string {
	if e.Errord == nil {
		return _errPrefix + ": no error actually (nil Errord)"
	}
	return fmt.Sprintf("%s: %s", _errPrefix, e.Errord.ErrorMsg)
}

type (
	CodeSended struct {
		// Куда отправлен код.
		Current AuthSupportedWay

		// Если делать resend, код будет отправлен туда.
		// Проверяте, не пустая ли строка если будете делать resend.
		Resend AuthSupportedWay
	}

	GotCode struct {
		// Код.
		Code string

		// Получить код другим методом?
		Resend bool
	}
)
