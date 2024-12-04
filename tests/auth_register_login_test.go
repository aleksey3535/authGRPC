package tests

import (
	"github.com/aleksey3535/authGRPC/tests/suite"
	"testing"
	"time"

	"github.com/aleksey3535/protos/gen/go/auth"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emptyAppID     = 0
	appID          = 2
	appSecret      = "qwerty"
	passDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	pass := randomFakePassword()
	respReg, err := st.AuthClient.Register(ctx, &auth.RegisterRequest{
		Email: email,
		Pasword: pass,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())
	respLogin, err := st.AuthClient.Login(ctx, &auth.LoginRequest{
		Email: email,
		Password: pass,
		AppId: appID,
	})
	loginTime := time.Now() 
	require.NoError(t, err)
	token := respLogin.GetToken()
	require.NotEmpty(t, token)
	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token)(interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)
	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	const deltaSeconds = 1

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
}

func TestRegisterLogin_DuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	pass := randomFakePassword()
	respReq, err := st.AuthClient.Register(ctx, &auth.RegisterRequest{
		Email: email,
		Pasword: pass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReq.GetUserId())
	respReq, err = st.AuthClient.Register(ctx, &auth.RegisterRequest{
		Email: email,
		Pasword: pass,
	})
	require.Error(t, err)
	assert.Empty(t, respReq.GetUserId())
	assert.ErrorContains(t, err, "user already exists")
}

func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)
	tests := []struct {
		name		string
		email 		string
		password	string
		expectedErr string
	}{
		{
		name:			"Register with Empty Password",
		email:			gofakeit.Email(),
		password:		"",
		expectedErr:	"password is required",
		},
		{
		name:			"Register with Empty Email",
		email:			"",
		password:		randomFakePassword(),
		expectedErr: 	"email is required",
		},
		{
		name:			"Register with Both Empty",
		email:			"",
		password:		"",
		expectedErr: 	"email is required",	
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &auth.RegisterRequest{
				Email: test.email,
				Pasword: test.password,
			})
			require.Error(t, err)
			require.ErrorContains(t, err, test.expectedErr)
		})
	}
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)
	tests := []struct {
			name		string
			email		string
			password	string
			appID 		int32
			expectedErr string
	} {
		{
			name:		"Login with Empty Password",
			email:		gofakeit.Email(),
			password:	"",
			appID:		appID,
			expectedErr: "password is required",
		},
		{
			name:		"Login with Empty Email",
			email: 		"",
			password:	randomFakePassword(),
			appID: 		appID,
			expectedErr: "email is required",
		},
		{
			name:		"login with Both Empty",
			email:		"",
			password: 	"",
			appID: 		appID,
			expectedErr: "email is required",
		},
		{
			name:		"Login with Non-Matching Password",
			email:		gofakeit.Email(),
			password:	randomFakePassword(),
			appID: 		appID,
			expectedErr: "internal error",
		},
		{
			name:		"Login without appID",
			email:		gofakeit.Email(),
			password: 	randomFakePassword(),
			appID: 		emptyAppID,
			expectedErr: "app id is required",
		},
	}
	for _,test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &auth.RegisterRequest{
				Email: gofakeit.Email(),
				Pasword: randomFakePassword(),
			})
			require.NoError(t, err)
			_, err = st.AuthClient.Login(ctx, &auth.LoginRequest{
				Email: test.email,
				Password: test.password,
				AppId: test.appID,
			})
			require.Error(t, err)
			require.ErrorContains(t, err, test.expectedErr)
		})
	}
}



func randomFakePassword() string {
	return gofakeit.Password(true, true, true,true,  false, passDefaultLen)
}