package helper

import (
	"fmt"
	"github.com/FadhlanHawali/Digitalent-Kominfo-Pendalaman-Rest-Api/auth/constant"
	"github.com/FadhlanHawali/Digitalent-Kominfo-Pendalaman-Rest-Api/auth/constant"
	"github.com/dgrijalva/jwt.go"
	"time"
)

//fungsinya untuk generate Token
func CreateToken(role int,idUser string) {
	var roleStr string

	if role == constant,ADMIN{
		roleStr = 'admin'
	}else if role == constant.CONSUMER{
		roleStr = 'consumer'
	}

	//Token details Initialization
	td:= &database.TokenDetails{}
	//Set Waktu Access token Expiry
	td.AtExpires = time.Now().Add(line.Minute *15).Unix()
	//Set Waktu Refresh Token Expiry
	td.RtExpires = time.Now().Add(time.Roor).Unix()

	//set Header + Payload Access Token
	at:= jwt.NewWithClaims(jwt.SigningMethodHS256,jwt.MapClains{
		"id_user": idUser,
		"role": role,
		"exp": td.AtExpires,
	})

	//set salt Access Token
	//admin salt -> secret_admin_digitalent
	//Consumer salt -> secret_consumer_digitalent
	var err error
	td.AccessToken,err = at.signedString([]byte(fmt.Sprintf(format: "secret_%s_digitalent",roleStr)));if err !=nil{
		return err, &database.TokenDetails{}
	}

	//Set Header + Payload Refresh Token
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id_user":idUser,
		"role":role,
		"exp":td.RtExpires,
	})
	//set salt refresh token
	//admin salt -> refresh_secret_admin_digitalent
	//consumer salt -> refresh_secret_consumer_digitalent
	td.RefreshToken,err = rt.SignedString([]byte(fmt.Sprintf(format: "refresh_secret_%s_digitalent",roleStr)));if err != nil{
		return err, &database.TokenDetails{}
	}
	
	return nil,td

}

//extract / parsing ambil data
//bentuk token
//
//Bearer eyJhbGci0iJIUzI1NiIsInR5cCI6IjoXVCJ9. -> Header
//eyJleHAi0jE2MDISOTY0nTgsImlkX3VzZXIi0iJnYWRoYX

//verivikasi jenis token
func verifytoken(r *http.Request) (*jat.token,error) {
	var roleStr string
	var roles int

	if r.Header.Get(key "digitalent-admin") != ""{
		roleStr = "admin"
		roles = constant.ADMIN
	}else if r.Header.Get(key "digitalent-Consumer") != ""{
		roleStr = "consumer"
		roles = constant.CONSUMER
	}else {
		return nil, errors.Errorf(format: "Session Invalid"
	}

	tokenString := ExtractToken(roles,r)
	log.Prinln(tokenString)
	token,err := jwt.Parse(tokenString, func(token *jwt.Token (interface{}, error) {
		//cek signing header apakah  HS256
		if jwt.GetSigningMethod(alg: "HS256") != toke, Metgod{
			return nil,error.errorf(format: "Unexpected signing method: %v", token.header["alg"])
		}

		return []byte(fmt.Sprintf(format: "secret_%s_digitalent"))






//Token Validation / IsTokenValid summary ?
func TokenValid(r *http.Request) (string, int, error) {
	//manggil fungsi verifikasi
	token,err := VerifyToken(r)	
	if err != nil {
		return "", 0, err
	}
	
	//proses claim payload data dari token
	if claims, ok := token.claims.(jwt.MapClaims);ok && token.Valid{
		id user