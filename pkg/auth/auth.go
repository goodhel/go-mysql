package auth

import (
	"fmt"
	"go-api/pkg/database"
	"go-api/pkg/jwt"
	"net/http"
	"strconv"

	jwt_go "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type CreateUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RefreshToken struct {
	RefreshToken string `json:"refresh_token"`
}

func Login(c *gin.Context) {
	var body CreateUser
	var user User

	// Call BindJson to bind the received JSON to body
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid json provided"})
		return
	}

	// Check user from database
	err := database.DB.QueryRow("SELECT id, username, password FROM auth_user WHERE username = ?", body.Username).Scan(&user.ID, &user.Username, &user.Password)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check Password between input and database
	match := CheckPassHash(body.Password, user.Password)

	if !match {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Wrong Password"})
		return
	}

	token, err := jwt.CreateJwt(user.ID, user.Username)

	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	authErr := jwt.CreateAuth(user.ID, token, &gin.Context{})

	if authErr != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	tokens := map[string]string{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login succesfully", "data": tokens})
}

func Register(c *gin.Context) {
	var body CreateUser

	// Call BindJson to bind the received JSON to body
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid json provided"})
		return
	}

	hash, err := HashPassword(body.Password)

	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Password hashed fail"})
		return
	}

	result, err := database.DB.Exec("INSERT INTO auth_user (username, password) VALUES (?,?)",
		body.Username, hash)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get the last id inserted
	id, err := result.LastInsertId()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error get last id"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Register user successfully", "data": id})
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func CheckPassHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err == nil
}

func Refresh(c *gin.Context) {
	var body RefreshToken

	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid json provided"})
		return
	}

	// Verify Token
	var jwtKeyRefresh = []byte("go-secret-key-refresh")
	token, err := jwt_go.Parse(body.RefreshToken, func(token *jwt_go.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt_go.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKeyRefresh, nil
	})
	//if there is an error, the token must have expired
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token expired"})
		return
	}
	//is token valid?
	if _, ok := token.Claims.(jwt_go.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, err)
		return
	}
	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt_go.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		username, ok := claims["u"].(string) //convert the interface to string
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, err)
			return
		}
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["i"]), 10, 64)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, "Error occurred")
			return
		}
		//Create new pairs of refresh and access tokens
		token, err := jwt.CreateJwt(userId, username)

		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}

		// Delete Old Token
		del, err := database.DB.Exec("DELETE FROM token WHERE user_id = ? AND refresh_token = ?",
			userId, body.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}

		fmt.Print(del)

		authErr := jwt.CreateAuth(userId, token, &gin.Context{})

		if authErr != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}

		tokens := map[string]string{
			"access_token":  token.AccessToken,
			"refresh_token": token.RefreshToken,
		}
		c.JSON(http.StatusCreated, tokens)
	} else {
		c.JSON(http.StatusUnauthorized, "refresh expired")
	}
}
