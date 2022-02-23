package todo

import (
	"go-api/pkg/database"
	"go-api/pkg/jwt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Todo struct {
	UserID uint64 `json:"user_id"`
	Title  string `json:"title"`
}

func CreateTodo(c *gin.Context) {
	var td Todo

	if err := c.BindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid Json"})
		return
	}

	tokenAuth, err := jwt.ExtracTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	td.UserID = tokenAuth.UserId

	result, err := database.DB.Exec("INSERT INTO todo (user_id, title) VALUES (?,?)",
		td.UserID, td.Title)

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

	c.JSON(http.StatusCreated, gin.H{"message": "Add todo successfully", "data": id})
}
