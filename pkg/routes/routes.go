package routes

import (
	"go-api/pkg/auth"
	"go-api/pkg/middleware"
	"go-api/pkg/todo"

	"github.com/gin-gonic/gin"
)

func Routes() *gin.Engine {
	router := gin.Default()

	router.POST("/login", auth.Login)
	router.POST("/register", auth.Register)
	router.POST("/refresh", auth.Refresh)
	router.POST("/todo", middleware.AuthMiddleware(), todo.CreateTodo)

	return router
}
