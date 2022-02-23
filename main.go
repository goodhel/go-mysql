package main

import (
	"database/sql"
	"fmt"
	"go-api/pkg/database"
	"go-api/pkg/greet"
	"go-api/pkg/routes"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	var err error
	//db, err = sql.Open("mysql", cfg.FormatDSN())
	// db, err = sql.Open("mysql", "root@tcp(127.0.0.1:3306)/recordings")
	database.DB, err = sql.Open("mysql", database.DbURL(database.BuildDBConfig()))
	fmt.Print(greet.Test2)

	if err != nil {
		log.Fatal(err)
	}
	// See "Important settings" section.
	database.DB.SetConnMaxLifetime(time.Minute * 3)
	database.DB.SetMaxOpenConns(10)
	database.DB.SetMaxIdleConns(10)

	defer database.DB.Close()

	// Routes
	routes := routes.Routes()

	routes.Run("localhost:8080")
}
