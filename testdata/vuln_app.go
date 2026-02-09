package main

import (
	"database/sql"
	"fmt"
)

func getUser(db *sql.DB, name string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	db.Exec(query)
}
