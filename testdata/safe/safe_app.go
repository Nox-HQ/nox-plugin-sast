package main

import (
	"crypto/sha256"
	"database/sql"
	"net/http"
)

func safeFetch() { _, _ = http.Get("http://internal/reports") } // constant URL

func strongHash(b []byte) [32]byte { return sha256.Sum256(b) } // sha256

func safeQuery(db *sql.DB, name string) {
	db.Exec("SELECT * FROM users WHERE name = $1", name) // parameterized
}
