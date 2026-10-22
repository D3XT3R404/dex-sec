package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func products(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	rows, err := db.Query(fmt.Sprintf("SELECT id, name FROM products WHERE name LIKE '%%%s%%'", term))
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "rows: %v", rows)
}

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("ping", "-c", "1", host).Output()
	fmt.Fprintf(w, "out: %s", out)
}

func main() {
	var db *sql.DB
	http.HandleFunc("/products", products)
	http.HandleFunc("/ping", ping)
	http.ListenAndServe(":8080", nil)
}
