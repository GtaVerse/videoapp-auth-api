package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type User struct {
	ID       int
	Username string
	Password string `json:"-"` 
}

type LoginDTO struct {
	Username string    `json:"username"`
	Password string `json:"password"`
}

func main() {
	
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	sslmode := os.Getenv("DB_SSLMODE")

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Başarıyla veritabanına bağlanıldı!")

	router := mux.NewRouter()

	router.HandleFunc("/auth", login).Methods("POST")

	
	log.Fatal(http.ListenAndServe(":8000", router))
}

func login(w http.ResponseWriter, r *http.Request) {
    var info LoginDTO
    err := json.NewDecoder(r.Body).Decode(&info)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    var user User
    err = db.QueryRow("SELECT id, username, password FROM users WHERE username = $1", info.Username).Scan(&user.ID, &user.Username, &user.Password)
    if err != nil {
        if err == sql.ErrNoRows {
            http.Error(w, "Invalid Username or Password", http.StatusNotFound)
        } else {
            http.Error(w, err.Error(), http.StatusInternalServerError)
        }
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(info.Password))
    if err != nil {
        http.Error(w, "Invalid Username or Password", http.StatusUnauthorized)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}
