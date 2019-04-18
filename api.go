package main

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	u "gotest1/mux-go-api/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gamegos/jsend"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"

	"github.com/gorilla/mux"
)

type User struct {
	Id         int
	Userid     int
	Email      string
	Username   string
	Datejoined time.Time
}

// location of the files used for signing and verification
const (
	privKeyPath = "keys/app.rsa" // openssl genrsa -out app.rsa keysize
	pubKeyPath  = "rsa.pub"      // openssl rsa -in app.rsa -pubout > app.rsa.pub
)

func DBconnection() (db *sql.DB) {

	dbDriver := "mysql"
	dbUser := os.Getenv("MYSQL_USER")
	dbPassword := os.Getenv("MYSQL_PASSWORD")
	dbName := os.Getenv("MYSQL_DATABASE")

	// when using containers - no matter what port mysql is mapped to it uses only service name to depend on...
	//db, err := sql.Open(dbDriver, dbUser+":"+dbPassword+"@tcp(mysqlserver:3306)/"+dbName)

	// to test in dev environment
	db, err := sql.Open(dbDriver, dbUser+":"+dbPassword+"@tcp(127.0.0.1:3350)/"+dbName+"?parseTime=true")

	if err != nil {
		log.Println("Connection error")
	}

	return db
}

func Home(w http.ResponseWriter, r *http.Request) {

	fmt.Println(greet)

	db := DBconnection()

	selDB, err := db.Query("SELECT id,userid,email,username,datejoined FROM userid")
	if err != nil {
		panic(err.Error())
	}

	var userid, id int
	var email, username string
	var datejoined time.Time

	res := []User{}

	for selDB.Next() {
		err = selDB.Scan(&id, &userid, &email, &username, &datejoined)
		if err != nil {
			log.Println(err.Error())
		}

		user := User{Id: id,
			Userid:     userid,
			Email:      email,
			Datejoined: datejoined,
			Username:   username}

		res = append(res, user)

		//w.Write([]byte(fmt.Sprintf("Userid : ", userid)))
	}

	json.NewDecoder(r.Body).Decode(&res)

	userJson, err := json.Marshal(res)

	if err != nil {
		panic(err)
	}

	//w.Header().Set("Content-Type", "application/json")
	//w.WriteHeader(http.StatusOK)

	response := make(map[string]interface{})
	tokenHeader := r.Header.Get("Authorization") //Grab the token from the header

	if tokenHeader == "" { //Token is missing, returns with error code 403 Unauthorized
		response = u.Message(false, "Missing auth token")
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		u.Respond(w, response)
		return
	}

	splitted := strings.Split(tokenHeader, " ") //The token normally comes in format `Bearer {token-body}`, we check if the retrieved token matched this requirement
	if len(splitted) != 2 {
		response = u.Message(false, "Invalid/Malformed auth token")
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		u.Respond(w, response)
		return
	}

	//log.Println(os.Getenv("token_password"))

	/* to create tokin
	tkn := &models.Token{UserId: 1000}
	tokenn := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tkn)
	tokenString, _ := tokenn.SignedString([]byte(os.Getenv("token_password")))
	fmt.Println(tokenString)
	*/

	tokenPart := splitted[1] //Grab the token part, what we are truly interested in
	//tk := &models.Token{}

	/*
		token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("token_password")), nil
		})
	*/

	var (
		verifyKey *rsa.PublicKey
	)

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		log.Println(err.Error())
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Println(err.Error())
	}

	//log.Println(verifyKey)
	//log.Println(tokenPart)

	if err != nil { //Malformed token, returns with http code 403 as usual
		log.Println(err.Error())

		response = u.Message(false, "Token is Malformed...")
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		u.Respond(w, response)
		return
	}

	//fmt.Println(tokenPart)

	// validate the token
	token, err := jwt.Parse(tokenPart, func(token *jwt.Token) (interface{}, error) {
		// since we only use the one private key to sign the tokens,
		// we also only use its public counter part to verify
		return verifyKey, nil
	})

	if err != nil {
		response = u.Message(false, err.Error())
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		u.Respond(w, response)
		return
	}

	if !token.Valid { //Token is invalid, maybe not signed on this server
		response = u.Message(false, "Token is not valid.")
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		u.Respond(w, response)
		return
	}

	//Everything went well, proceed with the request and set the caller to the user retrieved from the parsed token
	//fmt.Sprintf("User %", tk.Username) //Useful for monitoring
	//ctx := context.WithValue(r.Context(), "user", tk.UserId)
	//r = r.WithContext(ctx)
	//next.ServeHTTP(w, r) //proceed in the middleware chain!

	log.Println(userJson)
	//w.WriteHeader(http.StatusFound)
	//w.Header().Add("Content-Type", "application/json")

	jsend.Wrap(w).Status(200).Data(res).Send()

	return

	/*
		query := r.URL.Query()
		name := query.Get("name")
		if name == "" {
			name = "Guest"
		}

		log.Printf("Received request for %s\n", name)
	*/

}

func AllNotes(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "All Notes!")
}

func FindNote(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Find Note!")

}

func CreateNote(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Create Note!")
}

func UpdateNote(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Update Note!")
}

func DeleteNote(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Delete Note!")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	e := godotenv.Load() //Load .env file
	if e != nil {
		log.Println(e.Error())
	}

	r := mux.NewRouter()

	r.HandleFunc("/", Home).Methods("GET")
	r.HandleFunc("/notes", AllNotes).Methods("GET")
	r.HandleFunc("/notes", CreateNote).Methods("POST")
	r.HandleFunc("/notes", UpdateNote).Methods("PUT")
	r.HandleFunc("/notes", DeleteNote).Methods("DELETE")
	r.HandleFunc("/notes/{id}", FindNote).Methods("GET")

	srv := &http.Server{
		Handler:      r,
		Addr:         ":" + os.Getenv("WEBSERVER_PORT"),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start Server
	go func() {
		log.Println("Starting Server new")
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// Graceful Shutdown
	waitForShutdown(srv)

}

func waitForShutdown(srv *http.Server) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Block until we receive our signal.
	<-interruptChan

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	srv.Shutdown(ctx)

	log.Println("Shutting down")
	os.Exit(0)
}
