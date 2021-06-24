package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	userAuth "github.com/stricklerxc/jwt-login-demo/auth"
	"github.com/stricklerxc/jwt-login-demo/jwt"
	"github.com/stricklerxc/jwt-login-demo/mongodb"
)

func helloWorld(w http.ResponseWriter, req *http.Request) {
	err := jwt.ValidateToken(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
	} else {
		fmt.Fprintf(w, "Hello World!\n")
	}
}

func headers(w http.ResponseWriter, req *http.Request) {
	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func login(w http.ResponseWriter, req *http.Request) {
	http.ServeFile(w, req, "./ui/static/html/login.html")
}

func register(w http.ResponseWriter, req *http.Request) {
	http.ServeFile(w, req, "./ui/static/html/register.html")
}

func registerPost(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		log.Fatal(err)
	}
	username := req.Form.Get("username")
	password := req.Form.Get("password")

	err = mongodb.InsertUser(username, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	log.Printf("User %v successfully registered", username)
}

func auth(w http.ResponseWriter, req *http.Request) {
	var authenticated bool
	err := req.ParseForm()
	if err != nil {
		log.Fatal(err)
	}

	username := req.Form.Get("username")
	password := req.Form.Get("password")

	if authenticated = userAuth.Authenticate(username, password); authenticated {
		jwtToken, err := jwt.CreateToken(username, password)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Set-Cookie", "jwt-login="+jwtToken+"; HttpOnly")
		json.NewEncoder(w).Encode(map[string]string{"token": jwtToken})
	} else {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/hello", helloWorld)
	r.HandleFunc("/headers", headers)

	r.HandleFunc("/login", login)
	r.HandleFunc("/auth", auth).Methods("POST")

	r.HandleFunc("/register", register).Methods("GET")
	r.HandleFunc("/register", registerPost).Methods("POST")

	r.PathPrefix("/css/").Handler(http.StripPrefix("/css", http.FileServer(http.Dir("./ui/static/css"))))

	http.ListenAndServe(":8080", r)
}
