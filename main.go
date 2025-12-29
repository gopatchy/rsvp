package main

import (
	"bufio"
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/api/idtoken"
)

var (
	env       = map[string]string{}
	templates *template.Template
)

func init() {
	f, err := os.Open("secrets.env")
	if err != nil {
		log.Fatal("[ERROR] failed to open secrets.env: ", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}

	templates = template.Must(template.ParseGlob("static/*.html"))
}

func main() {
	http.HandleFunc("/", handleStatic)
	http.HandleFunc("/auth/google/callback", handleGoogleCallback)

	log.Println("server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	name := strings.TrimPrefix(path, "/")

	if strings.HasSuffix(name, ".html") {
		t := templates.Lookup(name)
		if t == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		t.Execute(w, env)
		return
	}

	http.ServeFile(w, r, filepath.Join("static", name))
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	credential := r.FormValue("credential")
	if credential == "" {
		http.Error(w, "missing credential", http.StatusBadRequest)
		return
	}

	payload, err := idtoken.Validate(context.Background(), credential, env["GOOGLE_CLIENT_ID"])
	if err != nil {
		log.Println("[ERROR] failed to validate token:", err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	response := map[string]any{
		"email":   payload.Claims["email"],
		"name":    payload.Claims["name"],
		"picture": payload.Claims["picture"],
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
