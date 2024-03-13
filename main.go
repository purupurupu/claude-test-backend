package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/sirupsen/logrus"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID          string `json:"id" gorm:"primary_key"`
	Name        string `json:"name"`
	Email       string `json:"email" gorm:"unique"`
	Password    string `json:"password"`
	Age         int    `json:"age"`
	Gender      string `json:"gender"`
	Preferences string `json:"preferences"`
	Bio         string `json:"bio"`
	Pictures    string `json:"pictures"`
}

type Match struct {
	ID        string `json:"id" gorm:"primary_key"`
	UserID    string `json:"user_id"`
	MatchedID string `json:"matched_id"`
}

type Message struct {
	ID         string    `json:"id" gorm:"primary_key"`
	SenderID   string    `json:"sender_id"`
	ReceiverID string    `json:"receiver_id"`
	Content    string    `json:"content"`
	Timestamp  time.Time `json:"timestamp"`
}

var db *gorm.DB
var jwtKey = []byte("secret_key")

func init() {
	var err error
	db, err = gorm.Open("postgres", "host=localhost port=5432 user=gorm dbname=gorm password=gorm sslmode=disable")
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &Match{}, &Message{})
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" || user.Password == "" {
		http.Error(w, "Email and Password are required", http.StatusBadRequest)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(hashedPassword)

	if err := db.Create(&user).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(user)
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)

	var foundUser User
	if err := db.Where("email = ?", user.Email).First(&foundUser).Error; err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(user.Password)); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": foundUser.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	db.Find(&users)
	json.NewEncoder(w).Encode(users)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["id"]

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["id"]

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewDecoder(r.Body).Decode(&user)
	db.Save(&user)

	json.NewEncoder(w).Encode(user)
}

func logout(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged out"})
}

func updatePassword(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["id"]
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var passwordData map[string]string
	json.NewDecoder(r.Body).Decode(&passwordData)

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(passwordData["old_password"])); err != nil {
		http.Error(w, "Invalid old password", http.StatusUnauthorized)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(passwordData["new_password"]), bcrypt.DefaultCost)
	user.Password = string(hashedPassword)
	db.Save(&user)

	json.NewEncoder(w).Encode(map[string]string{"message": "Password updated successfully"})
}

func getSettings(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"email":       user.Email,
		"age":         user.Age,
		"gender":      user.Gender,
		"preferences": user.Preferences,
	})
}

func updateSettings(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var settings map[string]interface{}
	json.NewDecoder(r.Body).Decode(&settings)

	if email, ok := settings["email"].(string); ok {
		user.Email = email
	}
	if age, ok := settings["age"].(float64); ok {
		user.Age = int(age)
	}
	if gender, ok := settings["gender"].(string); ok {
		user.Gender = gender
	}
	if preferences, ok := settings["preferences"].(string); ok {
		user.Preferences = preferences
	}

	db.Save(&user)
	json.NewEncoder(w).Encode(map[string]string{"message": "Settings updated successfully"})
}

func createMatch(w http.ResponseWriter, r *http.Request) {
	var match Match
	json.NewDecoder(r.Body).Decode(&match)

	if err := db.Create(&match).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(match)
}

func getMatches(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["user_id"]

	var matches []User
	db.Table("users").Joins("JOIN matches ON users.id = matches.matched_id").Where("matches.user_id = ?", userID).Scan(&matches)

	json.NewEncoder(w).Encode(matches)
}

func createMessage(w http.ResponseWriter, r *http.Request) {
	var message Message
	json.NewDecoder(r.Body).Decode(&message)
	message.Timestamp = time.Now()

	if err := db.Create(&message).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(message)
}

func getMessages(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["user_id"]
	matchedID := mux.Vars(r)["matched_id"]

	var messages []Message
	db.Where("(sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)", userID, matchedID, matchedID, userID).Order("timestamp").Find(&messages)

	json.NewEncoder(w).Encode(messages)
}

func limitMiddleware(lmt *limiter.Limiter) mux.MiddlewareFunc {
	return stdlib.NewMiddleware(lmt).Handler
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		next.ServeHTTP(w, r)
		logrus.WithFields(logrus.Fields{
			"method":      r.Method,
			"request_uri": r.RequestURI,
			"status_code": w.Header().Get("Status"),
			"duration":    time.Since(startTime),
		}).Info("Request completed")
	})
}

func main() {
	router := mux.NewRouter()

	rate, _ := limiter.NewRateFromFormatted("100-H")
	store := memory.NewStore()
	lmt := limiter.New(store, rate)
	router.Use(limitMiddleware(lmt))

	router.Use(loggingMiddleware)

	router.HandleFunc("/users", authMiddleware(getUsers)).Methods("GET")
	router.HandleFunc("/users/{id}", authMiddleware(getUser)).Methods("GET")
	router.HandleFunc("/users/{id}", authMiddleware(updateUser)).Methods("PUT")
	router.HandleFunc("/users/{id}/password", authMiddleware(updatePassword)).Methods("PUT")
	router.HandleFunc("/matches", authMiddleware(createMatch)).Methods("POST")
	router.HandleFunc("/matches/{user_id}", authMiddleware(getMatches)).Methods("GET")
	router.HandleFunc("/messages", authMiddleware(createMessage)).Methods("POST")
	router.HandleFunc("/messages/{user_id}/{matched_id}", authMiddleware(getMessages)).Methods("GET")
	router.HandleFunc("/settings", authMiddleware(getSettings)).Methods("GET")
	router.HandleFunc("/settings", authMiddleware(updateSettings)).Methods("PUT")

	router.HandleFunc("/users", createUser).Methods("POST")
	router.HandleFunc("/login", loginUser).Methods("POST")
	router.HandleFunc("/logout", logout).Methods("POST")

	log.Fatal(http.ListenAndServe(":8000", router))
}
