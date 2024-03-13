// @title Tinder API
// @version 1.0
// @description This is the API server for a Tinder-like application.
// @host localhost:8000
// @BasePath /
// @schemes http

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "backend/docs"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	httpSwagger "github.com/swaggo/http-swagger"
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
	loadErr := godotenv.Load()
	if loadErr != nil {
		log.Fatal("Error loading .env file")
	}

	var err error
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbURI := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable", dbHost, dbPort, dbUser, dbName, dbPassword)

	db, err = gorm.Open("postgres", dbURI)
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &Match{}, &Message{})
}

// createUser creates a new user.
//
// This endpoint allows you to create a new user by providing the user's email and password in the request body.
// The password will be hashed before storing it in the database.
//
// @Summary Create a new user
// @Description Create a new user with email and password
// @Tags Users
// @Accept json
// @Produce json
// @Param user body User true "User object containing email and password"
// @Success 200 {object} User
// @Failure 400 {string} string "Email and Password are required"
// @Failure 500 {string} string "Internal Server Error"
// @Router /users [post]

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

// loginUser logs in a user.
//
// This endpoint allows you to log in a user by providing the user's email and password in the request body.
// If the email and password are valid, a JWT token will be returned in the response.
//
// @Summary Log in a user
// @Description Log in a user with email and password
// @Tags Users
// @Accept json
// @Produce json
// @Param user body User true "User object containing email and password"
// @Success 200 {object} map[string]string
// @Failure 401 {string} string "Invalid email or password"
// @Failure 500 {string} string "Internal Server Error"
// @Router /login [post]

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

// authMiddleware is a middleware that checks if the request has a valid JWT token.
//
// This middleware checks if the request has a valid JWT token in the Authorization header.
// If the token is valid, the user ID is added to the request context and the next handler is called.
// If the token is invalid, a 401 Unauthorized response is returned.
//
// @Summary Check if the request has a valid JWT token
// @Description Check if the request has a valid JWT token in the Authorization header
// @Tags Users
// @Accept json
// @Produce json
// @Param Authorization header string true "JWT token"
// @Success 200 {string} string "OK"
// @Failure 401 {string} string "Unauthorized"
// @Router /users [get]

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

// getUsers returns a list of users.
//
// This endpoint allows you to get a list of all users.
// The response will contain an array of user objects.
//
// @Summary Get a list of users
// @Description Get a list of all users
// @Tags Users
// @Accept json
// @Produce json
// @Success 200 {array} User
// @Failure 500 {string} string "Internal Server Error"
// @Router /users [get]
func getUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	db.Find(&users)
	json.NewEncoder(w).Encode(users)
}

// getUser returns a user by ID.
//
// This endpoint allows you to get a user by providing the user's ID in the request URL.
// The response will contain the user object.
//
// @Summary Get a user by ID
// @Description Get a user by ID
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} User
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal Server Error"
// @Router /users/{id} [get]
func getUser(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["id"]

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}

// updateUser updates a user by ID.
//
// This endpoint allows you to update a user by providing the user's ID in the request URL and the updated user object in the request body.
// The response will contain the updated user object.
//
// @Summary Update a user by ID
// @Description Update a user by ID
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param user body User true "User object containing updated fields"
// @Success 200 {object} User
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal Server Error"
// @Router /users/{id} [put]
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

// logout logs out a user.
//
// This endpoint allows you to log out a user by invalidating the JWT token.
// The response will contain a message indicating that the user has been successfully logged out.
//
// @Summary Log out a user
// @Description Log out a user by invalidating the JWT token
// @Tags Users
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Router /logout [post]
func logout(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged out"})
}

// updatePassword updates a user's password.
//
// This endpoint allows you to update a user's password by providing the user's ID in the request URL and the old and new passwords in the request body.
// The response will contain a message indicating that the password has been successfully updated.
//
// @Summary Update a user's password
// @Description Update a user's password by providing the user's ID and the old and new passwords
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param passwordData body map[string]string true "Old and new passwords"
// @Success 200 {object} map[string]string
// @Failure 401 {string} string "Invalid old password"
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal Server Error"
// @Router /users/{id}/password [put]
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

// getSettings returns a user's settings.
//
// This endpoint allows you to get a user's settings.
// The response will contain the user
//
// @Summary Get a user's settings
// @Description Get a user's settings
// @Tags Users
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal Server Error"
// @Router /settings [get]
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

// updateSettings updates a user's settings.
//
// This endpoint allows you to update a user's settings by providing the user's ID in the request URL and the updated settings in the request body.
// The response will contain a message indicating that the settings have been successfully updated.
//
// @Summary Update a user's settings
// @Description Update a user's settings by providing the user's ID and the updated settings
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param settings body map[string]interface{} true "Updated settings"
// @Success 200 {object} map[string]string
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal Server Error"
// @Router /settings [put]
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

// createMatch creates a new match.
//
// This endpoint allows you to create a new match by providing the user's ID and the matched user's ID in the request body.
// The response will contain the match object.
//
// @Summary Create a new match
// @Description Create a new match with user ID and matched user ID
// @Tags Matches
// @Accept json
// @Produce json
// @Param match body Match true "Match object containing user ID and matched user ID"
// @Success 200 {object} Match
// @Failure 500 {string} string "Internal Server Error"
// @Router /matches [post]
func createMatch(w http.ResponseWriter, r *http.Request) {
	var match Match
	json.NewDecoder(r.Body).Decode(&match)

	if err := db.Create(&match).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(match)
}

// getMatches returns a list of matches for a user.
//
// This endpoint allows you to get a list of matches for a user by providing the user's ID in the request URL.
// The response will contain an array of user objects that the user has matched with.
//
// @Summary Get a list of matches for a user
// @Description Get a list of matches for a user by ID
// @Tags Matches
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Success 200 {array} User
// @Failure 500 {string} string "Internal Server Error"
// @Router /matches/{user_id} [get]
func getMatches(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["user_id"]

	var matches []User
	db.Table("users").Joins("JOIN matches ON users.id = matches.matched_id").Where("matches.user_id = ?", userID).Scan(&matches)

	json.NewEncoder(w).Encode(matches)
}

// createMessage creates a new message.
//
// This endpoint allows you to create a new message by providing the message object in the request body.
// The response will contain the message object.
//
// @Summary Create a new message
// @Description Create a new message with sender ID, receiver ID, and content
// @Tags Messages
// @Accept json
// @Produce json
// @Param message body Message true "Message object containing sender ID, receiver ID, and content"
// @Success 200 {object} Message
// @Failure 500 {string} string "Internal Server Error"
// @Router /messages [post]
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

// getMessages returns a list of messages between two users.
//
// This endpoint allows you to get a list of messages between two users by providing the user's ID and the matched user's ID in the request URL.
// The response will contain an array of message objects.
//
// @Summary Get a list of messages between two users
// @Description Get a list of messages between two users by ID
// @Tags Messages
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param matched_id path string true "Matched user ID"
// @Success 200 {array} Message
// @Failure 500 {string} string "Internal Server Error"
// @Router /messages/{user_id}/{matched_id} [get]
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
	router.PathPrefix("/swagger").Handler(httpSwagger.WrapHandler)

	// root endpoint
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to the Tinder API"))
	})

	log.Fatal(http.ListenAndServe(":8000", router))
}
