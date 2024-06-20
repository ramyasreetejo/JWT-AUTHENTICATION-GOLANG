package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/ramyasreetejo/jwt-authentication-golang/database"
	"github.com/ramyasreetejo/jwt-authentication-golang/helpers"
	"github.com/ramyasreetejo/jwt-authentication-golang/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""
	if err != nil {
		msg = "email of password is incorrect"
		check = false
	}
	return check, msg
}

func Signup(w http.ResponseWriter, r *http.Request) {
	// w.Write([]byte(`"message": "hi, signedup"`))
	var ctx, cancel = context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()

	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	validationErr := validate.Struct(user)
	if validationErr != nil {
		http.Error(w, validationErr.Error(), http.StatusBadRequest)
		return
	}

	password := HashPassword(*user.Password)
	user.Password = &password

	count_email, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
	if err != nil {
		log.Panic(err)
		http.Error(w, "error occurred while checking for the email", http.StatusInternalServerError)
		return
	}

	count_phno, err := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
	if err != nil {
		log.Panic(err)
		http.Error(w, "error occurred while checking for the phone number", http.StatusInternalServerError)
		return
	}

	if (count_email > 0) || (count_phno > 0) {
		http.Error(w, "this email or phone number already exists", http.StatusInternalServerError)
		return
	}

	user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.ID = primitive.NewObjectID()
	user.User_id = user.ID.Hex()
	token, refreshToken, _ := helpers.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, user.User_id)
	user.Token = &token
	user.Refresh_token = &refreshToken

	resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
	if insertErr != nil {
		msg := "User item was not created"
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resultInsertionNumber)
}

func Login(w http.ResponseWriter, r *http.Request) {
	// fmt.Fprintf(w, "hi, loggedin")
	var ctx, cancel = context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()
	var user models.User
	var foundUser models.User

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
	if err != nil {
		http.Error(w, "error: email doesn't exist in db", http.StatusBadRequest)
		return
	}

	passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
	if !passwordIsValid {
		http.Error(w, "error: "+msg, http.StatusInternalServerError)
		return
	}

	if foundUser.Email == nil {
		http.Error(w, "error: user not found", http.StatusInternalServerError)
	}
	token, refreshToken, _ := helpers.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)
	helpers.UpdateAllTokens(token, refreshToken, foundUser.User_id)
	err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)

	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	fmt.Printf(*foundUser.Token)
	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: "val",
	})
	// http.SetCookie(w, &http.Cookie{
	// 	Name:    "token",
	// 	Value:   *foundUser.Token,
	// 	Expires: time.Now().Add(24 * time.Hour),
	// 	Path:    "/users/login", // Set the path to match your API endpoint
	// 	Domain:  "localhost",    // Set the domain to match your API domain
	// })
	json.NewEncoder(w).Encode(foundUser)
}

func GetUsers(w http.ResponseWriter, r *http.Request) {
	// Access user information from request context
	email := r.Context().Value("email").(string)
	firstName := r.Context().Value("first_name").(string)
	lastName := r.Context().Value("last_name").(string)
	uid := r.Context().Value("uid").(string)
	userType := r.Context().Value("user_type").(string)

	// Use user information for further processing
	fmt.Fprintf(w, "Authenticated User: %s (%s %s), UID: %s, User Type: %s", email, firstName, lastName, uid, userType)

	// If user type is not ADMIN, return an error
	if err := helpers.CheckUserType(r, "ADMIN"); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Set up context and cancellation function
	var ctx, cancel = context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()

	// Parse query parameters for pagination
	recordPerPage, err := strconv.Atoi(r.URL.Query().Get("recordPerPage"))
	if err != nil || recordPerPage < 1 {
		recordPerPage = 10
	}

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	startIndex := (page - 1) * recordPerPage
	// Overwrite startIndex if provided as query parameter
	if queryStartIndex := r.URL.Query().Get("startIndex"); queryStartIndex != "" {
		startIndex, err = strconv.Atoi(queryStartIndex)
		if err != nil || startIndex < 0 {
			startIndex = 0
		}
	}

	matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}
	groupStage := bson.D{{Key: "$group", Value: bson.D{
		{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
		{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
		{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}}}}}
	projectStage := bson.D{
		{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "total_count", Value: 1},
			{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}}}}}

	// Perform aggregation query
	result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
		matchStage, groupStage, projectStage})
	if err != nil {
		http.Error(w, "error: error occured while listing user items", http.StatusInternalServerError)
		return
	}

	// Extract results
	var allusers []bson.M
	if err = result.All(ctx, &allusers); err != nil {
		log.Fatal(err)
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(allusers[0])
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	// Access user information from request context
	email := r.Context().Value("email").(string)
	firstName := r.Context().Value("first_name").(string)
	lastName := r.Context().Value("last_name").(string)
	uid := r.Context().Value("uid").(string)
	userType := r.Context().Value("user_type").(string)

	// Use user information for further processing
	fmt.Fprintf(w, "Authenticated User: %s (%s %s), UID: %s, User Type: %s", email, firstName, lastName, uid, userType)

	userId := r.Context().Value("user_id").(string)

	if err := helpers.MatchUserTypeToUid(r, userId); err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusBadRequest)
		return
	}
	var ctx, cancel = context.WithTimeout(r.Context(), 100*time.Second)

	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
	defer cancel()
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}
