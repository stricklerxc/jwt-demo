package mongodb

import (
	"context"
	"errors"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	connectionString = "mongodb://localhost:27017"
	MinCost          = 4
	MaxCost          = 31
	DefaultCost      = 13
)

func InsertUser(username, password string) error {
	client := getClient()

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := client.Connect(ctx)
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)

	collection := client.Database("auth").Collection("users")

	if _, err = GetUser(username); err == nil {
		return errors.New("User already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), DefaultCost)
	if err != nil {
		return err
	}

	res, err := collection.InsertOne(ctx, bson.D{
		primitive.E{Key: "username", Value: username},
		primitive.E{Key: "password", Value: hashedPassword}},
	)
	if err != nil {
		return err
	}
	log.Println(res)
	return nil
}

func GetUser(username string) (User, error) {
	client := getClient()

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := client.Connect(ctx)
	if err != nil {
		return User{}, nil
	}
	defer client.Disconnect(ctx)

	collection := client.Database("auth").Collection("users")
	cur, err := collection.Find(ctx, bson.D{
		primitive.E{Key: "username", Value: username},
	})
	if err != nil {
		return User{}, nil
	}

	var user []User
	if err = cur.All(ctx, &user); err != nil {
		return User{}, nil
	}

	if len(user) > 0 {
		return user[0], nil
	}

	return User{}, errors.New("User not found")
}

func getClient() *mongo.Client {
	client, err := mongo.NewClient(options.Client().ApplyURI(connectionString))
	if err != nil {
		log.Fatal(err)
	}

	return client
}
