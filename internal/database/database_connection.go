package database

import (
	"context"
	"fmt"
	"log"
	"time"

	config "github.com/xamuel98/syncspace-backend/internal/config"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func DBInstance() *mongo.Client {
	// Use the SetServerAPIOptions() method to set the version of the Stable API on the client
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)

	mongoURI := config.EnvMongoURI() // Get MongoDB URI

	if mongoURI == "" {
		log.Fatal("You must set your 'MONGODB_URI' environment variable.")
	}

	opts := options.Client().ApplyURI(mongoURI).SetServerAPIOptions(serverAPI)

	rootContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Create a new client and connect to the server
	client, err := mongo.Connect(rootContext, opts)

	if err != nil {
		panic(err)
	}

	// Send a ping to confirm a successful connection
	if err := client.Database("cluster0").RunCommand(rootContext, bson.D{{"ping", 1}}).Err(); err != nil {
		panic(err)
	}

	fmt.Println("Pinged your deployment. You successfully connected to MongoDB!")

	return client
}

// Client Instance
var Client *mongo.Client = DBInstance()

func OpenCollection(client *mongo.Client, collectionName string) (*mongo.Collection, error) {
	var collection *mongo.Collection = client.Database("cluster0").Collection(collectionName)

	return collection, nil
}
