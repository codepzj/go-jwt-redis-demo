package config

import (
	"os"
)

type Config struct {
	JWTSecret    string
	DBHost       string
	DBPort       string
	DBUser       string
	DBPassword   string
	DBName       string
	RedisHost    string
	RedisPort    string
	RedisPassword string
	RedisDB      int
}

var AppConfig Config

func InitConfig() {
	AppConfig = Config{
		JWTSecret:     getEnv("JWT_SECRET", "codepzj"),
		DBHost:        getEnv("DB_HOST", "localhost"),
		DBPort:        getEnv("DB_PORT", "3306"),
		DBUser:        getEnv("DB_USER", "root"),
		DBPassword:    getEnv("DB_PASSWORD", "123456"),
		DBName:        getEnv("DB_NAME", "mytest2"),
		RedisHost:     getEnv("REDIS_HOST", "localhost"),
		RedisPort:     getEnv("REDIS_PORT", "6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       0,
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
