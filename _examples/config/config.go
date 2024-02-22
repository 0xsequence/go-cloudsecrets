package config

type Config struct {
	DB *DB
}

type DB struct {
	Database string
	Host     string
	Username string
	Password string
}
