# go-cloudsecrets
- Package to hydrate secrets from GCP Secret Manager
- Find and replace string values starting with SECRET: prefix with the value fetched from GCP Secret Manager.

Example: 
```
# app.conf
[db]
database = "dbname"
host     = "dbhost"
username = "dbuser"
password = "SECRET:db_password" # reference to db_password secret in GCP project
```

## Usage
```
err = cloudsecrets.HydrateSecrets(context.Background(), "gcp", cfg)
if err != nil {
    return nil, fmt.Errorf("failed to replace secret placeholders with real values: %w", err)
}
```