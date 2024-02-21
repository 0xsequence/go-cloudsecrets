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


```
package cloudsecrets

func HydrateSecrets(client SecretStorage, v interface{}) {
    // iterate over all 'v' struct fields using reflect
    // for each field matching `SECRET:{name}`, replace the value by fetching `{name}` secret value from GCP Secret Manager
}
```

## Usage
```
// initialize GCP client
gcpClient, err := secretmanager.NewClient(context.Background())
if err != nil {
    return nil, fmt.Errorf("failed to initialize google secret manager: %w", err)
}

// fetch a projectId depends if you running project locally vs GKE
var projectId string
if metadata.OnGCE() {
    projectId, err = metadata.ProjectID()
    if err != nil {
        return nil, fmt.Errorf("failed to get project ID from metadata: %w", err)
    }
} else {
    projectId = os.Getenv("GOOGLE_CLOUD_PROJECT")
}

secretStorageClient := cloudsecrets.NewGCPSecretStorage(projectId, gcpClient)
// cfg = application config can be any struct
err = cloudsecrets.HydrateSecrets(context.Background(), secretStorageClient, cfg)
if err != nil {
    return nil, fmt.Errorf("failed to replace secret placeholders with real values: %w", err)
}
```