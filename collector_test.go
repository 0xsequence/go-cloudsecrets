package cloudsecrets

import (
	"fmt"
	"reflect"
	"testing"
)

type dbConfig struct {
	User     string
	Password string
}

type jwtSecret string

type config1 struct {
	DB         dbConfig
	JWTSecrets []jwtSecret
	unexported dbConfig
}

func TestCollectFields(t *testing.T) {
	tt := []struct {
		Input any
		Out   []string // field paths
		Error bool
	}{
		{
			Input: &config1{
				DB: dbConfig{
					User:     "db-user",
					Password: "db-password",
				},
			},
			Out: []string{},
		},
		{
			Input: &config1{
				DB: dbConfig{
					User:     "db-user",
					Password: "$SECRET:secretName",
				},
				JWTSecrets: []jwtSecret{"$SECRET:jwtSecret1", "$SECRET:jwtSecret2", "nope"},
			},
			Out: []string{"secretName", "jwtSecret1", "jwtSecret2"},
		},
		{
			Input: &config1{
				unexported: dbConfig{ // unexported fields can't be updated via reflect pkg
					User:     "db-user",
					Password: "$SECRET:secretName", // match inside unexported field
				},
			},
			Out:   []string{},
			Error: true, // expect error
		},
	}

	for i, tc := range tt {
		i, tc := i, tc
		t.Run(fmt.Sprintf("tt[%v]", i), func(t *testing.T) {
			v := reflect.ValueOf(tc.Input)

			c := &collector{}
			c.collectSecretFields(v, fmt.Sprintf("tt[%v].input", i))

			if tc.Error {
				if c.err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if c.err != nil {
					t.Errorf("unexpected error: %v", c.err)
				}
			}

			if len(c.fields) != len(tc.Out) {
				t.Errorf("expected %v secrets, got %v", len(tc.Out), len(c.fields))
			}
			for i := 0; i < len(c.fields); i++ {
				if c.fields[i].secretName != tc.Out[i] {
					t.Errorf("collected field[%v].secretName=%v doesn't match tc.Out[%v]=%v", i, c.fields[i].secretName, i, tc.Out[i])
				}
			}
		})
	}
}
