package storage

import "testing"

func TestPostgresConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		databaseURL string
		wantErr     bool
	}{
		{
			name:        "valid",
			databaseURL: "postgres://postgres:postgres@localhost:5432/layerleak?sslmode=disable",
		},
		{
			name:    "missing",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := PostgresConfig{
				DatabaseURL: tt.databaseURL,
			}.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}
