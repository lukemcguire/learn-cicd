package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input      http.Header
		wantAPIKey string
		wantErr    error
	}{
		"no auth header included": {
			input:      http.Header{"Authorization": {""}},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		"malformed header": {
			input:      http.Header{"Authorization": {"APIKey has extra stuff"}},
			wantAPIKey: "",
			wantErr:    ErrMalformedAuthHeader,
		},
		"valid": {
			input:      http.Header{"Authorization": {"ApiKey validAPIKey0123456789"}},
			wantAPIKey: "validAPIKey0123456789",
			wantErr:    nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.input)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %q, wantErr %q", err, tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %q", err)
				}
			}

			if tc.wantErr == nil {
				if diff := cmp.Diff(tc.wantAPIKey, got); diff != "" {
					t.Fatalf("GetAPIKey() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
