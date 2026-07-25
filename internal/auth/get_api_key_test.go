package auth

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestAuth(t *testing.T) {
	type test struct {
		input   http.Header
		want    string
		wantErr error
	}

	tests := []test{
		{input: http.Header{}, want: "", wantErr: ErrNoAuthHeaderIncluded},
		{input: http.Header{
			"Authorization": []string{"Bearer my-secret-token"},
		}, want: "", wantErr: errors.New("malformed authorization header")},
		{input: http.Header{
			"Authorization": []string{"ApiKey"},
		}, want: "", wantErr: errors.New("malformed authorization header")},
		{input: http.Header{
			"Authorization": []string{"ApiKey 123456789"},
		}, want: "123456789", wantErr: nil},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("TestGetAPIKey Case #%v:", i), func(t *testing.T) {
			got, err := GetAPIKey(tc.input)
			if !reflect.DeepEqual(tc.want, got) {
				t.Fatalf("expected: %v, got: %v", tc.want, got)
			}
			if err == nil && tc.wantErr == nil {
				return
			}
			if err == nil && tc.wantErr != nil {
				t.Errorf("GetAPIKey error = nil, wantErr %v", tc.wantErr)
				return
			}
			if err != nil && tc.wantErr == nil {
				t.Errorf("GetAPIKey error = %v, wantErr nil", err)
				return
			}
			if err.Error() != tc.wantErr.Error() {
				t.Errorf("GetAPIKey error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
