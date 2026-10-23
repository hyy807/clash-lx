package clash

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The app resolves this endpoint from the shared container, not APIPath in
// its own Go runtime. Never silently relocate it into the extension sandbox.
func TestSharedControlSocketReturnsRealSingleNodeDelay(t *testing.T) {
	base, err := os.MkdirTemp("", "probe-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	options := testOptions(t)
	options.BasePath = base
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if err := service.Start(helloYAML); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, clashAPISocketName)
	if APIPath() != want {
		t.Fatalf("server=%q app=%q", APIPath(), want)
	}
	if err := startControlPlane(nil, want); err != nil {
		t.Fatal(err)
	}
	defer stopClashAPI(want)
	client, err := NewAPIClient(want, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method=%s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	payload, err := client.URLTestOutcome("DIRECT", target.URL)
	if err != nil {
		t.Fatal(err)
	}
	var answer struct {
		Delay int `json:"delay"`
	}
	if err := json.Unmarshal([]byte(payload), &answer); err != nil || answer.Delay <= 0 {
		t.Fatalf("single-node real HTTP outcome=%s err=%v", payload, err)
	}
	t.Logf("shared endpoint=%s real HEAD outcome=%s", want, payload)
}

func TestSetupNeverRelocatesSharedControlSocket(t *testing.T) {
	options := testOptions(t)
	options.BasePath = filepath.Join(options.BasePath, strings.Repeat("x", 110))
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(options.BasePath, clashAPISocketName)
	if got := APIPath(); got != want {
		t.Fatalf("server relocated shared endpoint: got %q, app will dial %q", got, want)
	}
	if err := startControlPlane(nil, want); err == nil || !strings.Contains(err.Error(), "Darwin limit") {
		t.Fatalf("overlong shared endpoint must fail explicitly, not silently split client/server: %v", err)
	}
}
