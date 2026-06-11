package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

func decodeJSON(data []byte, target any) error {
	return json.Unmarshal(data, target)
}

// folderStubConfig extends stubConfig with a real temp directory for
// GetServerFolder/GetKeyFolder so token/key tests can touch the filesystem.
type folderStubConfig struct {
	stubConfig
	serverFolder string
}

func (s *folderStubConfig) GetServerFolder() string { return s.serverFolder }
func (s *folderStubConfig) GetKeyFolder() string    { return "keys" }

func newTestServerInstance(t *testing.T) *server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	return &server{
		config:                      &folderStubConfig{serverFolder: t.TempDir()},
		createdObjectsThrottler:     make(map[string][]int64),
		mapTokenHashToTimeoutStruct: make(map[string]timeoutStruct),
		mapFolderNameToTokenHash:    make(map[string]string),
		locksByFolderName:           make(map[string]*sync.Mutex),
	}
}

func ginContextWithHeader(headerName, headerValue string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	if headerName != "" {
		req.Header.Set(headerName, headerValue)
	}
	c.Request = req
	return c, w
}

func TestCheckKeyToFolderName_MissingHeader(t *testing.T) {
	s := newTestServerInstance(t)
	c, w := ginContextWithHeader("", "")

	_, _, ok := s.checkKeyToFolderName(c)
	if ok {
		t.Fatal("expected ok=false for missing key header")
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCheckKeyToFolderName_MalformedBase64(t *testing.T) {
	s := newTestServerInstance(t)
	c, w := ginContextWithHeader("key", "not-valid-base64!!")

	_, _, ok := s.checkKeyToFolderName(c)
	if ok {
		t.Fatal("expected ok=false for malformed key")
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCheckKeyToFolderName_UnknownKey(t *testing.T) {
	s := newTestServerInstance(t)
	// valid base64 but no folder created for it
	c, w := ginContextWithHeader("key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	_, _, ok := s.checkKeyToFolderName(c)
	if ok {
		t.Fatal("expected ok=false for unknown key")
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCheckTokenToFolderName_MissingHeader(t *testing.T) {
	s := newTestServerInstance(t)
	c, w := ginContextWithHeader("", "")

	_, _, ok := s.checkTokenToFolderName(c)
	if ok {
		t.Fatal("expected ok=false for missing token header")
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCheckTokenToFolderName_MalformedBase64(t *testing.T) {
	s := newTestServerInstance(t)
	c, w := ginContextWithHeader("token", "not-valid-base64!!")

	_, _, ok := s.checkTokenToFolderName(c)
	if ok {
		t.Fatal("expected ok=false for malformed token")
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCheckTokenToFolderName_UnknownToken(t *testing.T) {
	s := newTestServerInstance(t)
	c, w := ginContextWithHeader("token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	_, _, ok := s.checkTokenToFolderName(c)
	if ok {
		t.Fatal("expected ok=false for unknown token")
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteToken_MissingHeader(t *testing.T) {
	s := newTestServerInstance(t)
	c, w := ginContextWithHeader("", "")

	s.deleteToken(c)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteKey_NotFound(t *testing.T) {
	s := newTestServerInstance(t)
	c, w := ginContextWithHeader("key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	s.deleteKey(c)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCreateKey_Succeeds(t *testing.T) {
	s := newTestServerInstance(t)
	c, w := ginContextWithHeader("", "")

	s.createKey(c)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}
}

func TestCheckObjectCreationThrottler_LimitsAfter20(t *testing.T) {
	s := newTestServerInstance(t)

	for i := 0; i < 20; i++ {
		c, w := ginContextWithHeader("", "")
		if ok := s.checkObjectCreationThrottler(c, "TESTOBJ"); !ok {
			t.Fatalf("creation %d unexpectedly throttled", i)
		}
		if w.Code != http.StatusOK {
			t.Errorf("creation %d: unexpected status %d", i, w.Code)
		}
	}

	c, w := ginContextWithHeader("", "")
	if ok := s.checkObjectCreationThrottler(c, "TESTOBJ"); ok {
		t.Fatal("expected 21st creation to be throttled")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}
}

func TestCreateToken_And_CheckTokenToFolderName_RoundTrip(t *testing.T) {
	s := newTestServerInstance(t)

	// Create a key first
	c, w := ginContextWithHeader("", "")
	s.createKey(c)
	if w.Code != http.StatusCreated {
		t.Fatalf("createKey status = %d", w.Code)
	}

	var created struct {
		Key string `json:"key"`
	}
	if err := decodeJSON(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode createKey response: %v", err)
	}

	// Create a token using that key
	c, w = ginContextWithHeader("key", created.Key)
	s.createToken(c)
	if w.Code != http.StatusCreated {
		t.Fatalf("createToken status = %d, body=%s", w.Code, w.Body.String())
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("decode createToken response: %v", err)
	}

	// Use the token to resolve the folder
	c, _ = ginContextWithHeader("token", tokenResp.Token)
	_, _, ok := s.checkTokenToFolderName(c)
	if !ok {
		t.Fatal("expected checkTokenToFolderName to succeed with freshly created token")
	}

	// Delete the token and verify it no longer resolves
	c, w = ginContextWithHeader("token", tokenResp.Token)
	s.deleteToken(c)
	if w.Code != http.StatusOK {
		t.Fatalf("deleteToken status = %d", w.Code)
	}

	c, w = ginContextWithHeader("token", tokenResp.Token)
	_, _, ok = s.checkTokenToFolderName(c)
	if ok {
		t.Fatal("expected checkTokenToFolderName to fail after token deletion")
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}
