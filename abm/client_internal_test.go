package abm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func devicesPage(t *testing.T, w http.ResponseWriter, next string, serials ...string) {
	t.Helper()
	page := map[string]any{"data": []map[string]any{}, "links": map[string]any{}}
	for _, serial := range serials {
		page["data"] = append(page["data"].([]map[string]any), map[string]any{
			"type":       "orgDevices",
			"id":         serial,
			"attributes": map[string]any{"serialNumber": serial},
		})
	}
	if next != "" {
		page["links"] = map[string]any{"next": next}
	}
	if err := json.NewEncoder(w).Encode(page); err != nil {
		t.Errorf("failed to encode page: %v", err)
	}
}

func TestGetOrganizationDevicesFollowsPages(t *testing.T) {
	t.Parallel()

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/orgDevices" {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			devicesPage(t, w, ts.URL+"/v1/orgDevices?cursor=two", "A", "B")
		case "two":
			devicesPage(t, w, ts.URL+"/v1/orgDevices?cursor=three", "C")
		case "three":
			devicesPage(t, w, "", "D")
		default:
			http.Error(w, "bad cursor", http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	client := &Client{httpClient: ts.Client(), baseURL: ts.URL + "/v1"}
	devices, err := client.GetOrganizationDevices(t.Context())
	if err != nil {
		t.Fatalf("GetOrganizationDevices() error = %v", err)
	}
	var serials []string
	for _, d := range devices {
		serials = append(serials, d.SerialNumber)
	}
	if got := strings.Join(serials, ","); got != "A,B,C,D" {
		t.Errorf("serials = %q, want A,B,C,D", got)
	}
}

func TestGetOrganizationDevicesRejectsForeignNextPage(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		devicesPage(t, w, "https://attacker.example/v1/orgDevices?cursor=two", "A")
	}))
	defer ts.Close()

	client := &Client{httpClient: ts.Client(), baseURL: ts.URL + "/v1"}
	if _, err := client.GetOrganizationDevices(t.Context()); err == nil {
		t.Fatal("GetOrganizationDevices() error = nil, want rejection of foreign next page URL")
	}
}

func TestGetOrganizationDevicesPageError(t *testing.T) {
	t.Parallel()

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "" {
			devicesPage(t, w, ts.URL+"/v1/orgDevices?cursor=two", "A")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	}))
	defer ts.Close()

	client := &Client{httpClient: ts.Client(), baseURL: ts.URL + "/v1"}
	_, err := client.GetOrganizationDevices(t.Context())
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("GetOrganizationDevices() error = %v, want status 500 error", err)
	}
}
