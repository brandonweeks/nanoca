package abm

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
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

func TestGetReportsAPIErrors(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"id":"1","status":"403","code":"FORBIDDEN_ERROR","title":"This request is forbidden for security reasons","detail":"The API key in use does not allow this request"}]}`))
	}))
	defer ts.Close()

	client := &Client{httpClient: ts.Client(), baseURL: ts.URL + "/v1"}
	_, err := client.GetDevice(t.Context(), "A")
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "FORBIDDEN_ERROR") || !strings.Contains(err.Error(), "The API key in use does not allow this request") {
		t.Errorf("GetDevice() error = %v, want status, code, and detail", err)
	}
}

func TestGetOrganizationDevicesStatus(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("limit"); got != "1000" {
			t.Errorf("limit = %q, want 1000", got)
		}
		_, _ = w.Write([]byte(`{"data":[
			{"type":"orgDevices","id":"A","attributes":{"serialNumber":"A","status":"ASSIGNED"}},
			{"type":"orgDevices","id":"B","attributes":{"serialNumber":"B","status":"UNASSIGNED"}}
		]}`))
	}))
	defer ts.Close()

	client := &Client{httpClient: ts.Client(), baseURL: ts.URL + "/v1"}
	devices, err := client.GetOrganizationDevices(t.Context())
	if err != nil {
		t.Fatalf("GetOrganizationDevices() error = %v", err)
	}
	want := []Device{{SerialNumber: "A", Status: DeviceStatusAssigned}, {SerialNumber: "B", Status: DeviceStatusUnassigned}}
	if !slices.Equal(devices, want) {
		t.Errorf("devices = %+v, want %+v", devices, want)
	}
}

func TestGetDevice(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/orgDevices/A":
			_, _ = w.Write([]byte(`{"data":{"type":"orgDevices","id":"A","attributes":{"serialNumber":"A","status":"ASSIGNED"}}}`))
		case "/v1/orgDevices/R":
			_, _ = w.Write([]byte(`{"data":{"type":"orgDevices","id":"R","attributes":{"serialNumber":"R","releasedFromOrgDateTime":"2026-01-02T03:04:05Z"}}}`))
		case "/v1/orgDevices/E":
			_, _ = w.Write([]byte(`{"data":null}`))
		case "/v1/orgDevices/A/relationships/assignedServer":
			_, _ = w.Write([]byte(`{"data":{"type":"mdmServers","id":"server-1"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	client := &Client{httpClient: ts.Client(), baseURL: ts.URL + "/v1"}

	d, err := client.GetDevice(t.Context(), "A")
	if err != nil || d != (Device{SerialNumber: "A", Status: DeviceStatusAssigned}) {
		t.Errorf("GetDevice(A) = %+v, %v", d, err)
	}
	for _, serial := range []string{"R", "E", "missing"} {
		if _, err := client.GetDevice(t.Context(), serial); !errors.Is(err, ErrNotFound) {
			t.Errorf("GetDevice(%s) error = %v, want ErrNotFound", serial, err)
		}
	}

	if id, err := client.GetAssignedServerID(t.Context(), "A"); err != nil || id != "server-1" {
		t.Errorf("GetAssignedServerID(A) = %q, %v, want server-1", id, err)
	}
	if _, err := client.GetAssignedServerID(t.Context(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAssignedServerID(missing) error = %v, want ErrNotFound", err)
	}
}

func TestGetMDMServerSerials(t *testing.T) {
	t.Parallel()

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v1/mdmServers/server%2F1/relationships/devices" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("cursor") == "" {
			_, _ = w.Write([]byte(`{"data":[{"type":"orgDevices","id":"A"},{"type":"orgDevices","id":"B"}],` +
				`"links":{"next":"` + ts.URL + `/v1/mdmServers/server%2F1/relationships/devices?cursor=two"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"type":"orgDevices","id":"C"}]}`))
	}))
	defer ts.Close()

	client := &Client{httpClient: ts.Client(), baseURL: ts.URL + "/v1"}
	serials, err := client.GetMDMServerSerials(t.Context(), "server/1")
	if err != nil {
		t.Fatalf("GetMDMServerSerials() error = %v", err)
	}
	if got := strings.Join(serials, ","); got != "A,B,C" {
		t.Errorf("serials = %q, want A,B,C", got)
	}
}
