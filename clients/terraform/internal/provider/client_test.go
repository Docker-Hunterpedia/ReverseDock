package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func testClient(t *testing.T, f *fakeAdmin, token string) *Client {
	t.Helper()
	c, err := newClient(clientConfig{Endpoint: f.Server.URL, Token: token, UserAgent: "terraform-provider-reversedock/test"})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

var (
	appService = `{"backends":[{"address":"127.0.0.1:8080"}]}`
	webRoute   = "{\"match\":\"Host(`web.example.com`)\",\"service\":\"app\"}"
)

func TestParseEndpoint(t *testing.T) {
	ok := map[string]string{
		"http://127.0.0.1:2080":       "http://127.0.0.1:2080",
		"http://localhost:2080/":      "http://localhost:2080",
		"http://[::1]:2080":           "http://[::1]:2080",
		"https://rdock.example.com":   "https://rdock.example.com",
		" https://rdock.example.com/": "https://rdock.example.com",
		"https://h:2080/admin/":       "https://h:2080/admin",
	}
	for in, want := range ok {
		got, err := parseEndpoint(in)
		if err != nil || got != want {
			t.Errorf("parseEndpoint(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := map[string]string{
		"http://rdock.example.com:2080": "plain HTTP",
		"http://10.0.0.5:2080":          "plain HTTP",
		"ftp://127.0.0.1":               "unsupported scheme",
		"127.0.0.1:2080":                "not a URL",
		"":                              "not a URL",
		"https://user:pw@h":             "credentials",
		"https://h/?a=b":                "query",
	}
	for in, want := range bad {
		if _, err := parseEndpoint(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("parseEndpoint(%q) error = %v; want mention of %q", in, err, want)
		}
	}
}

func TestNewClientNeedsAToken(t *testing.T) {
	if _, err := newClient(clientConfig{Endpoint: "http://127.0.0.1:1", Token: "  "}); err == nil {
		t.Fatal("no error without a token")
	}
}

func TestRequestsCarryTheTokenAndTheUserAgent(t *testing.T) {
	f := newFakeAdmin(t)
	c := testClient(t, f, fakeViewerToken)
	if _, err := c.getStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := f.lastHeaders.Load().(http.Header)
	if h.Get("Authorization") != "Bearer "+fakeViewerToken || h.Get("User-Agent") != "terraform-provider-reversedock/test" {
		t.Errorf("headers: %v", h)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	f := newFakeAdmin(t)
	f.redirectTo = "https://elsewhere.invalid/steal"
	c := testClient(t, f, fakeViewerToken)
	_, err := c.getStatus(context.Background())
	if !isStatus(err, http.StatusTemporaryRedirect) {
		t.Fatalf("want the 307 reported as an error, got %v", err)
	}
}

func TestBadTokenIs401(t *testing.T) {
	f := newFakeAdmin(t)
	c := testClient(t, f, "rdk_pat_wrong")
	_, err := c.getAPI(context.Background())
	if !isStatus(err, http.StatusUnauthorized) || !strings.Contains(err.Error(), "token") {
		t.Fatalf("got %v", err)
	}
}

func TestCreateUpdateDeleteRoundTrip(t *testing.T) {
	f := newFakeAdmin(t)
	c := testClient(t, f, fakeOperatorToken)
	ctx := context.Background()

	if _, err := c.write(ctx, kindServices, "app", mustObject(t, appService), modeCreate); err != nil {
		t.Fatal(err)
	}
	res, err := c.write(ctx, kindRoutes, "web", mustObject(t, webRoute), modeCreate)
	if err != nil {
		t.Fatal(err)
	}
	// The API's rendering has defaults the spec did not mention.
	if res.Canonical["enabled"] != true || !contains(mustObject(t, webRoute), res.Canonical) {
		t.Errorf("canonical = %v", res.Canonical)
	}
	if !strings.HasPrefix(res.ETag, `"g`) {
		t.Errorf("etag = %q", res.ETag)
	}

	changed := mustObject(t, "{\"match\":\"Host(`web.example.com`)\",\"service\":\"app\",\"priority\":5}")
	res, err = c.write(ctx, kindRoutes, "web", changed, modeUpdate)
	if err != nil || !equalJSON(res.Canonical["priority"], int64(5)) {
		t.Fatalf("update: %v %v", res, err)
	}

	if _, err := c.write(ctx, kindRoutes, "web", nil, modeDelete); err != nil {
		t.Fatal(err)
	}
	if got := f.names(kindRoutes); len(got) != 0 {
		t.Errorf("routes left: %v", got)
	}
	_, err = c.write(ctx, kindRoutes, "web", nil, modeDelete)
	if !isStatus(err, http.StatusNotFound) {
		t.Errorf("deleting twice: %v", err)
	}
}

func TestCreateRefusesToAdoptAnExistingObject(t *testing.T) {
	f := newFakeAdmin(t)
	f.seed(kindServices, "app", mustObject(t, appService))
	c := testClient(t, f, fakeOperatorToken)
	_, err := c.write(context.Background(), kindServices, "app", mustObject(t, appService), modeCreate)
	if !errors.Is(err, errAlreadyExists) || !strings.Contains(err.Error(), "terraform import") {
		t.Fatalf("got %v", err)
	}
	// Update, by contrast, is a PUT: create or replace.
	if _, err := c.write(context.Background(), kindServices, "app", mustObject(t, appService), modeUpdate); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedByTheFileOrAProviderIsRefusedClearly(t *testing.T) {
	f := newFakeAdmin(t)
	f.fileObject(kindServices, "fromfile")
	c := testClient(t, f, fakeOperatorToken)
	_, err := c.write(context.Background(), kindServices, "fromfile", mustObject(t, appService), modeUpdate)
	if !isStatus(err, http.StatusForbidden) || !strings.Contains(err.Error(), "belongs to the configuration file") {
		t.Fatalf("file-owned: %v", err)
	}
	if strings.Contains(err.Error(), "operator role") {
		t.Errorf("the role hint is wrong here: %v", err)
	}
	_, err = c.write(context.Background(), kindServices, "x@docker", mustObject(t, appService), modeUpdate)
	if !isStatus(err, http.StatusForbidden) || !strings.Contains(err.Error(), "docker provider") {
		t.Fatalf("provider-owned: %v", err)
	}
}

func TestViewerCannotWrite(t *testing.T) {
	f := newFakeAdmin(t)
	c := testClient(t, f, fakeViewerToken)
	_, err := c.write(context.Background(), kindServices, "app", mustObject(t, appService), modeCreate)
	if !isStatus(err, http.StatusForbidden) || !strings.Contains(err.Error(), "operator role") {
		t.Fatalf("got %v", err)
	}
	// but reading works
	if _, err := c.getAPI(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRejectedConfigurationSurfacesTheDiagnostics(t *testing.T) {
	f := newFakeAdmin(t)
	c := testClient(t, f, fakeOperatorToken)
	_, err := c.write(context.Background(), kindRoutes, "web", mustObject(t, webRoute), modeCreate)
	ae := asAPIError(err)
	if ae == nil || ae.Status != 422 || len(ae.Diagnostics) != 1 ||
		!strings.Contains(ae.Diagnostics[0], "routes.web.service: unknown service `app`") {
		t.Fatalf("got %#v", err)
	}
	if got := f.names(kindRoutes); len(got) != 0 {
		t.Error("a rejected write must change nothing")
	}
	// A document the model cannot parse is {"error": …}.
	_, err = c.write(context.Background(), kindRoutes, "bad@name", mustObject(t, webRoute), modeUpdate)
	if !isStatus(err, http.StatusForbidden) {
		t.Fatalf("got %v", err)
	}
}

func TestDeletingAReferencedServiceIsRefusedWithTheReason(t *testing.T) {
	f := newFakeAdmin(t)
	f.seed(kindServices, "app", mustObject(t, appService))
	f.seed(kindRoutes, "web", mustObject(t, webRoute))
	c := testClient(t, f, fakeOperatorToken)
	_, err := c.write(context.Background(), kindServices, "app", nil, modeDelete)
	ae := asAPIError(err)
	if ae == nil || ae.Status != 422 || !strings.Contains(err.Error(), "routes.web.service") {
		t.Fatalf("got %v", err)
	}
	if f.stored(kindServices, "app") == nil {
		t.Error("the service must still exist")
	}
}

func TestConflictIsReadAgainAndRetried(t *testing.T) {
	f := newFakeAdmin(t)
	c := testClient(t, f, fakeOperatorToken)
	var slept []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }

	f.interfere.Store(2) // two other writers get in first
	if _, err := c.write(context.Background(), kindServices, "app", mustObject(t, appService), modeCreate); err != nil {
		t.Fatal(err)
	}
	if f.stored(kindServices, "app") == nil || len(slept) != 2 {
		t.Errorf("stored=%v, backoffs=%v", f.stored(kindServices, "app"), slept)
	}
}

func TestConflictRetriesAreBounded(t *testing.T) {
	f := newFakeAdmin(t)
	c := testClient(t, f, fakeOperatorToken)
	c.conflictRetries = 3
	f.interfere.Store(100)
	_, err := c.write(context.Background(), kindServices, "app", mustObject(t, appService), modeCreate)
	if !isStatus(err, http.StatusPreconditionFailed) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "another writer is active") {
		t.Errorf("the message does not say what to do: %v", err)
	}
	if got := f.interfere.Load(); got != 100-4 {
		t.Errorf("1 try + 3 retries expected, interference left %d", got)
	}
}

func TestRateLimitWaitsForRetryAfter(t *testing.T) {
	f := newFakeAdmin(t)
	c := testClient(t, f, fakeOperatorToken)
	var slept []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	f.tooMany.Store(2)
	if _, err := c.write(context.Background(), kindServices, "app", mustObject(t, appService), modeCreate); err != nil {
		t.Fatal(err)
	}
	if len(slept) != 2 || slept[0] != time.Second {
		t.Errorf("waits = %v", slept)
	}
}

func TestContextCancellationStopsRetrying(t *testing.T) {
	f := newFakeAdmin(t)
	c := testClient(t, f, fakeOperatorToken)
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
	f.tooMany.Store(100)
	_, err := c.write(ctx, kindServices, "app", mustObject(t, appService), modeCreate)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestParallelWritesAreSerialisedAndNeverConflict(t *testing.T) {
	f := newFakeAdmin(t)
	f.putDelay = 5 * time.Millisecond
	// Two Client values for the same endpoint, as with two provider aliases: they share the lock.
	a, b := testClient(t, f, fakeOperatorToken), testClient(t, f, fakeOperatorToken)
	slept := 0
	var mu sync.Mutex
	count := func(context.Context, time.Duration) error { mu.Lock(); slept++; mu.Unlock(); return nil }
	a.sleep, b.sleep = count, count

	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := range 20 {
		for _, c := range []*Client{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				name := fmt.Sprintf("svc-%d-%p", i, c)
				_, err := c.write(context.Background(), kindServices, name, mustObject(t, appService), modeCreate)
				errs <- err
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := len(f.names(kindServices)); got != 40 {
		t.Errorf("%d services stored, want 40", got)
	}
	if m := f.maxInFlight.Load(); m != 1 {
		t.Errorf("writes overlapped: %d in flight at once", m)
	}
	if slept != 0 {
		t.Errorf("serialised writes must not hit 412 (%d retries)", slept)
	}
}

func TestValidateObjectDryRunsTheWholeDocument(t *testing.T) {
	f := newFakeAdmin(t)
	f.seed(kindServices, "app", mustObject(t, appService))
	c := testClient(t, f, fakeOperatorToken)
	problems, err := c.validateObject(context.Background(), kindRoutes, "web", mustObject(t, webRoute))
	if err != nil || len(problems) != 0 {
		t.Fatalf("problems=%v err=%v", problems, err)
	}
	problems, err = c.validateObject(context.Background(), kindRoutes, "web",
		mustObject(t, "{\"match\":\"Host(`a`)\",\"service\":\"missing\"}"))
	if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "unknown service `missing`") {
		t.Fatalf("problems=%v err=%v", problems, err)
	}
	if len(f.names(kindRoutes)) != 0 {
		t.Error("a dry run must not apply anything")
	}
	// Viewers cannot dry-run.
	v := testClient(t, f, fakeViewerToken)
	if _, err := v.validateObject(context.Background(), kindRoutes, "web", mustObject(t, webRoute)); !isStatus(err, 403) {
		t.Errorf("viewer: %v", err)
	}
}

func TestGetObjectFindsAnyOwner(t *testing.T) {
	f := newFakeAdmin(t)
	f.fileObject(kindServices, "fromfile")
	f.otherObject(kindServices, "dock@docker")
	f.seed(kindServices, "app", mustObject(t, appService))
	c := testClient(t, f, fakeViewerToken)
	for name, owner := range map[string]string{"fromfile": "file", "dock@docker": "docker", "app@api": "api"} {
		got, err := c.getObject(context.Background(), kindServices, name)
		if err != nil || got == nil || got.Owner != owner {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	got, err := c.getObject(context.Background(), kindServices, "nope")
	if err != nil || got != nil {
		t.Errorf("missing: %v %v", got, err)
	}
}

func TestReadsWaitOutRateLimits(t *testing.T) {
	f := newFakeAdmin(t)
	c := testClient(t, f, fakeOperatorToken)
	var waits []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	// The fake rate-limits only writes; wrap a read that fails twice with 429, then succeeds.
	calls := 0
	err := c.retryRateLimited(context.Background(), func() error {
		calls++
		if calls <= 2 {
			return &apiError{Op: "GET x", Status: http.StatusTooManyRequests, RetryAfter: 3 * time.Second}
		}
		return nil
	})
	if err != nil || calls != 3 || len(waits) != 2 || waits[0] != 3*time.Second {
		t.Fatalf("err=%v calls=%d waits=%v", err, calls, waits)
	}
	// Other errors are not retried, and the number of waits is bounded.
	calls = 0
	err = c.retryRateLimited(context.Background(), func() error { calls++; return &apiError{Status: 500} })
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	calls = 0
	err = c.retryRateLimited(context.Background(), func() error { calls++; return &apiError{Status: 429} })
	if !isStatus(err, 429) || calls != maxRateLimitWaits+1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
