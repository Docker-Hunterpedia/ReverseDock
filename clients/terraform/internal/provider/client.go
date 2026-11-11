package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	rdock "github.com/Docker-Hunterpedia/ReverseDock/clients/go"
)

// The sections of the configuration that the per-object endpoints of the admin API serve
// (`/api/v1/{kind}` in schema/openapi.json). TCP routes and services are not among them,
// and the API document refuses them, so the provider has no resources for them.
const (
	kindRoutes      = "routes"
	kindServices    = "services"
	kindMiddlewares = "middlewares"
)

const (
	defaultTimeout         = 30 * time.Second
	defaultConflictRetries = 5
	maxRateLimitWaits      = 30
	maxRetryAfter          = 30 * time.Second
)

// clientConfig is everything needed to talk to one admin API.
type clientConfig struct {
	Endpoint        string
	Token           string
	CACertFile      string
	Timeout         time.Duration
	ConflictRetries int
	UserAgent       string
	ValidateOnPlan  bool
}

// Client is the admin API as the provider uses it. All writes through one endpoint are
// serialised by a lock shared by every Client for that endpoint in the process: Terraform
// applies resources in parallel, but the API provider's objects are one document with one
// version.
type Client struct {
	api             *rdock.ClientWithResponses
	endpoint        string
	conflictRetries int
	validateOnPlan  bool
	sleep           func(context.Context, time.Duration) error
}

var writeLocks sync.Map // endpoint -> *sync.Mutex

func lockFor(endpoint string) *sync.Mutex {
	l, _ := writeLocks.LoadOrStore(endpoint, &sync.Mutex{})
	return l.(*sync.Mutex)
}

// parseEndpoint checks the admin URL. Plain HTTP is accepted only for a loopback address,
// as the admin API itself only listens in clear text there (any other listener needs TLS)
// and the CLI sends its token to loopback only: a bearer token must not cross a network
// unencrypted.
func parseEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not a URL such as http://127.0.0.1:2080 or https://rdock.example.com:2080", raw)
	}
	if u.User != nil {
		return "", errors.New("the endpoint must not carry credentials; use the token attribute")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("the endpoint must not have a query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return "", fmt.Errorf("refusing to send the token over plain HTTP to %s: use https, or reach the admin API through a loopback address (for example an SSH tunnel)", u.Hostname())
		}
	default:
		return "", fmt.Errorf("unsupported scheme %q: use http (loopback only) or https", u.Scheme)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newHTTPClient(caFile string, timeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // the path is the operator's own setting
		if err != nil {
			return nil, fmt.Errorf("reading ca_cert_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_cert_file %s holds no PEM certificate", caFile)
		}
		tlsConfig.RootCAs = pool
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// The admin API never redirects; following one would send the token elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func newClient(cfg clientConfig) (*Client, error) {
	endpoint, err := parseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("no token: set the token attribute or RDOCK_ADMIN_TOKEN (an API token with the operator role to manage objects, viewer to only read)")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.ConflictRetries <= 0 {
		cfg.ConflictRetries = defaultConflictRetries
	}
	httpClient, err := newHTTPClient(cfg.CACertFile, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(cfg.Token)
	agent := cfg.UserAgent
	api, err := rdock.NewClientWithResponses(endpoint,
		rdock.WithHTTPClient(httpClient),
		rdock.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("User-Agent", agent)
			req.Header.Set("Accept", "application/json")
			return nil
		}))
	if err != nil {
		return nil, err
	}
	return &Client{
		api:             api,
		endpoint:        endpoint,
		conflictRetries: cfg.ConflictRetries,
		validateOnPlan:  cfg.ValidateOnPlan,
		sleep:           sleepContext,
	}, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// apiError is a refusal by the admin API.
type apiError struct {
	Op          string
	Status      int
	Message     string
	Diagnostics []string
	ETag        string
	RetryAfter  time.Duration
}

func (e *apiError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: HTTP %d", e.Op, e.Status)
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	}
	for _, d := range e.Diagnostics {
		fmt.Fprintf(&b, "\n  - %s", d)
	}
	switch e.Status {
	case http.StatusUnauthorized:
		b.WriteString("\n  (the token is missing, expired or revoked)")
	case http.StatusForbidden:
		if e.Message == "" || !strings.Contains(e.Message, "belongs to") {
			b.WriteString("\n  (writing needs a token with the operator role, and admin.api_writes must not be false)")
		}
	}
	return b.String()
}

// newAPIError builds the error for a non-success answer, reading the two shapes the API
// uses: {"error": "…"} and a reload report with `diagnostics`.
func newAPIError(op string, status int, header http.Header, body []byte) *apiError {
	e := &apiError{Op: op, Status: status, ETag: header.Get("ETag")}
	if ra := header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
			e.RetryAfter = time.Duration(secs) * time.Second
		}
	}
	parsed, err := decodeJSON(body)
	obj, isObj := parsed.(map[string]any)
	if err != nil || !isObj {
		text := strings.TrimSpace(string(body))
		if len(text) > 300 {
			text = text[:300] + "…"
		}
		e.Message = text
		return e
	}
	if msg, ok := obj["error"].(string); ok {
		e.Message = msg
	}
	if list, ok := obj["diagnostics"].([]any); ok {
		for _, item := range list {
			d, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if sev, _ := d["severity"].(string); sev == "warning" {
				continue
			}
			e.Diagnostics = append(e.Diagnostics, describeDiagnostic(d))
		}
	}
	return e
}

func asAPIError(err error) *apiError {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae
	}
	return nil
}

func isStatus(err error, status int) bool {
	ae := asAPIError(err)
	return ae != nil && ae.Status == status
}

// retryRateLimited runs fn again after `429 Too Many Requests`, waiting for Retry-After
// (callers may make 20 requests a second, bursts of 100; configuration writes and dry runs
// 5 a second), a bounded number of times.
func (c *Client) retryRateLimited(ctx context.Context, fn func() error) error {
	for waits := 0; ; waits++ {
		err := fn()
		ae := asAPIError(err)
		if ae == nil || ae.Status != http.StatusTooManyRequests || waits >= maxRateLimitWaits {
			return err
		}
		if err := c.sleep(ctx, retryDelay(ae.RetryAfter)); err != nil {
			return err
		}
	}
}

func retryDelay(retryAfter time.Duration) time.Duration {
	return min(max(retryAfter, time.Second), maxRetryAfter)
}

// apiDocument is `GET /api/v1/config/api`: the API provider's objects and their version.
type apiDocument struct {
	Objects map[string]any
	ETag    string
}

// object returns the API's rendering of one object, or nil.
func (d *apiDocument) object(kind, name string) map[string]any {
	section, _ := d.Objects[kind].(map[string]any)
	obj, _ := section[name].(map[string]any)
	return obj
}

func (c *Client) getAPI(ctx context.Context) (doc *apiDocument, err error) {
	err = c.retryRateLimited(ctx, func() error {
		doc, err = c.getAPIOnce(ctx)
		return err
	})
	return doc, err
}

func (c *Client) getAPIOnce(ctx context.Context) (*apiDocument, error) {
	const op = "GET /api/v1/config/api"
	resp, err := c.api.GetApiWithResponse(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, newAPIError(op, resp.StatusCode(), resp.HTTPResponse.Header, resp.Body)
	}
	parsed, err := decodeJSON(resp.Body)
	obj, ok := parsed.(map[string]any)
	if err != nil || !ok {
		return nil, fmt.Errorf("%s: the answer is not a JSON object", op)
	}
	etag := resp.HTTPResponse.Header.Get("ETag")
	if etag == "" {
		return nil, fmt.Errorf("%s: the answer has no ETag, so writes could not be made conditional", op)
	}
	return &apiDocument{Objects: obj, ETag: etag}, nil
}

// ownedObject is one object of the effective configuration with its owner.
type ownedObject struct {
	Name  string
	Owner string
	Spec  map[string]any
}

// getObject reads one object of any owner (`GET /api/v1/{kind}/{name}`); nil when it does
// not exist. Objects of providers are named `name@provider`; API objects `name@api`.
func (c *Client) getObject(ctx context.Context, kind, name string) (found *ownedObject, err error) {
	err = c.retryRateLimited(ctx, func() error {
		found, err = c.getObjectOnce(ctx, kind, name)
		return err
	})
	return found, err
}

func (c *Client) getObjectOnce(ctx context.Context, kind, name string) (*ownedObject, error) {
	op := fmt.Sprintf("GET /api/v1/%s/%s", kind, name)
	resp, err := c.api.GetObjectWithResponse(ctx, rdock.GetObjectParamsKind(kind), name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	switch resp.StatusCode() {
	case http.StatusOK:
		parsed, err := decodeJSON(resp.Body)
		obj, ok := parsed.(map[string]any)
		if err != nil || !ok {
			return nil, fmt.Errorf("%s: the answer is not a JSON object", op)
		}
		spec, _ := obj["spec"].(map[string]any)
		owner, _ := obj["owner"].(string)
		return &ownedObject{Name: name, Owner: owner, Spec: spec}, nil
	case http.StatusNotFound:
		return nil, nil //nolint:nilnil // absence is not an error here
	default:
		return nil, newAPIError(op, resp.StatusCode(), resp.HTTPResponse.Header, resp.Body)
	}
}

// getStatus reads `GET /api/v1/status`.
func (c *Client) getStatus(ctx context.Context) (doc map[string]any, err error) {
	err = c.retryRateLimited(ctx, func() error {
		doc, err = c.getStatusOnce(ctx)
		return err
	})
	return doc, err
}

func (c *Client) getStatusOnce(ctx context.Context) (map[string]any, error) {
	const op = "GET /api/v1/status"
	resp, err := c.api.StatusWithResponse(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, newAPIError(op, resp.StatusCode(), resp.HTTPResponse.Header, resp.Body)
	}
	parsed, err := decodeJSON(resp.Body)
	obj, ok := parsed.(map[string]any)
	if err != nil || !ok {
		return nil, fmt.Errorf("%s: the answer is not a JSON object", op)
	}
	return obj, nil
}

// validateObject dry-runs the API document as it would be with `spec` as the object
// `kind/name` (`POST /api/v1/config/validate`; operator role). It returns the error
// diagnostics, empty when the document is valid.
func (c *Client) validateObject(ctx context.Context, kind, name string, spec map[string]any) ([]string, error) {
	const op = "POST /api/v1/config/validate"
	doc, err := c.getAPI(ctx)
	if err != nil {
		return nil, err
	}
	candidate := withObject(doc.Objects, kind, name, spec)
	raw, err := encodeJSON(candidate)
	if err != nil {
		return nil, err
	}
	var (
		status int
		body   []byte
	)
	err = c.retryRateLimited(ctx, func() error {
		resp, err := c.api.ValidateWithBodyWithResponse(ctx, "application/json", strings.NewReader(raw))
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		status, body = resp.StatusCode(), resp.Body
		if status != http.StatusOK {
			return newAPIError(op, status, resp.HTTPResponse.Header, body)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	parsed, err := decodeJSON(body)
	obj, ok := parsed.(map[string]any)
	if err != nil || !ok {
		return nil, fmt.Errorf("%s: the answer is not a JSON object", op)
	}
	if valid, _ := obj["valid"].(bool); valid {
		return nil, nil
	}
	ae := newAPIError(op, http.StatusOK, http.Header{}, body)
	if len(ae.Diagnostics) == 0 {
		ae.Diagnostics = []string{"the configuration would not be accepted"}
	}
	return ae.Diagnostics, nil
}

// withObject returns a copy of the document with one object replaced, or removed when spec
// is nil.
func withObject(doc map[string]any, kind, name string, spec map[string]any) map[string]any {
	out := make(map[string]any, len(doc)+1)
	for k, v := range doc {
		out[k] = v
	}
	section := map[string]any{}
	if old, ok := doc[kind].(map[string]any); ok {
		for k, v := range old {
			section[k] = v
		}
	}
	if spec == nil {
		delete(section, name)
	} else {
		section[name] = spec
	}
	out[kind] = section
	return out
}

// writeMode says what a mutation expects to find.
type writeMode int

const (
	modeCreate writeMode = iota // the name must be free
	modeUpdate                  // create or replace
	modeDelete
)

var errAlreadyExists = errors.New("an object with this name already exists in the API's objects")

// writeResult is the API's rendering of the object right after a write, and the version of
// the API objects it left behind.
type writeResult struct {
	Canonical map[string]any
	ETag      string
}

// write creates, replaces or deletes one API-owned object. It holds the endpoint's write
// lock, reads the current version of the API objects, sends the change with If-Match, and
// on 412 (somebody else wrote in between, for example the dashboard or another Terraform
// run) reads again and retries, at most conflictRetries times. On 429 it waits for
// Retry-After (the API accepts five configuration writes a second) and tries again.
func (c *Client) write(ctx context.Context, kind, name string, spec map[string]any, mode writeMode) (*writeResult, error) {
	lock := lockFor(c.endpoint)
	lock.Lock()
	defer lock.Unlock()

	conflicts, waits := 0, 0
	for {
		doc, err := c.getAPI(ctx)
		if err == nil {
			err = c.send(ctx, doc, kind, name, spec, mode)
		}
		if err == nil {
			break
		}
		ae := asAPIError(err)
		switch {
		case ae != nil && ae.Status == http.StatusPreconditionFailed && conflicts < c.conflictRetries:
			conflicts++
			if err := c.sleep(ctx, time.Duration(conflicts)*50*time.Millisecond); err != nil {
				return nil, err
			}
		case ae != nil && ae.Status == http.StatusTooManyRequests && waits < maxRateLimitWaits:
			waits++
			if err := c.sleep(ctx, retryDelay(ae.RetryAfter)); err != nil {
				return nil, err
			}
		case ae != nil && ae.Status == http.StatusPreconditionFailed:
			return nil, fmt.Errorf("%w\n  (the API objects changed %d times while this change was being applied; another writer is active. Run it again)", ae, conflicts+1)
		default:
			return nil, err
		}
	}
	if mode == modeDelete {
		return &writeResult{}, nil
	}
	after, err := c.getAPI(ctx)
	if err != nil {
		return nil, err
	}
	canonical := after.object(kind, name)
	if canonical == nil {
		return nil, fmt.Errorf("the API accepted %s/%s but does not show it afterwards", kind, name)
	}
	return &writeResult{Canonical: canonical, ETag: after.ETag}, nil
}

// send makes one conditional request against the version in doc.
func (c *Client) send(ctx context.Context, doc *apiDocument, kind, name string, spec map[string]any, mode writeMode) error {
	if mode == modeCreate && doc.object(kind, name) != nil {
		return fmt.Errorf("%s/%s: %w; import it with `terraform import` or choose another name", kind, name, errAlreadyExists)
	}
	var (
		op     string
		status int
		header http.Header
		body   []byte
	)
	if mode == modeDelete {
		op = fmt.Sprintf("DELETE /api/v1/%s/%s", kind, name)
		resp, err := c.api.DeleteObjectWithResponse(ctx, rdock.DeleteObjectParamsKind(kind), name,
			&rdock.DeleteObjectParams{IfMatch: doc.ETag})
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		status, header, body = resp.StatusCode(), resp.HTTPResponse.Header, resp.Body
	} else {
		op = fmt.Sprintf("PUT /api/v1/%s/%s", kind, name)
		raw, err := encodeJSON(spec)
		if err != nil {
			return err
		}
		resp, err := c.api.PutObjectWithBodyWithResponse(ctx, rdock.PutObjectParamsKind(kind), name,
			&rdock.PutObjectParams{IfMatch: doc.ETag}, "application/json", bytes.NewReader([]byte(raw)))
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		status, header, body = resp.StatusCode(), resp.HTTPResponse.Header, resp.Body
	}
	if status != http.StatusOK {
		return newAPIError(op, status, header, body)
	}
	return nil
}
