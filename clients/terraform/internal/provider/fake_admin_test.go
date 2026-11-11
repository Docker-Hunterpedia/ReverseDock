package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAdmin is a small stand-in for the admin API's object endpoints, written from the Rust
// handlers it copies (crates/rdock-admin/src/resources.rs and config_api.rs, the API
// provider in crates/rdock/src/engine/api.rs):
//
//   - `GET /api/v1/config/api` returns the API provider's objects with an `ETag` of the form
//     `"g<generation>-<16 hex of SHA-256>"`; secrets are shown as `***`, basic-auth users
//     as `name:***`, `${…}` references as written.
//   - `PUT` and `DELETE /api/v1/{routes,services,middlewares}/{name}` need the operator
//     role and `If-Match` (428 without, 412 with an old version, carrying the current ETag);
//     file-owned names answer 403, `name@provider` names answer 403 naming the provider,
//     deleting an absent object answers 404; a configuration with errors is refused as a
//     whole with 422 and a report (`result`, `error`, `diagnostics`); a document the model
//     cannot parse is 422 `{"error": …}`; a write that is applied bumps the generation and
//     answers 200 with the new ETag.
//   - Stored objects come back with defaults filled in and durations normalised, as serde
//     does for the Rust model (the exact fields differ from the real model: the provider must
//     not depend on them).
//   - `GET /api/v1/{kind}[/{name}]` shows the effective configuration: API objects as
//     `name@api`, file objects bare, other providers' as `name@provider`.
//   - `POST /api/v1/config/validate` (operator) is a dry run; `GET /api/v1/status`.
type fakeAdmin struct {
	t      *testing.T
	Server *httptest.Server

	mu         sync.Mutex
	generation int
	api        map[string]map[string]map[string]any // kind -> name -> stored object
	file       map[string]map[string]bool           // kind -> names owned by the file
	other      map[string]map[string]bool           // kind -> "name@provider"
	tokens     map[string]string                    // token -> role
	secrets    map[string]map[string]string         // kind/name -> real secret values by field

	// Test hooks.
	interfere   atomic.Int32 // the next n If-Match checks first see another writer's change
	tooMany     atomic.Int32 // the next n writes answer 429
	putDelay    time.Duration
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	requests    atomic.Int32
	lastHeaders atomic.Value // http.Header of the latest request
	redirectTo  string       // when set, GET /api/v1/status answers 307 to it
}

const (
	fakeOperatorToken = "rdk_pat_operator"
	fakeViewerToken   = "rdk_pat_viewer"
)

var fakeNameRule = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func newFakeAdmin(t *testing.T) *fakeAdmin {
	t.Helper()
	f := &fakeAdmin{
		t:          t,
		generation: 1,
		api:        map[string]map[string]map[string]any{kindRoutes: {}, kindServices: {}, kindMiddlewares: {}},
		file:       map[string]map[string]bool{kindRoutes: {}, kindServices: {}, kindMiddlewares: {}},
		other:      map[string]map[string]bool{kindRoutes: {}, kindServices: {}, kindMiddlewares: {}},
		tokens:     map[string]string{fakeOperatorToken: "operator", fakeViewerToken: "viewer"},
		secrets:    map[string]map[string]string{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

// --- document helpers -------------------------------------------------------------------

func (f *fakeAdmin) etag() string {
	raw, _ := json.Marshal(f.fragment(false))
	sum := sha256.Sum256(raw)
	return fmt.Sprintf(`"g%d-%s"`, f.generation, hex.EncodeToString(sum[:8]))
}

func (f *fakeAdmin) fragment(masked bool) map[string]any {
	out := map[string]any{}
	for kind, objs := range f.api {
		section := map[string]any{}
		for name, obj := range objs {
			if masked {
				section[name] = maskObject(obj)
			} else {
				section[name] = obj
			}
		}
		out[kind] = section
	}
	return out
}

var secretFields = map[string]bool{"secret": true, "hmac_secret": true, "key_password": true}

func maskObject(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			if s, ok := x.(string); ok && secretFields[k] && !strings.HasPrefix(s, "${") {
				out[k] = maskedValue
				continue
			}
			if k == "users" {
				if list, ok := x.([]any); ok {
					masked := make([]any, len(list))
					for i, e := range list {
						s, _ := e.(string)
						if name, _, found := strings.Cut(s, ":"); found {
							masked[i] = name + ":" + maskedValue
						} else {
							masked[i] = e
						}
					}
					out[k] = masked
					continue
				}
			}
			out[k] = maskObject(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = maskObject(x)
		}
		return out
	}
	return v
}

// restore puts the stored secret back where the candidate kept `***`, as restore_masked does.
func restoreSecrets(candidate, current any) (any, error) {
	switch c := candidate.(type) {
	case map[string]any:
		cur, _ := current.(map[string]any)
		for k, v := range c {
			if s, ok := v.(string); ok && secretFields[k] && s == maskedValue {
				kept, ok := cur[k].(string)
				if !ok {
					return nil, fmt.Errorf("%s is `***`, the masked value; write the secret or a ${file:…} reference", k)
				}
				c[k] = kept
				continue
			}
			if k == "users" {
				if list, ok := v.([]any); ok {
					curUsers, _ := cur[k].([]any)
					for i, e := range list {
						s, _ := e.(string)
						name, found := strings.CutSuffix(s, ":"+maskedValue)
						if !found {
							continue
						}
						restored := ""
						for _, ce := range curUsers {
							cs, _ := ce.(string)
							if n, _, ok := strings.Cut(cs, ":"); ok && n == name {
								restored = cs
							}
						}
						if restored == "" {
							return nil, fmt.Errorf("user %s has no current password hash to keep; write name:hash", name)
						}
						list[i] = restored
					}
					continue
				}
			}
			nv, err := restoreSecrets(v, cur[k])
			if err != nil {
				return nil, err
			}
			c[k] = nv
		}
	}
	return candidate, nil
}

// store fills in defaults and normalises durations like the Rust model's serialisation.
func store(kind string, obj map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range obj {
		out[k] = v
	}
	switch kind {
	case kindRoutes:
		setDefault(out, "listeners", nil)
		setDefault(out, "priority", float64(0))
		setDefault(out, "middlewares", []any{})
		setDefault(out, "service", nil)
		setDefault(out, "tls", nil)
		setDefault(out, "mirror", nil)
		setDefault(out, "max_body", nil)
		setDefault(out, "enabled", true)
		timeouts, _ := out["timeouts"].(map[string]any)
		norm := map[string]any{"connect": nil, "read": nil, "write": nil}
		for k, v := range timeouts {
			if s, ok := v.(string); ok && s == "1m" {
				v = "60s"
			}
			norm[k] = v
		}
		out["timeouts"] = norm
	case kindServices:
		setDefault(out, "sticky", nil)
		setDefault(out, "load_balancing", "round_robin")
	case kindMiddlewares:
		// An internally tagged enum: only the fields given are shown.
	}
	return out
}

func setDefault(m map[string]any, k string, v any) {
	if _, ok := m[k]; !ok {
		m[k] = v
	}
}

// --- validation -------------------------------------------------------------------------

type diagnostic struct {
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
	Hint     string `json:"hint,omitempty"`
}

// parseDocument is api::parse: unknown sections and `@` in names are refused.
func parseDocument(doc map[string]any) error {
	for k, v := range doc {
		if k != kindRoutes && k != kindServices && k != kindMiddlewares {
			return fmt.Errorf("%s: unknown field `%s`", k, k)
		}
		section, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: invalid type, expected a map", k)
		}
		for name, obj := range section {
			if strings.Contains(name, "@") {
				return fmt.Errorf("`%s`: names in the API configuration cannot contain `@`", name)
			}
			if _, ok := obj.(map[string]any); !ok {
				return fmt.Errorf("%s.%s: invalid type, expected a map", k, name)
			}
		}
	}
	return nil
}

func (f *fakeAdmin) known(kind, ref string, doc map[string]map[string]map[string]any) bool {
	if strings.Contains(ref, "@") {
		return true // resolved at runtime, as in check_reference
	}
	if _, ok := doc[kind][ref]; ok {
		return true
	}
	return f.file[kind][ref]
}

func (f *fakeAdmin) validate(doc map[string]map[string]map[string]any) []diagnostic {
	var out []diagnostic
	bad := func(path, msg string) { out = append(out, diagnostic{Severity: "error", Path: path, Message: msg}) }
	for kind, objs := range doc {
		for name, obj := range objs {
			if !fakeNameRule.MatchString(name) {
				bad(kind+"."+name, "invalid name `"+name+"`")
			}
			switch kind {
			case kindRoutes:
				if _, ok := obj["match"]; !ok {
					bad("routes."+name+".match", "missing field `match`")
				}
				if s, ok := obj["service"].(string); ok && !f.known(kindServices, s, doc) {
					bad("routes."+name+".service", "unknown service `"+s+"`")
				}
				if list, ok := obj["middlewares"].([]any); ok {
					for i, m := range list {
						if s, ok := m.(string); ok && !f.known(kindMiddlewares, s, doc) {
							bad(fmt.Sprintf("routes.%s.middlewares[%d]", name, i), "unknown middleware `"+s+"`")
						}
					}
				}
			case kindServices:
				if list, ok := obj["backends"].([]any); !ok || len(list) == 0 {
					bad("services."+name+".backends", "a service needs at least one backend")
				}
			case kindMiddlewares:
				if _, ok := obj["type"].(string); !ok {
					bad("middlewares."+name+".type", "missing field `type`")
				}
			}
		}
	}
	return out
}

// --- HTTP ---------------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func (f *fakeAdmin) serve(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	f.lastHeaders.Store(r.Header.Clone())
	role := ""
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		role = f.tokens[tok]
	}
	if role == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		errBody(w, http.StatusUnauthorized, "no valid session or token")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // api v1 …
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "v1" {
		errBody(w, http.StatusNotFound, "not found")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rest := parts[2:]
	switch {
	case len(rest) == 1 && rest[0] == "status" && r.Method == http.MethodGet:
		if f.redirectTo != "" {
			http.Redirect(w, r, f.redirectTo, http.StatusTemporaryRedirect)
			return
		}
		writeJSON(w, 200, map[string]any{"version": "0.0.0-fake", "commit": "abc123", "ready": true,
			"generation": f.generation, "started_at": "2026-11-11T00:00:00Z", "origin": "file",
			"listeners": []any{}, "providers": map[string]any{}})
	case len(rest) == 2 && rest[0] == "config" && rest[1] == "api" && r.Method == http.MethodGet:
		w.Header().Set("ETag", f.etag())
		writeJSON(w, 200, f.fragment(true))
	case len(rest) == 2 && rest[0] == "config" && rest[1] == "validate" && r.Method == http.MethodPost:
		if role != "operator" {
			errBody(w, http.StatusForbidden, "this needs the operator role")
			return
		}
		var doc map[string]any
		if json.NewDecoder(r.Body).Decode(&doc) != nil {
			errBody(w, 422, "not a configuration document")
			return
		}
		if err := parseDocument(doc); err != nil {
			errBody(w, 422, err.Error())
			return
		}
		candidate := toDoc(doc)
		diags := f.validate(candidate)
		writeJSON(w, 200, map[string]any{"valid": len(diags) == 0, "diagnostics": diags, "diff": ""})
	case len(rest) == 1 && r.Method == http.MethodGet && f.api[rest[0]] != nil:
		list := []any{}
		for name, spec := range f.effective(rest[0]) {
			list = append(list, map[string]any{"name": name, "owner": ownerOf(name), "spec": spec})
		}
		writeJSON(w, 200, list)
	case len(rest) == 2 && f.api[rest[0]] != nil:
		f.object(w, r, role, rest[0], rest[1])
	default:
		errBody(w, http.StatusNotFound, "not found")
	}
}

func ownerOf(name string) string {
	if _, p, ok := strings.Cut(name, "@"); ok {
		return p
	}
	return "file"
}

func (f *fakeAdmin) effective(kind string) map[string]any {
	out := map[string]any{}
	for name := range f.file[kind] {
		out[name] = map[string]any{"fake": "file object"}
	}
	for name := range f.other[kind] {
		out[name] = map[string]any{"fake": "provider object"}
	}
	for name, obj := range f.api[kind] {
		out[name+"@api"] = maskObject(obj)
	}
	return out
}

func toDoc(doc map[string]any) map[string]map[string]map[string]any {
	out := map[string]map[string]map[string]any{kindRoutes: {}, kindServices: {}, kindMiddlewares: {}}
	for kind, v := range doc {
		for name, obj := range v.(map[string]any) {
			out[kind][name] = obj.(map[string]any)
		}
	}
	return out
}

func (f *fakeAdmin) object(w http.ResponseWriter, r *http.Request, role, kind, name string) {
	if r.Method == http.MethodGet {
		spec, ok := f.effective(kind)[name]
		if !ok {
			errBody(w, http.StatusNotFound, "no such object")
			return
		}
		writeJSON(w, 200, map[string]any{"name": name, "owner": ownerOf(name), "spec": spec})
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		errBody(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if role != "operator" {
		errBody(w, http.StatusForbidden, "this needs the operator role")
		return
	}
	if r.Method == http.MethodPut {
		n := f.inFlight.Add(1)
		for {
			m := f.maxInFlight.Load()
			if n <= m || f.maxInFlight.CompareAndSwap(m, n) {
				break
			}
		}
		defer f.inFlight.Add(-1)
		if f.putDelay > 0 {
			f.mu.Unlock()
			time.Sleep(f.putDelay)
			f.mu.Lock()
		}
	}
	if f.tooMany.Load() > 0 {
		f.tooMany.Add(-1)
		w.Header().Set("Retry-After", "1")
		errBody(w, http.StatusTooManyRequests, "too many configuration writes; try again after 1 second")
		return
	}
	tag := r.Header.Get("If-Match")
	if tag == "" {
		errBody(w, http.StatusPreconditionRequired, "send If-Match with the ETag from GET /api/v1/config/api")
		return
	}
	bare, provider, hasProvider := strings.Cut(name, "@")
	if hasProvider && provider != "api" {
		errBody(w, http.StatusForbidden, "this object belongs to the "+provider+" provider; change it there")
		return
	}
	if f.file[kind][bare] {
		errBody(w, http.StatusForbidden, "this object belongs to the configuration file; change it there")
		return
	}
	if f.interfere.Load() > 0 {
		f.interfere.Add(-1)
		f.generation++ // another writer applied something meanwhile
	}
	if tag != f.etag() {
		w.Header().Set("ETag", f.etag())
		errBody(w, http.StatusPreconditionFailed, "the configuration changed since you read it; fetch it again")
		return
	}
	candidate := map[string]any{}
	for kd, objs := range f.api {
		section := map[string]any{}
		for n, o := range objs {
			section[n] = o
		}
		candidate[kd] = section
	}
	if r.Method == http.MethodPut {
		var obj map[string]any
		if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
			errBody(w, http.StatusBadRequest, "the body is not JSON")
			return
		}
		current := map[string]any{}
		if old, ok := f.api[kind][bare]; ok {
			current = old
		}
		if _, err := restoreSecrets(obj, current); err != nil {
			errBody(w, 422, kind+"."+bare+"."+err.Error())
			return
		}
		candidate[kind].(map[string]any)[bare] = store(kind, obj)
	} else {
		if _, ok := f.api[kind][bare]; !ok {
			errBody(w, http.StatusNotFound, "no such object")
			return
		}
		delete(candidate[kind].(map[string]any), bare)
	}
	if err := parseDocument(candidate); err != nil {
		errBody(w, 422, err.Error())
		return
	}
	if diags := f.validate(toDoc(candidate)); len(diags) > 0 {
		writeJSON(w, 422, map[string]any{"result": "rejected", "error": "the API configuration has errors",
			"diagnostics": diags})
		return
	}
	f.api = toDoc(candidate)
	f.generation++
	w.Header().Set("ETag", f.etag())
	writeJSON(w, 200, map[string]any{"result": "applied", "trigger": "api", "generation": f.generation, "diagnostics": []any{}})
}

// --- direct manipulation for tests -------------------------------------------------------

func (f *fakeAdmin) seed(kind, name string, obj map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.api[kind][name] = store(kind, obj)
	f.generation++
}

func (f *fakeAdmin) stored(kind, name string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.api[kind][name]
}

func (f *fakeAdmin) names(kind string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for n := range f.api[kind] {
		out = append(out, n)
	}
	return out
}

func (f *fakeAdmin) fileObject(kind, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.file[kind][name] = true
}

func (f *fakeAdmin) otherObject(kind, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.other[kind][name] = true
}
