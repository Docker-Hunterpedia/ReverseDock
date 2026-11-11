package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

// maskedValue is what the admin API shows in place of a secret written in the
// configuration (`GET /api/v1/config/api` masks it; `${file:…}` and `${env:…}`
// references are shown as written).
const maskedValue = "***"

// decodeJSON parses one JSON value, keeping numbers as json.Number so that large
// integers survive a round trip.
func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the JSON value")
	}
	return v, nil
}

// decodeObject parses a JSON object (the spec of a route, service or middleware).
func decodeObject(raw string) (map[string]any, error) {
	v, err := decodeJSON([]byte(raw))
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("the spec must be a JSON object")
	}
	return obj, nil
}

// encodeJSON writes v compactly with sorted keys (Go sorts map keys) and without HTML
// escaping.
func encodeJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// normalize turns json.Number into int64 or float64 so that 1, 1.0 and 1e0 compare equal.
func normalize(v any) any {
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		if f, err := t.Float64(); err == nil {
			if f > -(1<<53) && f < 1<<53 && f == math.Trunc(f) {
				return int64(f)
			}
			return f
		}
		return t.String()
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = normalize(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = normalize(x)
		}
		return out
	default:
		return v
	}
}

// equalJSON reports whether two decoded JSON values are semantically equal.
func equalJSON(a, b any) bool {
	return equalNormalized(normalize(a), normalize(b))
}

func equalNormalized(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !equalNormalized(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equalNormalized(x[i], y[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

// isEmpty is true for null and for empty containers: what an unset optional field looks
// like once the admin API has filled in its defaults.
func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	default:
		return false
	}
}

// contains reports whether everything `sub` says is also said by `super`: the admin API
// returns objects with every default filled in (`priority: 0`, `middlewares: []`,
// `enabled: true`…), so a spec that omits them is still "the same" as the stored object.
// Arrays must match element by element.
func contains(sub, super any) bool {
	return containsNormalized(normalize(sub), normalize(super))
}

func containsNormalized(sub, super any) bool {
	if isEmpty(sub) {
		return isEmpty(super)
	}
	switch s := sub.(type) {
	case map[string]any:
		t, ok := super.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range s {
			if !containsNormalized(v, t[k]) {
				return false
			}
		}
		return true
	case []any:
		t, ok := super.([]any)
		if !ok || len(s) != len(t) {
			return false
		}
		for i := range s {
			if !containsNormalized(s[i], t[i]) {
				return false
			}
		}
		return true
	default:
		return sub == super
	}
}

// restoreMasked returns a copy of `read` in which every secret the API masked is put back
// from `prior` (the spec Terraform last wrote): `***` becomes the prior string at the same
// place, and a basic-auth entry `name:***` becomes the prior entry for that name. A mask
// with no prior value stays as the API showed it.
func restoreMasked(read, prior any) any {
	switch r := read.(type) {
	case map[string]any:
		p, _ := prior.(map[string]any)
		out := make(map[string]any, len(r))
		for k, v := range r {
			out[k] = restoreMasked(v, p[k])
		}
		return out
	case []any:
		p, _ := prior.([]any)
		out := make([]any, len(r))
		for i, v := range r {
			var pv any
			if i < len(p) {
				pv = p[i]
			}
			if s, ok := v.(string); ok && strings.HasSuffix(s, ":"+maskedValue) {
				// Basic-auth users are matched by name, not position (the API does the same).
				out[i] = restoreUser(s, p)
				continue
			}
			out[i] = restoreMasked(v, pv)
		}
		return out
	case string:
		if r == maskedValue {
			if s, ok := prior.(string); ok {
				return s
			}
		}
		return r
	default:
		return read
	}
}

func restoreUser(masked string, prior []any) string {
	name := strings.TrimSuffix(masked, ":"+maskedValue)
	for _, e := range prior {
		if s, ok := e.(string); ok {
			if n, _, found := strings.Cut(s, ":"); found && n == name && !strings.HasSuffix(s, ":"+maskedValue) {
				return s
			}
		}
	}
	return masked
}

// reconcile decides what Terraform should hold as the spec after reading the object from
// the API.
//
//   - prior is the spec in state (nil on import), canonical the API's own rendering of the
//     object right after Terraform last wrote or accepted it (nil when unknown),
//     server the object as the API shows it now.
//   - The API normalises what it stores (defaults, durations), so the user's text is never
//     compared with the server's directly. The object has not drifted when the server shows
//     exactly what it showed after our last write. Without that record (state from an
//     older provider) the object has not drifted when it still says everything the spec
//     says.
//   - On drift, or on import, the spec becomes the server's object, with masked secrets put
//     back from the prior spec where there was one.
func reconcile(prior map[string]any, canonical, server map[string]any) (spec map[string]any, drifted bool) {
	if prior != nil {
		if canonical != nil {
			if equalJSON(canonical, server) {
				return prior, false
			}
		} else if contains(prior, server) {
			return prior, false
		}
	}
	restored, _ := restoreMasked(server, prior).(map[string]any)
	return restored, prior != nil
}

// describeDiagnostic formats one entry of an API diagnostics list.
func describeDiagnostic(d map[string]any) string {
	path, _ := d["path"].(string)
	msg, _ := d["message"].(string)
	hint, _ := d["hint"].(string)
	var b strings.Builder
	if path != "" {
		fmt.Fprintf(&b, "%s: ", path)
	}
	b.WriteString(msg)
	if hint != "" {
		fmt.Fprintf(&b, " (%s)", strings.Join(strings.Fields(hint), " "))
	}
	return b.String()
}
