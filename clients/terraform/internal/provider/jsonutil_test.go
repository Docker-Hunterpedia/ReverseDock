package provider

import (
	"testing"
)

func mustObject(t *testing.T, s string) map[string]any {
	t.Helper()
	o, err := decodeObject(s)
	if err != nil {
		t.Fatalf("decodeObject(%s): %v", s, err)
	}
	return o
}

func TestDecodeObjectRefusesNonObjectsAndTrailingData(t *testing.T) {
	for _, bad := range []string{``, `[]`, `"x"`, `1`, `{"a":1} {"b":2}`, `{"a":`, `null`} {
		if _, err := decodeObject(bad); err == nil {
			t.Errorf("decodeObject(%q) succeeded", bad)
		}
	}
	if _, err := decodeObject(" {\n \"a\" : 1 }\n"); err != nil {
		t.Errorf("whitespace around an object: %v", err)
	}
}

func TestEqualJSONIgnoresFormattingKeyOrderAndNumberSpelling(t *testing.T) {
	a := mustObject(t, `{"b":[1,2,{"x":1.0}],"a":"s","big":9007199254740993}`)
	b := mustObject(t, `{ "a":"s", "big":9007199254740993, "b":[1,2,{"x":1}] }`)
	if !equalJSON(a, b) {
		t.Error("equal documents compared unequal")
	}
	c := mustObject(t, `{"b":[1,2,{"x":1}],"a":"s","big":9007199254740992}`)
	if equalJSON(a, c) {
		t.Error("integers beyond 2^53 must stay distinct")
	}
	if equalJSON(mustObject(t, `{"a":[1,2]}`), mustObject(t, `{"a":[2,1]}`)) {
		t.Error("array order matters")
	}
}

func TestContainsToleratesFilledInDefaults(t *testing.T) {
	spec := mustObject(t, `{"match":"Host(`+"`a`"+`)","service":"app","timeouts":{"read":"5s"},"middlewares":[]}`)
	server := mustObject(t, `{"match":"Host(`+"`a`"+`)","service":"app","priority":0,"middlewares":[],"listeners":null,
		"timeouts":{"connect":null,"read":"5s","write":null},"enabled":true}`)
	if !contains(spec, server) {
		t.Error("a spec without defaults must be contained in the server's object")
	}
	if contains(server, spec) {
		t.Error("the server's object says more than the spec")
	}
	changed := mustObject(t, `{"match":"Host(`+"`a`"+`)","service":"other"}`)
	if contains(changed, server) {
		t.Error("a different value is not contained")
	}
	// An empty value in the spec means "unset": the server must not hold a value there.
	if contains(mustObject(t, `{"middlewares":[]}`), mustObject(t, `{"middlewares":["x"]}`)) {
		t.Error("an empty list is not contained in a filled one")
	}
	if contains(mustObject(t, `{"a":[1,2]}`), mustObject(t, `{"a":[1,2,3]}`)) {
		t.Error("arrays match element by element")
	}
}

func TestRestoreMaskedPutsSecretsBackByPathAndByUserName(t *testing.T) {
	prior := mustObject(t, `{"type":"basic_auth","users":["ann:$2y$05$aaa","bob:$2y$05$bbb"],"hmac_secret":"s3cret","note":"***"}`)
	read := mustObject(t, `{"type":"basic_auth","users":["bob:***","cy:***"],"hmac_secret":"***","note":"***","extra":{"k":"***"}}`)
	got := restoreMasked(read, prior).(map[string]any)
	if got["hmac_secret"] != "s3cret" {
		t.Errorf("hmac_secret = %v", got["hmac_secret"])
	}
	users := got["users"].([]any)
	if users[0] != "bob:$2y$05$bbb" {
		t.Errorf("bob was matched by position, not name: %v", users[0])
	}
	if users[1] != "cy:***" {
		t.Errorf("a user with no prior hash stays masked: %v", users[1])
	}
	if got["extra"].(map[string]any)["k"] != "***" {
		t.Error("a mask with no prior value stays as shown")
	}
	// The inputs are not modified.
	if read["hmac_secret"] != "***" {
		t.Error("restoreMasked modified its input")
	}
}

func TestReconcile(t *testing.T) {
	prior := mustObject(t, `{"match":"M","service":"app","timeouts":{"read":"1m"}}`)
	server := mustObject(t, `{"match":"M","service":"app","priority":0,"timeouts":{"connect":null,"read":"60s","write":null}}`)

	t.Run("same as after the last write: no drift, even though the API normalised 1m to 60s", func(t *testing.T) {
		spec, drifted := reconcile(prior, server, server)
		if drifted || !equalJSON(spec, prior) {
			t.Errorf("spec=%v drifted=%v", spec, drifted)
		}
	})
	t.Run("changed since: drift, and the spec becomes the server's object", func(t *testing.T) {
		changed := mustObject(t, `{"match":"M","service":"app","priority":7,"timeouts":{"connect":null,"read":"60s","write":null}}`)
		spec, drifted := reconcile(prior, server, changed)
		if !drifted || !equalJSON(spec, changed) {
			t.Errorf("spec=%v drifted=%v", spec, drifted)
		}
	})
	t.Run("no record of the last write: the spec only has to be contained", func(t *testing.T) {
		same := mustObject(t, `{"match":"M","service":"app","priority":0}`)
		spec, drifted := reconcile(mustObject(t, `{"match":"M","service":"app"}`), nil, same)
		if drifted || spec == nil {
			t.Errorf("drifted=%v", drifted)
		}
		_, drifted = reconcile(mustObject(t, `{"match":"M","service":"other"}`), nil, same)
		if !drifted {
			t.Error("a different service is drift")
		}
	})
	t.Run("import: the server's object, not drift", func(t *testing.T) {
		spec, drifted := reconcile(nil, nil, server)
		if drifted || !equalJSON(spec, server) {
			t.Errorf("spec=%v drifted=%v", spec, drifted)
		}
	})
	t.Run("drift keeps the secrets Terraform wrote", func(t *testing.T) {
		p := mustObject(t, `{"type":"hmac","hmac_secret":"s3cret"}`)
		before := mustObject(t, `{"type":"hmac","hmac_secret":"***"}`)
		after := mustObject(t, `{"type":"hmac","hmac_secret":"***","algorithm":"sha512"}`)
		spec, drifted := reconcile(p, before, after)
		if !drifted || spec["hmac_secret"] != "s3cret" || spec["algorithm"] != "sha512" {
			t.Errorf("spec=%v drifted=%v", spec, drifted)
		}
	})
}
