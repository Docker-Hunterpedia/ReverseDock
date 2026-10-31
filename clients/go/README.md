# ReverseDock Go client

A Go client for the ReverseDock admin API, generated from [`schema/openapi.json`](../../schema/openapi.json) with [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen) v2.8.0 (OpenAPI 3.1 support since v2.8.0, released 2026-07-17).

```go
import rdock "github.com/Docker-Hunterpedia/ReverseDock/clients/go"

client, err := rdock.NewClientWithResponses("http://127.0.0.1:2080",
    rdock.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
        req.Header.Set("Authorization", "Bearer "+os.Getenv("RDOCK_ADMIN_TOKEN"))
        return nil
    }))
status, err := client.StatusWithResponse(ctx)
```

Do not edit `client.gen.go`. After the API changes, run `just schema` and `just clients` from the repository root; CI fails when the generated file is out of date.
