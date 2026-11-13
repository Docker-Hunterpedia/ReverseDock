package provider

import (
	"context"
	"fmt"
	"math"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = (*statusDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*statusDataSource)(nil)
)

type statusDataSource struct{ client *Client }

func newStatusDataSource() datasource.DataSource { return &statusDataSource{} }

type statusModel struct {
	ID         types.String         `tfsdk:"id"`
	Version    types.String         `tfsdk:"version"`
	Commit     types.String         `tfsdk:"commit"`
	Ready      types.Bool           `tfsdk:"ready"`
	Generation types.Int64          `tfsdk:"generation"`
	StartedAt  types.String         `tfsdk:"started_at"`
	JSON       jsontypes.Normalized `tfsdk:"json"`
}

func (d *statusDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_status"
}

func (d *statusDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The running ReverseDock process (`GET /api/v1/status`; viewer role): version, configuration generation, " +
			"readiness, and the whole document with listeners, providers, certificates and the last reload as `json`.",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true, Description: "Always `status`."},
			"version":    schema.StringAttribute{Computed: true, Description: "The ReverseDock version."},
			"commit":     schema.StringAttribute{Computed: true, Description: "The commit it was built from."},
			"ready":      schema.BoolAttribute{Computed: true, Description: "Whether the proxy serves traffic."},
			"generation": schema.Int64Attribute{Computed: true, Description: "The generation of the configuration in use."},
			"started_at": schema.StringAttribute{Computed: true, Description: "When the process started (RFC 3339)."},
			"json": schema.StringAttribute{
				Computed:    true,
				CustomType:  jsontypes.NormalizedType{},
				Description: "The whole status document as JSON; decode it with `jsondecode`.",
			},
		},
	}
}

func (d *statusDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *Client, got %T", req.ProviderData))
		return
	}
	d.client = client
}

func (d *statusDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	doc, err := d.client.getStatus(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the status", err.Error())
		return
	}
	text, err := encodeJSON(doc)
	if err != nil {
		resp.Diagnostics.AddError("Cannot encode the API's answer", err.Error())
		return
	}
	str := func(key string) types.String {
		s, _ := doc[key].(string)
		return types.StringValue(s)
	}
	ready, _ := doc["ready"].(bool)
	var generation int64
	if n := normalize(doc["generation"]); n != nil {
		switch v := n.(type) {
		case int64:
			generation = v
		case float64:
			generation = int64(math.Round(v))
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &statusModel{
		ID:         types.StringValue("status"),
		Version:    str("version"),
		Commit:     str("commit"),
		Ready:      types.BoolValue(ready),
		Generation: types.Int64Value(generation),
		StartedAt:  str("started_at"),
		JSON:       jsontypes.NewNormalizedValue(text),
	})...)
}
