package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = (*objectDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*objectDataSource)(nil)
)

// objectDataSource reads one route, service or middleware of the running configuration,
// whoever owns it (`GET /api/v1/{kind}/{name}`; viewer role).
type objectDataSource struct {
	kind   string
	noun   string
	client *Client
}

func newObjectDataSource(kind, noun string) datasource.DataSource {
	return &objectDataSource{kind: kind, noun: noun}
}

type objectDataModel struct {
	ID    types.String         `tfsdk:"id"`
	Name  types.String         `tfsdk:"name"`
	Owner types.String         `tfsdk:"owner"`
	Spec  jsontypes.Normalized `tfsdk:"spec"`
}

func (d *objectDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + d.noun
}

func (d *objectDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: fmt.Sprintf("Reads a %s of the running configuration, whichever provider owns it (`GET /api/v1/%s/{name}`). "+
			"Needs the `viewer` role.", d.noun, d.kind),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The name as the API knows it, for example `shop@api`."},
			"name": schema.StringAttribute{
				Required: true,
				Description: "The name as the API lists it: a bare name for objects of the configuration file, `name@provider` " +
					"for the others (`shop@docker`). A bare name that is not in the file is looked up as an API object (`name@api`).",
			},
			"owner": schema.StringAttribute{Computed: true, Description: "`file`, `api`, `docker`, `swarm` or `kubernetes`."},
			"spec": schema.StringAttribute{
				Computed:    true,
				CustomType:  jsontypes.NormalizedType{},
				Description: "The object as a JSON string, with defaults filled in and secrets masked as `***` by the API.",
			},
		},
	}
}

func (d *objectDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *objectDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model objectDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := model.Name.ValueString()
	found, err := d.client.getObject(ctx, d.kind, name)
	if err == nil && found == nil && !strings.Contains(name, "@") {
		found, err = d.client.getObject(ctx, d.kind, name+"@api")
	}
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the "+d.noun, err.Error())
		return
	}
	if found == nil {
		resp.Diagnostics.AddError("Not found", fmt.Sprintf("The running configuration has no %s named %q.", d.noun, name))
		return
	}
	text, err := encodeJSON(found.Spec)
	if err != nil {
		resp.Diagnostics.AddError("Cannot encode the API's answer", err.Error())
		return
	}
	model.ID = types.StringValue(found.Name)
	model.Owner = types.StringValue(found.Owner)
	model.Spec = jsontypes.NewNormalizedValue(text)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
