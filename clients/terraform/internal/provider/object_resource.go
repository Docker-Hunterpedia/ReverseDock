package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// nameRule is the rule rdock applies to the names of objects (`check_name` in
// crates/rdock-model/src/validate.rs): a letter or digit first, then letters, digits, `-`,
// `_` or `.`, at most 63 characters. `@` is reserved for provider references.
var nameRule = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// canonicalKey is the private-state key under which a resource keeps the API's own
// rendering of its object from the last time Terraform wrote or accepted it.
const canonicalKey = "canonical"

var (
	_ resource.Resource                = (*objectResource)(nil)
	_ resource.ResourceWithConfigure   = (*objectResource)(nil)
	_ resource.ResourceWithImportState = (*objectResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*objectResource)(nil)
)

// objectResource is one resource type over one section of the API: routes, services or
// middlewares behave identically and differ only in the path segment.
type objectResource struct {
	kind   string // path segment: routes, services, middlewares
	noun   string // route, service, middleware
	client *Client
}

func newObjectResource(kind, noun string) resource.Resource {
	return &objectResource{kind: kind, noun: noun}
}

type objectModel struct {
	ID   types.String         `tfsdk:"id"`
	Name types.String         `tfsdk:"name"`
	Spec jsontypes.Normalized `tfsdk:"spec"`
	ETag types.String         `tfsdk:"etag"`
}

func (r *objectResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.noun
}

func (r *objectResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: fmt.Sprintf("A ReverseDock %s owned by the admin API (`name@api` in the running configuration), "+
			"managed through `PUT` and `DELETE /api/v1/%s/{name}`.", r.noun, r.kind),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The name of the object.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true,
				Description: "Name of the object, without a provider suffix: it starts with a letter or digit and uses letters, " +
					"digits, `-`, `_` or `.` (at most 63 characters). References between API objects use the bare name. " +
					"Changing it replaces the object.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.RegexMatches(nameRule, "must start with a letter or digit and use only letters, digits, `-`, `_` or `.` (at most 63 characters)"),
				},
			},
			"spec": schema.StringAttribute{
				Required:   true,
				CustomType: jsontypes.NormalizedType{},
				Description: fmt.Sprintf("The %s as a JSON object, in the shape of the `%s` section of the configuration file "+
					"(see the configuration reference or `schema/rdock.v1.json`). Use `jsonencode(…)`. Formatting and key order "+
					"never show as a change. The admin API fills in defaults and masks secrets it is shown (`***`); the provider "+
					"keeps what you wrote unless the object really changed on the server. Write secrets as `${file:…}` or `${env:…}` "+
					"references: the spec is stored in Terraform state as written.", r.noun, r.kind),
				PlanModifiers: []planmodifier.String{keepStateWhenSemanticallyEqual{}},
				Validators:    []validator.String{objectJSONValidator{}},
			},
			"etag": schema.StringAttribute{
				Computed: true,
				Description: "The `ETag` of the API's objects (all of them: they are one versioned document) as of the last time " +
					"this resource was written or imported. Informational: every write sends the current ETag in `If-Match` itself.",
			},
		},
	}
}

func (r *objectResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *Client, got %T", req.ProviderData))
		return
	}
	r.client = client
}

// keepStateWhenSemanticallyEqual keeps the spec in state when the configuration says the
// same in other words (spacing, key order, number spelling): Terraform compares the
// configuration with the state as text, so without this a reformatted spec would plan an
// update that changes nothing.
type keepStateWhenSemanticallyEqual struct{}

func (keepStateWhenSemanticallyEqual) Description(context.Context) string {
	return "Keeps the stored spec when the configured one is the same JSON."
}

func (m keepStateWhenSemanticallyEqual) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (keepStateWhenSemanticallyEqual) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.StateValue.IsNull() || req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	configured := jsontypes.NewNormalizedValue(req.ConfigValue.ValueString())
	stored := jsontypes.NewNormalizedValue(req.StateValue.ValueString())
	if equal, diags := configured.StringSemanticEquals(ctx, stored); !diags.HasError() && equal {
		resp.PlanValue = req.StateValue
	}
}

// objectJSONValidator requires the spec to be a JSON object.
type objectJSONValidator struct{}

func (objectJSONValidator) Description(context.Context) string {
	return "the value must be a JSON object"
}
func (v objectJSONValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (objectJSONValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	obj, err := decodeObject(req.ConfigValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid spec", err.Error())
		return
	}
	if len(obj) == 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid spec", "the spec is an empty object")
	}
}

// ModifyPlan keeps the plan quiet when nothing changes, and dry-runs a changed spec when the
// provider has validate_on_plan set.
func (r *objectResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() { // destroy
		return
	}
	var plan, state objectModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	unchanged := false
	if !req.State.Raw.IsNull() {
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		unchanged = plan.Name.Equal(state.Name) && plan.Spec.Equal(state.Spec)
		if unchanged && plan.ETag.IsUnknown() {
			// The framework marks computed attributes unknown as soon as the configuration text
			// differs from the state's, even when the spec plan modifier decided it means the
			// same: keep the stored ETag so that a reformatted spec plans no change at all.
			plan.ETag = state.ETag
			resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		}
	}
	if unchanged || r.client == nil || !r.client.validateOnPlan || plan.Spec.IsNull() || plan.Spec.IsUnknown() || plan.Name.IsUnknown() {
		return
	}
	spec, err := decodeObject(plan.Spec.ValueString())
	if err != nil {
		return // the attribute validator reports it
	}
	problems, err := r.client.validateObject(ctx, r.kind, plan.Name.ValueString(), spec)
	if err != nil {
		resp.Diagnostics.AddAttributeWarning(path.Root("spec"), "Could not dry-run the spec against the admin API", err.Error())
		return
	}
	for _, p := range problems {
		resp.Diagnostics.AddAttributeError(path.Root("spec"), "The admin API's dry run rejects this configuration", p)
	}
}

func (r *objectResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan objectModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, modeCreate, &resp.State, resp.Private, &resp.Diagnostics)
}

func (r *objectResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan objectModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, modeUpdate, &resp.State, resp.Private, &resp.Diagnostics)
}

// privateSetter is the part of the response's private state the resource writes.
type privateSetter interface {
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

type stateSetter interface {
	Set(ctx context.Context, val any) diag.Diagnostics
}

func (r *objectResource) apply(ctx context.Context, plan *objectModel, mode writeMode, state stateSetter, private privateSetter, diags *diag.Diagnostics) {
	name := plan.Name.ValueString()
	spec, err := decodeObject(plan.Spec.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root("spec"), "Invalid spec", err.Error())
		return
	}
	res, err := r.client.write(ctx, r.kind, name, spec, mode)
	if err != nil {
		r.reportWriteError(diags, "Cannot write the "+r.noun, err)
		return
	}
	canonical, err := encodeJSON(res.Canonical)
	if err != nil {
		diags.AddError("Cannot encode the API's answer", err.Error())
		return
	}
	// The state holds what the plan said (Terraform requires it), not the API's rendering.
	plan.ID = types.StringValue(name)
	plan.ETag = types.StringValue(res.ETag)
	diags.Append(state.Set(ctx, plan)...)
	diags.Append(private.SetKey(ctx, canonicalKey, []byte(canonical))...)
}

func (r *objectResource) reportWriteError(diags *diag.Diagnostics, summary string, err error) {
	if errors.Is(err, errAlreadyExists) {
		diags.AddAttributeError(path.Root("name"), summary, err.Error())
		return
	}
	if ae := asAPIError(err); ae != nil && ae.Status == 422 {
		diags.AddAttributeError(path.Root("spec"), "The admin API rejected this configuration",
			ae.Error()+"\n\nNothing was changed: the API applies a configuration as a whole or not at all.")
		return
	}
	diags.AddError(summary, err.Error())
}

func (r *objectResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state objectModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	doc, err := r.client.getAPI(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the "+r.noun, err.Error())
		return
	}
	server := doc.object(r.kind, name)
	if server == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	var prior, canonical map[string]any
	if !state.Spec.IsNull() && !state.Spec.IsUnknown() {
		prior, _ = decodeObject(state.Spec.ValueString())
	}
	raw, diags := req.Private.GetKey(ctx, canonicalKey)
	resp.Diagnostics.Append(diags...)
	if len(raw) > 0 {
		if v, err := decodeJSON(raw); err == nil {
			canonical, _ = v.(map[string]any)
		}
	}

	spec, drifted := reconcile(prior, canonical, server)
	if drifted || prior == nil {
		text, err := encodeJSON(spec)
		if err != nil {
			resp.Diagnostics.AddError("Cannot encode the "+r.noun, err.Error())
			return
		}
		state.Spec = jsontypes.NewNormalizedValue(text)
	}
	state.ID = types.StringValue(name)
	if state.ETag.IsNull() || state.ETag.IsUnknown() {
		state.ETag = types.StringValue(doc.ETag)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

	record, err := encodeJSON(server)
	if err != nil {
		resp.Diagnostics.AddError("Cannot encode the API's answer", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, canonicalKey, []byte(record))...)
}

func (r *objectResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state objectModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.write(ctx, r.kind, state.Name.ValueString(), nil, modeDelete)
	switch {
	case err == nil, isStatus(err, 404):
		return // gone, or already gone
	case isStatus(err, 422):
		resp.Diagnostics.AddError("The admin API refused to delete the "+r.noun,
			err.Error()+"\n\nUsually something still refers to it (a route to a service, a route to a middleware). "+
				"Remove or change the referring object first; Terraform does this on its own when the references "+
				"are expressions in the same configuration.")
	default:
		resp.Diagnostics.AddError("Cannot delete the "+r.noun, err.Error())
	}
}

func (r *objectResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !nameRule.MatchString(req.ID) {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("The import ID is the bare name of an API-owned %s (for example `shop`, not `shop@api`); got %q.", r.noun, req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
