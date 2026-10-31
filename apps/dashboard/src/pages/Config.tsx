import { json } from "@codemirror/lang-json";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { jsonSchema } from "@valtown/codemirror-json-schema";
import { EditorView, basicSetup } from "codemirror";
import { useEffect, useMemo, useRef, useState } from "react";
import fullSchema from "../../../../schema/rdock.v1.json";
import { useReauth } from "../components/Reauth";
import { TD, TH, Table } from "../components/Table";
import { useToast } from "../components/Toast";
import { Alert, Button, Card, StatusPill } from "../components/ui";
import { type Diagnostic, type Session, api, apiWithTag, describe, diagnostics } from "../lib/api";

type JSONSchema7 = NonNullable<Parameters<typeof jsonSchema>[0]>;

/** What the API provider accepts: routes, services and middlewares of rdock.yaml. */
const apiSchema = {
  $schema: "http://json-schema.org/draft-07/schema#",
  type: "object",
  additionalProperties: false,
  properties: {
    routes: fullSchema.properties.routes,
    services: fullSchema.properties.services,
    middlewares: fullSchema.properties.middlewares,
  },
  $defs: (fullSchema as { $defs?: object }).$defs,
} as unknown as JSONSchema7;

interface Checked {
  valid: boolean;
  diagnostics: Diagnostic[];
  diff: string;
}

interface Entry {
  id: number;
  generation: number;
  applied_at: string;
  summary: string;
  api: boolean;
}

/** CodeMirror 6 with JSON-Schema completion, hover and lint for the API objects. */
function Editor({ value, onChange, readOnly }: { value: string; onChange?: (v: string) => void; readOnly?: boolean }) {
  const box = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const change = useRef(onChange);
  change.current = onChange;
  useEffect(() => {
    if (!box.current) return;
    view.current = new EditorView({
      parent: box.current,
      doc: value,
      extensions: [
        basicSetup,
        json(),
        readOnly ? [] : jsonSchema(apiSchema),
        EditorView.editable.of(!readOnly),
        EditorView.updateListener.of((u) => u.docChanged && change.current?.(u.state.doc.toString())),
        EditorView.theme({
          "&": { fontSize: "13px", backgroundColor: "var(--rd-surface-2)", color: "var(--rd-text)" },
          ".cm-content": { fontFamily: "var(--font-mono)", caretColor: "var(--rd-accent)" },
          ".cm-gutters": { backgroundColor: "var(--rd-surface)", color: "var(--rd-text-3)", borderRight: "1px solid var(--rd-border)" },
          ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "color-mix(in srgb, var(--rd-accent) 8%, transparent)" },
          "&.cm-focused": { outline: "2px solid var(--rd-focus)" },
        }),
      ],
    });
    return () => view.current?.destroy();
    // The document is set once; later outside changes go through the effect below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readOnly]);
  useEffect(() => {
    const current = view.current?.state.doc.toString();
    if (view.current && current !== value) {
      view.current.dispatch({ changes: { from: 0, to: current?.length ?? 0, insert: value } });
    }
  }, [value]);
  return <div ref={box} className="min-h-[420px] overflow-hidden rounded-sm border border-line [&_.cm-editor]:min-h-[420px]" />;
}

function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="max-h-[420px] overflow-auto rounded-sm border border-line bg-surface-2 p-3 font-mono text-[12.5px] leading-5">
      {diff.split("\n").map((line, i) => (
        <div
          key={i}
          className={
            line.startsWith("+") && !line.startsWith("+++")
              ? "bg-[color-mix(in_srgb,var(--rd-ok)_14%,transparent)]"
              : line.startsWith("-") && !line.startsWith("---")
                ? "bg-[color-mix(in_srgb,var(--rd-danger)_14%,transparent)]"
                : line.startsWith("@@")
                  ? "text-fg-3"
                  : ""
          }
        >
          {line || " "}
        </div>
      ))}
    </pre>
  );
}

function Diagnostics({ list }: { list: Diagnostic[] }) {
  if (list.length === 0) return null;
  return (
    <ul className="flex flex-col gap-1.5 text-[13px]">
      {list.map((d, i) => (
        <li key={i} className="flex flex-wrap gap-2">
          <StatusPill tone={d.severity === "error" ? "danger" : d.severity === "warning" ? "warn" : "info"}>{d.severity}</StatusPill>
          <span className="font-mono text-fg-2">{d.path}</span>
          <span>{d.message}{d.hint && <span className="text-fg-3"> · {d.hint}</span>}</span>
        </li>
      ))}
    </ul>
  );
}

type Tab = "edit" | "effective" | "history";

/** The API provider's objects: edit with schema help, validate (dry run with diff), apply. */
export function Config({ session }: { session: Session }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const reauth = useReauth();
  const [tab, setTab] = useState<Tab>("edit");
  const current = useQuery({ queryKey: ["config-api"], queryFn: () => apiWithTag<object>("/config/api") });
  const effective = useQuery({ queryKey: ["config"], queryFn: () => api<{ config: object; owners: object }>("/config"), enabled: tab === "effective" });
  const history = useQuery({ queryKey: ["history"], queryFn: () => api<Entry[]>("/config/history"), enabled: tab === "history" });
  const original = useMemo(() => JSON.stringify(current.data?.data ?? {}, null, 2), [current.data]);
  const [draft, setDraft] = useState<string | null>(null);
  const text = draft ?? original;
  const [checked, setChecked] = useState<Checked | null>(null);
  const canWrite = session.role !== "viewer";

  const parsed = (): unknown => JSON.parse(text);
  const validate = useMutation({
    mutationFn: () => api<Checked>("/config/validate", { method: "POST", body: parsed() }),
    onSuccess: (result) => {
      setChecked(result);
      toast(result.valid ? "Valid: it would be applied. Review the changes, then apply." : "Not valid: see the problems below.", result.valid ? "ok" : "danger");
    },
    onError: (error) => toast(describe(error), "danger"),
  });
  const apply = useMutation({
    mutationFn: () => api<{ generation?: number }>("/config/api", { method: "PUT", ifMatch: current.data?.etag, body: parsed() }),
    onSuccess: (report) => {
      toast(`Applied. Configuration generation ${report.generation ?? "?"} is live.`);
      setDraft(null);
      setChecked(null);
      void queryClient.invalidateQueries({ queryKey: ["config-api"] });
    },
    onError: (error) => toast(`Not applied: ${describe(error)}`, "danger"),
  });
  const rollback = useMutation({
    mutationFn: async (id: number) => {
      const { etag } = await apiWithTag("/config/api");
      return reauth(() => api<{ generation?: number }>("/config/rollback", { method: "POST", ifMatch: etag, body: { id } }));
    },
    onSuccess: (report) => {
      toast(`Rolled back; generation ${report.generation ?? "?"} is live.`);
      void queryClient.invalidateQueries({ queryKey: ["config-api"] });
      void queryClient.invalidateQueries({ queryKey: ["history"] });
    },
    onError: (error) => toast(`Rollback refused: ${describe(error)}`, "danger"),
  });

  let syntax: string | null = null;
  try {
    JSON.parse(text);
  } catch (e) {
    syntax = e instanceof Error ? e.message : "not JSON";
  }
  const changed = draft !== null && draft !== original;

  return (
    <>
      <h1 className="mb-1 text-[22px] leading-7 font-semibold">Config</h1>
      <p className="mb-4 text-fg-2">
        Routes, services and middlewares owned by the API, as JSON with the fields of rdock.yaml (Ctrl+Space completes,
        hover explains). The file and Docker keep their own objects.
      </p>
      <div role="tablist" className="mb-4 flex gap-4 border-b border-line">
        {(["edit", "effective", "history"] as Tab[]).map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
            className={`-mb-px border-b-2 pb-2 text-sm ${tab === t ? "border-accent font-medium text-fg" : "border-transparent text-fg-3 hover:text-fg"}`}
          >
            {{ edit: "API objects", effective: "Effective configuration", history: "History" }[t]}
          </button>
        ))}
      </div>

      {tab === "edit" && (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          <Card
            title="API objects"
            actions={
              <span className="flex items-center gap-2">
                {changed && <StatusPill tone="warn">unsaved</StatusPill>}
                {current.data && <span className="font-mono text-xs text-fg-3">{current.data.etag}</span>}
              </span>
            }
          >
            {current.error && <Alert>{describe(current.error)}</Alert>}
            {current.data && <Editor value={text} onChange={canWrite ? setDraft : undefined} readOnly={!canWrite} />}
            {syntax && <p className="mt-2 text-[13px] text-danger">JSON: {syntax}</p>}
            {canWrite && (
              <div className="mt-4 flex flex-wrap gap-2">
                <Button onClick={() => validate.mutate()} disabled={!!syntax || validate.isPending}>
                  {validate.isPending ? "Checking…" : "Validate"}
                </Button>
                <Button variant="primary" onClick={() => apply.mutate()} disabled={!!syntax || !changed || apply.isPending}>
                  {apply.isPending ? "Applying…" : "Apply"}
                </Button>
                {changed && <Button variant="ghost" onClick={() => { setDraft(null); setChecked(null); }}>Discard changes</Button>}
              </div>
            )}
          </Card>
          <Card title="Check">
            {!checked && !apply.error && (
              <p className="text-fg-3">Validate to see the problems and what would change, before you apply. Nothing is applied by a check.</p>
            )}
            {apply.error && (
              <div className="mb-4">
                <Alert>
                  <p className="font-medium">Not applied: {describe(apply.error)}</p>
                  <div className="mt-2"><Diagnostics list={diagnostics(apply.error)} /></div>
                </Alert>
              </div>
            )}
            {checked && (
              <div className="flex flex-col gap-4">
                <Alert tone={checked.valid ? "ok" : "danger"}>{checked.valid ? "Valid: this would be applied." : "Not valid: nothing would be applied."}</Alert>
                <Diagnostics list={checked.diagnostics} />
                {checked.diff ? <DiffView diff={checked.diff} /> : <p className="text-fg-3">No changes.</p>}
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "effective" && (
        <Card title="Everything in use, providers merged (read-only, secrets masked)">
          {effective.error && <Alert>{describe(effective.error)}</Alert>}
          {effective.data && <Editor value={JSON.stringify(effective.data.config, null, 2)} readOnly />}
        </Card>
      )}

      {tab === "history" && (
        <Card title="Applied configurations, newest first">
          {history.error && <Alert>{describe(history.error)}</Alert>}
          <Table head={<><th className={TH}>Applied</th><th className={TH}>Gen</th><th className={TH}>Changes</th><th className={TH}><span className="sr-only">Actions</span></th></>}>
            {(history.data ?? []).map((e, i) => (
              <tr key={e.id} className="hover:bg-surface-2">
                <td className={`${TD} font-mono text-[12.5px] whitespace-nowrap`}>{e.applied_at.replace("T", " ").slice(0, 19)}</td>
                <td className={`${TD} tabular-nums`}>{e.generation}</td>
                <td className={TD}>{e.summary}</td>
                <td className={`${TD} text-right`}>
                  {canWrite && i > 0 && (
                    <Button className="h-8" disabled={rollback.isPending} onClick={() => rollback.mutate(e.id)} title="Restore the API objects of this version">
                      Roll back to this
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </Table>
          <p className="mt-6 text-[13px] text-fg-3">A rollback restores the API objects of that version; the file is its own source of truth.</p>
        </Card>
      )}
    </>
  );
}
