import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { type ReactNode, useState } from "react";
import { Drawer, OwnerBadge } from "../components/Drawer";
import { RouteTester } from "../components/RouteTester";
import { useToast } from "../components/Toast";
import { TD, TH, Table } from "../components/Table";
import { Alert, Button, Card } from "../components/ui";
import { type Session, api, apiWithTag, describe, diagnostics } from "../lib/api";

export type Kind = "routes" | "services" | "middlewares";

interface Item {
  name: string;
  owner: string;
  spec: Record<string, unknown>;
}

const TITLES: Record<Kind, { title: string; intro: string; empty: string }> = {
  routes: {
    title: "Routes",
    intro: "Which requests go where. Objects from the file or Docker change there; API objects change here.",
    empty: "No routes yet. Add a label rdock.host=app.example.com to a container, or create one here.",
  },
  services: {
    title: "Services",
    intro: "Backend pools and how requests are spread over them.",
    empty: "No services yet.",
  },
  middlewares: {
    title: "Middlewares",
    intro: "Steps a request passes through: authentication, headers, limits, redirects.",
    empty: "No middlewares yet.",
  },
};

const TEMPLATES: Record<Kind, unknown> = {
  routes: { match: "Host(`app.example.com`)", service: "app" },
  services: { backends: [{ address: "10.0.0.5:8080" }] },
  middlewares: { type: "headers", response: { set: { "X-Frame-Options": "DENY" } } },
};

function summary(kind: Kind, spec: Record<string, unknown>): ReactNode {
  const mono = "font-mono text-[13px]";
  if (kind === "routes") {
    const middlewares = (spec.middlewares as string[] | undefined) ?? [];
    return (
      <>
        <td className={`${TD} ${mono} max-w-[28rem] truncate`} title={String(spec.match ?? "")}>{String(spec.match ?? "")}</td>
        <td className={`${TD} ${mono}`}>{String(spec.service ?? "—")}</td>
        <td className={`${TD} text-fg-2`}>{middlewares.length ? middlewares.join(", ") : "—"}</td>
      </>
    );
  }
  if (kind === "services") {
    const backends = (spec.backends as unknown[] | undefined) ?? [];
    const policy = (spec.load_balancer as { policy?: string } | undefined)?.policy ?? "round_robin";
    return (
      <>
        <td className={TD}>{backends.length}</td>
        <td className={`${TD} text-fg-2`}>{policy}</td>
        <td className={`${TD} text-fg-2`}>{spec.health ? "checked" : "—"}</td>
      </>
    );
  }
  return (
    <>
      <td className={`${TD} ${mono}`}>{String(spec.type ?? "—")}</td>
      <td className={TD} colSpan={2} />
    </>
  );
}

const HEADS: Record<Kind, string[]> = {
  routes: ["Match", "Service", "Middlewares"],
  services: ["Backends", "Policy", "Health"],
  middlewares: ["Type", ""],
};

/** Edits or creates one API-owned object; changes go through If-Match on the API objects. */
function Editor({ kind, item, onClose, canEdit }: { kind: Kind; item: Item | null; onClose: () => void; canEdit: boolean }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const creating = item === null;
  const editable = canEdit && (creating || item.owner === "api");
  const [name, setName] = useState(item?.name.replace(/@api$/, "") ?? "");
  const [text, setText] = useState(JSON.stringify(item?.spec ?? TEMPLATES[kind], null, 2));
  const [problem, setProblem] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: async (remove: boolean) => {
      const { etag } = await apiWithTag("/config/api");
      const path = `/${kind}/${encodeURIComponent(name.trim())}`;
      const method = remove ? "DELETE" : "PUT";
      const body = remove ? undefined : (JSON.parse(text) as unknown);
      const report = await api<{ generation?: number }>(path, { method, ifMatch: etag, body });
      return { remove, generation: report?.generation };
    },
    onSuccess: ({ remove, generation }) => {
      void queryClient.invalidateQueries({ queryKey: [kind] });
      const what = `${kind.slice(0, -1).replace(/^./, (c) => c.toUpperCase())} ${name.trim()}@api`;
      toast(
        <>
          <strong className="font-medium">{what} {remove ? "deleted" : "validated and applied"}.</strong>
          {generation != null && <span className="text-fg-2"> Configuration generation {generation} is live.</span>}
        </>,
      );
      onClose();
    },
  });
  const submit = (remove: boolean) => {
    try {
      if (!remove) JSON.parse(text);
      setProblem(null);
      save.mutate(remove);
    } catch {
      setProblem("The definition is not valid JSON.");
    }
  };
  return (
    <Drawer
      title={creating ? `New ${kind.slice(0, -1)}` : item.name}
      badge={item && <OwnerBadge owner={item.owner} />}
      onClose={onClose}
      footer={
        editable && (
          <>
            {!creating && <Button variant="danger" onClick={() => submit(true)} disabled={save.isPending}>Delete</Button>}
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={() => submit(false)} disabled={save.isPending || !name.trim()}>
              {save.isPending ? "Applying…" : "Validate and apply"}
            </Button>
          </>
        )
      }
    >
      {!editable && item && (
        <div className="mb-4">
          <Alert tone="info">
            {item.owner === "file"
              ? "This object comes from the configuration file; change it there and reload."
              : item.owner === "api"
                ? "Your role can read this object but not change it."
                : `This object comes from the ${item.owner} provider; change it there.`}
          </Alert>
        </div>
      )}
      {creating && (
        <label className="mb-4 flex flex-col gap-1.5 text-[13px] font-medium text-fg-2">
          Name
          <input
            className="h-9 rounded-sm border border-line bg-surface px-3 font-mono text-sm text-fg"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="shop"
            autoFocus
          />
        </label>
      )}
      <label className="flex flex-col gap-1.5 text-[13px] font-medium text-fg-2">
        Definition (JSON, same fields as rdock.yaml)
        <textarea
          className="min-h-[360px] rounded-sm border border-line bg-surface-2 p-3 font-mono text-[13px] leading-5 text-fg"
          value={text}
          onChange={(e) => setText(e.target.value)}
          readOnly={!editable}
          spellCheck={false}
        />
      </label>
      {(problem || save.error) && (
        <div className="mt-3">
          <Alert>
            <p className="font-medium">{problem ?? `Not applied: ${describe(save.error)}`}</p>
            {diagnostics(save.error).length > 0 && (
              <ul className="mt-1.5 flex list-disc flex-col gap-1 pl-4">
                {diagnostics(save.error).map((d, i) => (
                  <li key={i}>
                    <span className="font-mono">{d.path}</span>: {d.message}
                    {d.hint && <span className="text-fg-3"> ({d.hint})</span>}
                  </li>
                ))}
              </ul>
            )}
            {!problem && <p className="mt-1.5 text-fg-3">Nothing changed; the running configuration stays in use.</p>}
          </Alert>
        </div>
      )}
      {editable && (
        <p className="mt-3 text-[13px] text-fg-3">
          Applied through the same validation as a file reload; a configuration that would be refused changes nothing.
        </p>
      )}
    </Drawer>
  );
}

/** Routes, Services or Middlewares: every object with its owner; API objects are editable. */
export function Resources({ kind, session, extra }: { kind: Kind; session: Session; extra?: ReactNode }) {
  const list = useQuery({ queryKey: [kind], queryFn: () => api<Item[]>(`/${kind}`), refetchInterval: 10000 });
  const [open, setOpen] = useState<Item | null | "new">(null);
  const canEdit = session.role !== "viewer";
  const text = TITLES[kind];
  const items = [...(list.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));
  return (
    <>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-[22px] leading-7 font-semibold">{text.title}</h1>
          <p className="mt-1 text-fg-2">{text.intro}</p>
        </div>
        <div className="flex gap-2">
          {kind === "routes" && <RouteTester />}
          {canEdit && (
            <Button variant="primary" onClick={() => setOpen("new")}>
              <Plus size={15} aria-hidden />
              New {kind.slice(0, -1)}
            </Button>
          )}
        </div>
      </div>
      {list.error && <Alert>{describe(list.error)}</Alert>}
      <Card>
        <Table
          head={
            <>
              <th className={TH}>Name</th>
              <th className={TH}>Owner</th>
              {HEADS[kind].map((h, i) => <th key={i} className={TH}>{h}</th>)}
            </>
          }
          empty={list.data && items.length === 0 ? text.empty : undefined}
        >
          {items.map((item) => (
            <tr
              key={item.name}
              tabIndex={0}
              onClick={() => setOpen(item)}
              onKeyDown={(e) => e.key === "Enter" && setOpen(item)}
              className="cursor-pointer hover:bg-surface-2"
            >
              <td className={`${TD} font-mono text-[13px] font-medium`}>{item.name}</td>
              <td className={TD}><OwnerBadge owner={item.owner} /></td>
              {summary(kind, item.spec)}
            </tr>
          ))}
        </Table>
      </Card>
      {extra}
      {open !== null && (
        <Editor kind={kind} item={open === "new" ? null : open} canEdit={canEdit} onClose={() => setOpen(null)} />
      )}
    </>
  );
}

