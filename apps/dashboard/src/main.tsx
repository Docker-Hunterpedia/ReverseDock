import "./styles.css";

import { MutationCache, QueryCache, QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import { RouterProvider, createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import { StrictMode, createContext, use, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Shell } from "./components/Shell";
import { Alert } from "./components/ui";
import { ApiError, type Session, api, describe, readCsrfFrom } from "./lib/api";
import { type Theme, applyTheme, storedTheme, watchSystemTheme } from "./lib/theme";
import { Enrol } from "./pages/Enrol";
import { Login } from "./pages/Login";
import { Mfa } from "./pages/Mfa";
import { Overview } from "./pages/Overview";
import { Security } from "./pages/Security";
import { Setup } from "./pages/Setup";

let theme = storedTheme();
applyTheme(theme);
watchSystemTheme(() => theme);

/** A 401 anywhere means the session ended: ask for the session again, which shows Login. */
function onError(error: unknown) {
  if (error instanceof ApiError && error.status === 401) {
    void queryClient.invalidateQueries({ queryKey: ["session"] });
  }
}

const queryClient = new QueryClient({
  queryCache: new QueryCache({ onError }),
  mutationCache: new MutationCache({ onError }),
  defaultOptions: { queries: { retry: (count, error) => !(error instanceof ApiError) && count < 2 } },
});

readCsrfFrom(() => queryClient.getQueryData<Session | null>(["session"])?.csrf_token ?? "");

interface App {
  session: Session;
  theme: Theme;
  setTheme: (theme: Theme) => void;
  logout: () => void;
}

const AppContext = createContext<App | null>(null);

function useApp(): App {
  const app = use(AppContext);
  if (!app) throw new Error("outside the app");
  return app;
}

const root = createRootRoute({
  component: () => {
    const app = useApp();
    return <Shell session={app.session} theme={app.theme} setTheme={app.setTheme} onLogout={app.logout} />;
  },
  notFoundComponent: () => <p className="text-fg-2">This page does not exist.</p>,
});

const router = createRouter({
  routeTree: root.addChildren([
    createRoute({ getParentRoute: () => root, path: "/", component: () => <Overview session={useApp().session} /> }),
    createRoute({ getParentRoute: () => root, path: "/security", component: () => <Security session={useApp().session} /> }),
  ]),
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

/** Shows first run, login, the second factor or the dashboard, by the server's answer. */
function Gate() {
  const client = useQueryClient();
  const [current, setCurrent] = useState<Theme>(theme);
  const [ended, setEnded] = useState(false);
  const setup = useQuery({ queryKey: ["setup"], queryFn: () => api<{ needed: boolean }>("/setup") });
  const session = useQuery({
    queryKey: ["session"],
    queryFn: async () => {
      try {
        return await api<Session>("/auth/session");
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) return null;
        throw error;
      }
    },
    enabled: setup.data?.needed === false,
    refetchInterval: 60_000,
  });
  const data = session.data;

  // A session that disappears without a logout has expired; say so on the login page.
  const hadSession = useRef(false);
  useEffect(() => {
    if (data) {
      hadSession.current = true;
      setEnded(false);
    } else if (data === null && hadSession.current) {
      hadSession.current = false;
      setEnded(true);
    }
  }, [data]);

  const logout = () => {
    hadSession.current = false;
    void api("/auth/logout", { method: "POST", body: {} }).finally(() => {
      // Keep the session and setup entries (the gate observes them); drop everything else.
      client.removeQueries({ predicate: (q) => !["session", "setup"].includes(String(q.queryKey[0])) });
      client.setQueryData(["session"], null);
    });
  };

  if (setup.error) return <div className="p-6"><Alert>{describe(setup.error)}</Alert></div>;
  if (!setup.data) return null;
  if (setup.data.needed) return <Setup />;
  if (session.error) return <div className="p-6"><Alert>{describe(session.error)}</Alert></div>;
  if (data === undefined) return null;
  if (data === null) return <Login expired={ended} />;
  if (data.stage === "mfa") return <Mfa onCancel={logout} />;
  if (data.stage === "enrol") return <Enrol onCancel={logout} />;

  const setTheme = (next: Theme) => {
    theme = next;
    applyTheme(next);
    setCurrent(next);
  };
  return (
    <AppContext value={{ session: data, theme: current, setTheme, logout }}>
      <RouterProvider router={router} />
    </AppContext>
  );
}

const element = document.getElementById("root");
if (element) {
  createRoot(element).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <Gate />
      </QueryClientProvider>
    </StrictMode>,
  );
}
