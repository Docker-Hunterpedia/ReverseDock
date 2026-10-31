// Light, dark or the system's choice; the page sets data-theme so the Harbor tokens and the
// Tailwind dark variant follow it (docs/08-design-system.md §6).

export type Theme = "light" | "dark" | "system";

const KEY = "rdock.theme";

export function storedTheme(): Theme {
  try {
    const value = localStorage.getItem(KEY);
    if (value === "light" || value === "dark") return value;
  } catch {
    // Storage can be unavailable (private windows); the system theme is used then.
  }
  return "system";
}

const dark = window.matchMedia("(prefers-color-scheme: dark)");

export function applyTheme(theme: Theme): void {
  const resolved = theme === "system" ? (dark.matches ? "dark" : "light") : theme;
  document.documentElement.dataset.theme = resolved;
  document.documentElement.style.colorScheme = resolved;
  try {
    if (theme === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, theme);
  } catch {
    // See storedTheme.
  }
}

/** Follows system changes while the theme is "system". */
export function watchSystemTheme(current: () => Theme): void {
  dark.addEventListener("change", () => {
    if (current() === "system") applyTheme("system");
  });
}
