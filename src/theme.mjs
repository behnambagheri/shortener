const $ = (id) => document.getElementById(id);
const themeOptions = ["auto", "light", "dark"];

export function setupTheme() {
  let theme = "auto";
  try { theme = localStorage.getItem("bea-shortener-theme") || "auto"; } catch { /* Storage can be disabled. */ }
  if (!themeOptions.includes(theme)) theme = "auto";
  function applyTheme() {
    const dark = theme === "dark" || (theme === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.dataset.theme = dark ? "bea-dark" : "bea";
    const label = theme[0].toUpperCase() + theme.slice(1);
    $("theme-label").textContent = label;
    $("theme-toggle").setAttribute("aria-label", `Appearance: ${label}`);
  }
  applyTheme();
  $("theme-toggle").addEventListener("click", () => {
    theme = themeOptions[(themeOptions.indexOf(theme) + 1) % themeOptions.length];
    try { localStorage.setItem("bea-shortener-theme", theme); } catch { /* Storage can be disabled. */ }
    applyTheme();
  });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyTheme);
}
