// Theme before first paint (loaded synchronously in <head>, external so the
// pages carry no inline script). An explicit choice in localStorage wins;
// otherwise the reader's system preference decides. veyrs.js wires the toggle.
(function () {
  var t = null;
  try { t = localStorage.getItem("veyrs.docs.theme"); } catch (e) { /* storage blocked */ }
  if (t !== "light" && t !== "dark") {
    t = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", t);
})();
