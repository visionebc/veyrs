// VEYRS Docs Center behaviour. External file on purpose: the pages carry no
// inline script and no inline event handlers (tests/test_docs_center.py).
// theme.js (in <head>) has already set data-theme before first paint.

// Theme toggle: an explicit choice is remembered; system preference otherwise.
(function () {
  var btn = document.querySelector(".themetoggle");
  if (!btn) return;
  function current() { return document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light"; }
  function label() {
    btn.setAttribute("aria-label", current() === "dark" ? "Switch to light theme" : "Switch to dark theme");
    btn.setAttribute("title", btn.getAttribute("aria-label"));
  }
  btn.addEventListener("click", function () {
    var next = current() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("veyrs.docs.theme", next); } catch (e) { /* storage blocked */ }
    label();
  });
  label();
})();

// Sidebar: off-canvas below 1024px. Escape and a click outside close it.
(function () {
  var btn = document.querySelector(".sidetoggle");
  var side = document.getElementById("sidebar");
  if (!side) return;
  var active = side.querySelector("a.active");
  if (active && side.scrollHeight > side.clientHeight) {
    side.scrollTop = Math.max(0, active.offsetTop - side.clientHeight / 2);
  }
  if (!btn) return;
  function set(open) {
    document.body.classList.toggle("nav-open", open);
    btn.setAttribute("aria-expanded", String(open));
    btn.setAttribute("aria-label", open ? "Close the documentation menu" : "Open the documentation menu");
    if (open) { var f = side.querySelector("a.active") || side.querySelector("a"); if (f) f.focus(); }
  }
  btn.addEventListener("click", function () { set(!document.body.classList.contains("nav-open")); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && document.body.classList.contains("nav-open")) { set(false); btn.focus(); }
  });
  document.addEventListener("click", function (e) {
    if (document.body.classList.contains("nav-open") && !side.contains(e.target) && !btn.contains(e.target)) set(false);
  });
})();

// "/" focuses the search box (unless the reader is typing somewhere).
(function () {
  document.addEventListener("keydown", function (e) {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    var t = e.target, tag = t && t.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (t && t.isContentEditable)) return;
    var box = document.getElementById("dc-q") || document.getElementById("homeq") || document.getElementById("topq");
    if (!box || box.offsetParent === null) box = document.getElementById("topq");
    if (!box) return;
    e.preventDefault();
    box.focus();
    box.select();
  });
})();

// Copy buttons on code blocks.
(function () {
  var ICON_COPY = '<svg class="ico" viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>';
  var ICON_OK = '<svg class="ico" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>';
  Array.prototype.forEach.call(document.querySelectorAll(".codeblock"), function (block) {
    var pre = block.querySelector("pre");
    if (!pre) return;
    var b = document.createElement("button");
    b.type = "button";
    b.className = "copybtn";
    b.innerHTML = ICON_COPY + "<span>Copy</span>";
    b.setAttribute("aria-label", "Copy this code to the clipboard");
    b.addEventListener("click", function () {
      var text = pre.innerText.replace(/\n$/, "");
      function ok() {
        b.classList.add("done");
        b.innerHTML = ICON_OK + "<span>Copied</span>";
        setTimeout(function () { b.classList.remove("done"); b.innerHTML = ICON_COPY + "<span>Copy</span>"; }, 1800);
      }
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(ok, function () {});
      } else {
        var ta = document.createElement("textarea");
        ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta); ta.select();
        try { document.execCommand("copy"); ok(); } catch (e) { /* nothing to do */ }
        document.body.removeChild(ta);
      }
    });
    block.appendChild(b);
  });
})();

// Scroll-spy for the on-this-page rail.
(function () {
  var links = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  if (!links.length || !("IntersectionObserver" in window)) return;
  var byId = {};
  links.forEach(function (a) { byId[decodeURIComponent(a.getAttribute("href").slice(1))] = a; });
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      var a = byId[e.target.id];
      if (!a || !e.isIntersecting) return;
      links.forEach(function (l) { l.classList.remove("active"); l.removeAttribute("aria-current"); });
      a.classList.add("active");
      a.setAttribute("aria-current", "location");
    });
  }, { rootMargin: "-80px 0px -70% 0px", threshold: 0 });
  Object.keys(byId).forEach(function (id) {
    var el = document.getElementById(id);
    if (el) io.observe(el);
  });
})();

// Search: /search.html?q=… filters search-index.json (built by site/build.py)
// client-side. Every term must match the document; title and heading hits
// rank above body hits, and a heading hit links straight to that section.
(function () {
  var list = document.getElementById("dc-results");
  if (!list) return;
  var input = document.getElementById("dc-q");
  var count = document.getElementById("dc-count");
  var q = (new URLSearchParams(location.search).get("q") || "").trim();
  if (input) input.value = q;
  var top = document.getElementById("topq");
  if (top) top.value = q;
  if (!q) { count.textContent = "Type a word or a phrase to search every document."; return; }
  var terms = q.toLowerCase().split(/\s+/).filter(Boolean);

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; });
  }
  function snippet(text) {
    var low = text.toLowerCase(), at = -1;
    for (var i = 0; i < terms.length && at < 0; i++) at = low.indexOf(terms[i]);
    var start = Math.max(0, at - 80), cut = text.slice(start, start + 240);
    var out = (start > 0 ? "…" : "") + esc(cut) + (start + 240 < text.length ? "…" : "");
    terms.forEach(function (t) {
      var re = new RegExp("(" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "gi");
      out = out.replace(re, "<mark>$1</mark>");
    });
    return out;
  }

  fetch("/search-index.json").then(function (r) { return r.json(); }).then(function (docs) {
    var hits = [];
    docs.forEach(function (d) {
      var title = d.t.toLowerCase(), heads = d.h.join(" ").toLowerCase();
      var body = (d.s + " " + d.x).toLowerCase(), score = 0;
      for (var i = 0; i < terms.length; i++) {
        var t = terms[i];
        if (title.indexOf(t) >= 0) score += 10;
        else if (heads.indexOf(t) >= 0) score += 4;
        else if (body.indexOf(t) >= 0) score += 1;
        else return;
      }
      var section = null;
      for (var j = 0; j < d.h.length && !section; j++) {
        var hl = d.h[j].toLowerCase();
        if (terms.every(function (t) { return hl.indexOf(t) >= 0; })) section = { h: d.h[j], a: (d.a || [])[j] };
      }
      hits.push({ d: d, score: score, section: section });
    });
    hits.sort(function (a, b) { return b.score - a.score || a.d.t.localeCompare(b.d.t); });
    count.textContent = hits.length + (hits.length === 1 ? " document matches " : " documents match ") + "“" + q + "”.";
    list.innerHTML = hits.slice(0, 200).map(function (h) {
      var sec = h.section && h.section.a
        ? '<a class="dc-sec" href="' + esc(h.d.u) + "#" + esc(h.section.a) + '">Section: ' + esc(h.section.h) + "</a>" : "";
      return '<li><a class="hit" href="' + esc(h.d.u) + '">' + esc(h.d.t) + '</a><span class="dc-cat">' + esc(h.d.c) +
        "</span>" + sec + "<p>" + snippet(h.d.x || h.d.s) + "</p></li>";
    }).join("");
  }).catch(function () {
    count.textContent = "The search index could not be loaded. Browse the domains on the home page.";
  });
})();
