// Sidebar toggle + scroll-spy for the on-this-page rail.
(function () {
  var btn = document.querySelector(".navtoggle");
  var side = document.querySelector(".sidebar");
  if (btn && side) {
    btn.addEventListener("click", function () {
      var open = side.classList.toggle("open");
      btn.setAttribute("aria-expanded", String(open));
    });
  }

  var links = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  if (!links.length || !("IntersectionObserver" in window)) return;
  var byId = {};
  links.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });

  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      var a = byId[e.target.id];
      if (!a) return;
      if (e.isIntersecting) {
        links.forEach(function (l) { l.classList.remove("active"); });
        a.classList.add("active");
      }
    });
  }, { rootMargin: "-80px 0px -70% 0px", threshold: 0 });

  Object.keys(byId).forEach(function (id) {
    var el = document.getElementById(id);
    if (el) io.observe(el);
  });
})();

// Docs Center search: /search.html?q=… filters search-index.json (built by
// site/build.py) client-side. Every term must match; title and heading hits
// rank above body hits. No third-party code, no inline script.
(function () {
  var list = document.getElementById("dc-results");
  if (!list) return;
  var input = document.getElementById("dc-q");
  var count = document.getElementById("dc-count");
  var q = (new URLSearchParams(location.search).get("q") || "").trim();
  if (input) input.value = q;
  if (!q) { count.textContent = "Type a word or a phrase to search every document."; return; }
  var terms = q.toLowerCase().split(/\s+/).filter(Boolean);

  function esc(s) {
    return s.replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; });
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
      hits.push({ d: d, score: score });
    });
    hits.sort(function (a, b) { return b.score - a.score || a.d.t.localeCompare(b.d.t); });
    count.textContent = hits.length + (hits.length === 1 ? " document matches " : " documents match ") + "“" + q + "”.";
    list.innerHTML = hits.map(function (h) {
      return '<li><a href="' + esc(h.d.u) + '">' + esc(h.d.t) + '</a><span class="dc-cat">' + esc(h.d.c) +
        "</span><p>" + snippet(h.d.x || h.d.s) + "</p></li>";
    }).join("");
  }).catch(function () {
    count.textContent = "The search index could not be loaded. Browse the categories on the home page.";
  });
})();
