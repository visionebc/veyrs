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
