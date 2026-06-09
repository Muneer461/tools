/* ZorkSec shared UI safety net - loaded on EVERY page via base.html.
 *
 * Purpose: make runtime failures VISIBLE (the reported "buttons do nothing and
 * no error is shown" class of problem) and provide small, robust behaviours
 * that work without inline event handlers (which can be blocked by hardened
 * browser settings or a future CSP).
 */
(function () {
  "use strict";

  // ---- visible global error banner ---------------------------------------
  function banner(message, kind) {
    var bar = document.getElementById("zs-error-bar");
    if (!bar) {
      bar = document.createElement("div");
      bar.id = "zs-error-bar";
      bar.style.cssText =
        "position:fixed;left:0;right:0;bottom:0;z-index:99999;" +
        "padding:10px 16px;font:13px/1.4 monospace;color:#fff;" +
        "background:#7a1f1f;border-top:2px solid #ff6b6b;cursor:pointer;" +
        "box-shadow:0 -4px 16px rgba(0,0,0,.4);";
      bar.title = "Click to dismiss";
      bar.addEventListener("click", function () { bar.style.display = "none"; });
      (document.body || document.documentElement).appendChild(bar);
    }
    bar.style.background = kind === "warn" ? "#7a5a1f" : "#7a1f1f";
    bar.textContent = "\u26A0 " + message + "  (click to dismiss)";
    bar.style.display = "block";
  }
  // Expose so page scripts can surface their own failures consistently.
  window.zsError = function (m) { banner(String(m), "error"); };
  window.zsWarn = function (m) { banner(String(m), "warn"); };

  window.addEventListener("error", function (e) {
    banner("Script error: " + (e && e.message ? e.message : "unknown") +
           (e && e.filename ? " (" + e.filename.split("/").pop() +
            ":" + e.lineno + ")" : ""), "error");
  });
  window.addEventListener("unhandledrejection", function (e) {
    var r = e && e.reason;
    banner("Request failed: " + ((r && r.message) ? r.message : r), "error");
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      var b = document.getElementById("zs-error-bar");
      if (b) b.style.display = "none";
    }
  });

  // ---- team selector: submit on change without inline onchange ------------
  document.addEventListener("change", function (ev) {
    var t = ev.target;
    if (t && t.matches && t.matches('select[name="team"]') && t.form) {
      t.form.submit();
    }
  });
})();
