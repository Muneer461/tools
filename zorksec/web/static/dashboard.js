/* ZorkSec dashboard interactions.
 *
 * Uses a SINGLE delegated click listener on `document` keyed on `data-action`
 * attributes instead of per-element inline `onclick`. This guarantees the
 * handlers fire regardless of:
 *   - inline-script restrictions / a future Content-Security-Policy,
 *   - DOM-ready timing (the listener lives on document, not on each button),
 *   - cards being re-rendered.
 * Any thrown error is surfaced by zorksec-ui.js (visible banner).
 */
(function () {
  "use strict";

  function openTab(url) {
    var win = window.open(url, "_blank");
    if (!win || win.closed || typeof win.closed === "undefined") {
      // Popup blocked -> navigate the current tab so the click never "does nothing".
      window.location.href = url;
    }
  }
  function openTerm(slug, action) {
    openTab("/terminal?tool=" + encodeURIComponent(slug) +
            "&action=" + encodeURIComponent(action));
  }
  function openDocs(slug) {
    openTab("/usage?tool=" + encodeURIComponent(slug));
  }

  // ---- category / installed filtering ------------------------------------
  function applyFilter(cat) {
    document.querySelectorAll(".sidebar .nav-item[data-cat]").forEach(function (b) {
      b.classList.toggle("active", b.dataset.cat === cat);
    });
    var shown = 0;
    document.querySelectorAll("#tool-grid .tool-card").forEach(function (card) {
      var visible;
      if (cat === "__all__") visible = true;
      else if (cat === "__installed__") visible = card.dataset.installed === "1";
      else visible = card.dataset.cat === cat;
      card.style.display = visible ? "" : "none";
      if (visible) shown++;
    });
    var empty = document.getElementById("tool-empty");
    if (empty) empty.style.display = (shown === 0) ? "" : "none";
  }

  // ---- run modal ----------------------------------------------------------
  var runSlug = null;
  function askRun(slug, name, runnable) {
    runSlug = slug;
    document.getElementById("run-modal-title").textContent = "Run " + (name || slug);
    var msg = document.getElementById("run-modal-msg");
    if (runnable === false) {
      // Services / GUIs / libraries have no CLI launcher - steer to Docs so the
      // Run button is never a confusing dead-end.
      msg.innerHTML = '<span style="color:var(--orange-primary)">' +
        (name || slug) + " is a service, GUI, or library with no direct " +
        "command-line launcher. Open <b>Docs</b> for how to start it.</span>";
    } else {
      msg.textContent = "";
    }
    document.getElementById("run-modal").style.display = "flex";
  }
  function closeRun() {
    document.getElementById("run-modal").style.display = "none";
    runSlug = null;
  }
  async function runChoice(where) {
    if (!runSlug) return;
    if (where === "browser") {
      openTerm(runSlug, "run"); closeRun();
    } else if (where === "docs") {
      openDocs(runSlug); closeRun();
    } else if (where === "native") {
      var msg = document.getElementById("run-modal-msg");
      msg.textContent = "Launching native Kali terminal\u2026";
      try {
        var r = await fetch("/api/run-target", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tool: runSlug }) });
        var data = await r.json();
        if (data.launched) {
          msg.innerHTML = '<span style="color:var(--green-primary)">' +
            (data.detail || "Launched.") + "</span>";
          setTimeout(closeRun, 1200);
        } else {
          var slug = runSlug;
          msg.innerHTML = '<span style="color:var(--orange-primary)">' +
            (data.error || data.detail || "Could not open a native terminal.") +
            " Opening in-browser terminal\u2026</span>";
          setTimeout(function () { openTerm(slug, "run"); closeRun(); }, 1600);
        }
      } catch (e) {
        msg.innerHTML = '<span style="color:var(--red-primary)">Request failed: ' +
          (e && e.message ? e.message : e) + "</span>";
      }
    }
  }

  function runCustom() {
    var input = document.getElementById("custom-cmd");
    var cmd = (input.value || "").trim();
    if (!cmd) { input.focus(); return; }
    openTab("/terminal?cmd=" + encodeURIComponent(cmd));
  }

  // ---- AI assistant -------------------------------------------------------
  async function askAi() {
    var input = document.getElementById("ai-input");
    var log = document.getElementById("ai-log");
    var q = (input.value || "").trim();
    if (!q) return;
    var u = document.createElement("div");
    u.className = "ai-message user"; u.textContent = q;
    log.appendChild(u);
    input.value = "";
    try {
      var r = await fetch("/api/ai", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: q }) });
      var data = await r.json();
      var b = document.createElement("div");
      b.className = "ai-message bot"; b.textContent = data.reply || "(no reply)";
      log.appendChild(b);
    } catch (e) {
      window.zsError && window.zsError("AI request failed: " + (e && e.message ? e.message : e));
    }
    log.scrollTop = log.scrollHeight;
  }

  // ---- system metrics -----------------------------------------------------
  async function refreshMetrics() {
    try {
      var r = await fetch("/api/metrics");
      var m = await r.json();
      document.getElementById("m-cpu").textContent = m.available ? m.cpu_percent : "n/a";
      document.getElementById("m-mem").textContent = m.available ? m.memory_percent : "n/a";
      document.getElementById("m-disk").textContent = m.available ? m.disk_percent : "n/a";
    } catch (e) { /* metrics are best-effort; never break the page */ }
  }

  // ---- one delegated click handler for every action ----------------------
  document.addEventListener("click", function (ev) {
    var el = ev.target.closest ? ev.target.closest("[data-action]") : null;
    if (!el) return;
    var action = el.dataset.action;
    var card = el.closest(".tool-card");
    var slug = el.dataset.slug || (card && card.dataset.slug) || "";
    var name = el.dataset.name || (card && card.dataset.name) || "";
    switch (action) {
      case "toggle-sidebar":
        document.getElementById("sidebar").classList.toggle("open"); break;
      case "filter":
        applyFilter(el.dataset.cat); break;
      case "filter-installed":
        applyFilter("__installed__");
        document.getElementById("tool-grid")
          .scrollIntoView({ behavior: "smooth", block: "start" });
        break;
      case "tool-install": openTerm(slug, "install"); break;
      case "tool-run": askRun(slug, name, (card && card.dataset.runnable) !== "0"); break;
      case "tool-docs": openDocs(slug); break;
      case "run-choice": runChoice(el.dataset.where); break;
      case "close-run": closeRun(); break;
      case "run-custom": runCustom(); break;
      case "ask-ai": askAi(); break;
      default: break;
    }
  });

  function init() {
    var ai = document.getElementById("ai-input");
    if (ai) ai.addEventListener("keydown", function (e) {
      if (e.key === "Enter") askAi();
    });
    var custom = document.getElementById("custom-cmd");
    if (custom) custom.addEventListener("keydown", function (e) {
      if (e.key === "Enter") runCustom();
    });
    refreshMetrics();
    setInterval(refreshMetrics, 5000);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
