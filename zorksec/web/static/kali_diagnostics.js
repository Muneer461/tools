/* Kali diagnostics page logic - external + event-delegated so the Scan / Auto
 * Repair / Manual buttons (and the dynamically-rendered per-check buttons)
 * always fire, even under strict browser settings. Endpoint URLs come from
 * data-* attributes on #kali-root so they stay in sync with Flask routing.
 */
(function () {
  "use strict";

  var root = document.getElementById("kali-root");
  if (!root) return;
  var SCAN_URL = root.dataset.scanUrl;
  var REPAIR_URL = root.dataset.repairUrl;

  function setStatus(m) { document.getElementById("status").textContent = m; }
  function badge(s) { return '<span class="badge ' + s + '">' + s.toUpperCase() + "</span>"; }
  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }

  function renderSteps(steps) {
    if (!steps || !steps.length) return "";
    return '<div class="steps">' +
      steps.map(function (s) { return "<code>$ " + esc(s) + "</code>"; }).join("") +
      "</div>";
  }

  async function scan() {
    setStatus("Scanning Kali package subsystem\u2026");
    try {
      var r = await fetch(SCAN_URL);
      var data = await r.json();
      document.getElementById("distro").innerHTML =
        "Detected distro: <b>" + esc(data.distro) + "</b> " +
        (data.is_kali ? badge("ok") : badge("skipped"));
      var c = data.counts;
      document.getElementById("overall").innerHTML =
        "Overall: " + badge(data.overall) + " &nbsp; ok:" + c.ok +
        " warning:" + c.warning + " fail:" + c.fail + " skipped:" + c.skipped;
      document.getElementById("checks").innerHTML = data.checks.map(function (ch) {
        var fixBtn = ch.fixable
          ? '<button data-action="kali-fix" data-key="' + esc(ch.key) + '">Auto fix</button>' : "";
        var manBtn = (ch.manual_steps && ch.manual_steps.length)
          ? '<button data-action="kali-steps" data-key="' + esc(ch.key) + '">Manual steps</button>' : "";
        var rowActions = (ch.status === "fail" || ch.status === "warning")
          ? '<div class="row-actions">' + fixBtn + manBtn + "</div>" +
            '<div id="steps-' + esc(ch.key) + '" style="display:none;">' +
            renderSteps(ch.manual_steps) + "</div>"
          : "";
        return '<div class="check"><h3><span>' + esc(ch.name) + "</span>" +
          badge(ch.status) + "</h3>" +
          '<div class="detail">' + esc(ch.detail || "") + "</div>" +
          (ch.root_cause ? '<div class="meta">Root cause: ' + esc(ch.root_cause) + "</div>" : "") +
          rowActions + "</div>";
      }).join("");
      document.getElementById("rca").innerHTML = (data.root_cause || [])
        .map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("");
      setStatus("Scan complete.");
    } catch (e) {
      setStatus("Scan failed: " + (e && e.message ? e.message : e));
      window.zsError && window.zsError("Kali scan failed: " + (e && e.message ? e.message : e));
    }
  }

  function toggleSteps(key) {
    var el = document.getElementById("steps-" + key);
    if (el) el.style.display = el.style.display === "none" ? "block" : "none";
  }

  async function repair(body, label) {
    setStatus(label);
    try {
      var r = await fetch(REPAIR_URL, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body) });
      var data = await r.json();
      if (data.mode === "manual") return data;
      setStatus((data.results || []).map(function (x) {
        return x.key + ": " + (x.attempted ? (x.success ? "fixed" : "failed") : "skipped") +
          (x.detail ? " - " + x.detail : "");
      }).join(" | "));
      await scan();
    } catch (e) {
      setStatus("Repair failed: " + (e && e.message ? e.message : e));
      window.zsError && window.zsError("Kali repair failed: " + (e && e.message ? e.message : e));
    }
  }

  async function manualGuide() {
    try {
      var r = await fetch(REPAIR_URL, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: "manual" }) });
      var data = await r.json();
      var guide = data.guide || {};
      var keys = Object.keys(guide);
      if (!keys.length) { setStatus("No manual steps needed - nothing failing."); return; }
      document.getElementById("checks").innerHTML = keys.map(function (k) {
        return '<div class="check"><h3><span>' + esc(k) + "</span></h3>" +
          renderSteps(guide[k]) + "</div>";
      }).join("");
      setStatus("Manual repair guide loaded. Copy-paste the steps into a terminal.");
    } catch (e) {
      setStatus("Manual guide failed: " + (e && e.message ? e.message : e));
    }
  }

  document.addEventListener("click", function (ev) {
    var el = ev.target.closest ? ev.target.closest("[data-action]") : null;
    if (!el) return;
    switch (el.dataset.action) {
      case "kali-scan": scan(); break;
      case "kali-repair-all": repair({ mode: "auto" }, "Applying safe auto-fixes for all failing checks\u2026"); break;
      case "kali-fix": repair({ mode: "auto", keys: [el.dataset.key] }, "Applying safe auto-fix for " + el.dataset.key + "\u2026"); break;
      case "kali-steps": toggleSteps(el.dataset.key); break;
      case "kali-manual": manualGuide(); break;
      default: break;
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scan);
  } else {
    scan();
  }
})();
