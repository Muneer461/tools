/* Diagnostic Center logic - external + event-delegated (no inline onclick).
 * Endpoint URLs come from data-* on #diag-root to stay in sync with Flask.
 */
(function () {
  "use strict";

  var root = document.getElementById("diag-root");
  if (!root) return;
  var RUN_URL = root.dataset.runUrl;
  var REPAIR_URL = root.dataset.repairUrl;
  var GUIDE_URL = root.dataset.guideUrl;
  var EXPORT_URL = root.dataset.exportUrl;
  var DOWNLOAD_URL = root.dataset.downloadUrl;

  function setStatus(m) { document.getElementById("status").textContent = m; }
  function badge(s) { return '<span class="badge ' + s + '">' + s.toUpperCase() + "</span>"; }
  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }

  async function runDiagnostic() {
    setStatus("Running full diagnostic...");
    try {
      var r = await fetch(RUN_URL);
      var data = await r.json();
      var c = data.counts;
      document.getElementById("overall").innerHTML =
        "Overall: " + badge(data.overall) + " &nbsp; ok:" + c.ok +
        " warning:" + c.warning + " fail:" + c.fail + " unknown:" + c.unknown;
      document.getElementById("checks").innerHTML = data.checks.map(function (ch) {
        return '<div class="check"><h3>' + esc(ch.name) + badge(ch.status) + "</h3>" +
          '<div class="detail">' + esc(ch.detail || "") + "</div>" +
          (ch.root_cause ? '<div class="meta">Root cause: ' + esc(ch.root_cause) + "</div>" : "") +
          (ch.manual_fix ? '<div class="meta">Fix: ' + esc(ch.manual_fix) + "</div>" : "") +
          "</div>";
      }).join("");
      document.getElementById("rca").innerHTML = (data.root_cause || [])
        .map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("");
      setStatus("Diagnostic complete.");
    } catch (e) {
      setStatus("Diagnostic failed: " + (e && e.message ? e.message : e));
      window.zsError && window.zsError("Diagnostic failed: " + (e && e.message ? e.message : e));
    }
  }

  async function autoRepair() {
    setStatus("Attempting safe auto-repairs...");
    try {
      var r = await fetch(REPAIR_URL, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      var data = await r.json();
      setStatus("Auto-repair: " + (data.results || []).map(function (x) {
        return x.key + " -> " + (x.attempted ? (x.success ? "fixed" : "failed") : "skipped");
      }).join(", "));
      await runDiagnostic();
    } catch (e) {
      setStatus("Auto-repair failed: " + (e && e.message ? e.message : e));
    }
  }

  async function loadGuide() {
    try {
      var r = await fetch(GUIDE_URL);
      var data = await r.json();
      document.getElementById("guide").innerHTML = Object.entries(data.guide || {})
        .map(function (kv) {
          return '<div style="margin-bottom:6px;"><b>' + esc(kv[0]) + ":</b> " + esc(kv[1]) + "</div>";
        }).join("");
    } catch (e) {
      setStatus("Guide failed: " + (e && e.message ? e.message : e));
    }
  }

  async function exportReport() {
    var fmt = document.getElementById("fmt").value;
    setStatus("Exporting report...");
    try {
      var r = await fetch(EXPORT_URL, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format: fmt }) });
      var data = await r.json();
      setStatus(data.path ? "Report written to: " + data.path : "Error: " + data.error);
    } catch (e) {
      setStatus("Export failed: " + (e && e.message ? e.message : e));
    }
  }

  // Stream the report from the server and save it to the user's device.
  async function downloadReport() {
    var fmt = (document.getElementById("fmt") || {}).value || "json";
    setStatus("Preparing " + fmt.toUpperCase() + " download...");
    try {
      var r = await fetch(DOWNLOAD_URL + "?format=" + encodeURIComponent(fmt));
      if (!r.ok) {
        var err = "";
        try { err = (await r.json()).error || ""; } catch (e) { err = "HTTP " + r.status; }
        setStatus("Download failed: " + err);
        return;
      }
      var blob = await r.blob();
      var name = "zorksec-diagnostic." + (fmt === "markdown" ? "md" : fmt);
      var cd = r.headers.get("Content-Disposition") || "";
      var m = /filename="?([^"]+)"?/.exec(cd);
      if (m) name = m[1];
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click();
      a.remove(); URL.revokeObjectURL(url);
      setStatus("Downloaded " + name + " (" + blob.size + " bytes).");
    } catch (e) {
      setStatus("Download failed: " + (e && e.message ? e.message : e));
    }
  }

  document.addEventListener("click", function (ev) {
    var el = ev.target.closest ? ev.target.closest("[data-action]") : null;
    if (!el) return;
    switch (el.dataset.action) {
      case "diag-run": runDiagnostic(); break;
      case "diag-repair": autoRepair(); break;
      case "diag-guide": loadGuide(); break;
      case "diag-export": exportReport(); break;
      case "diag-download": downloadReport(); break;
      default: break;
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runDiagnostic);
  } else {
    runDiagnostic();
  }
})();
