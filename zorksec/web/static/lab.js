/* ZorkSec "Build My Lab" interactions.
 *
 * External + event-delegated (single document click listener keyed on
 * data-action) to match the hardened UI pattern used across ZorkSec. This
 * avoids inline onclick handlers entirely, so VM template names containing
 * quotes/apostrophes can never break the handler, and the buttons keep working
 * even under strict browser settings / a future CSP.
 *
 * Any thrown error is surfaced by zorksec-ui.js (the visible error banner).
 */
(function () {
  "use strict";

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  async function addVm(name, role) {
    // Target (vulnerable) VMs default to an isolated host-only network; the
    // analyst VM may use NAT for updates. The server re-validates either way.
    var network = role === "target" ? "hostonly" : "nat";
    var msg = document.getElementById("vm-msg");
    msg.className = "";
    msg.textContent = "Adding " + name + "\u2026";
    try {
      var r = await fetch("/api/lab/vm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name, role: role,
                               hypervisor: "virtualbox", network_mode: network }),
      });
      if (!r.ok) throw new Error("server returned " + r.status);
      var data = await r.json();
      msg.className = data.safe ? "ok-box" : "warn-box";
      msg.textContent = data.message || (data.safe ? "Added." : "Added (review network).");

      var empty = document.getElementById("vm-empty");
      if (empty) empty.remove();

      var badge = data.safe
        ? '<span class="tool-badge ok">isolated</span>'
        : '<span class="tool-badge deprecated">unsafe</span>';
      var row = document.getElementById("vm-body").insertRow(-1);
      row.innerHTML =
        "<td>" + esc(name) + "</td><td>" + esc(role) + "</td>" +
        "<td>virtualbox</td><td>" + esc(network) + "</td><td>" + badge + "</td>";
    } catch (e) {
      msg.className = "warn-box";
      msg.textContent = "Could not add VM: " + (e && e.message ? e.message : e);
      if (window.zsError) window.zsError("Add VM failed: " + (e && e.message ? e.message : e));
    }
  }

  document.addEventListener("click", function (ev) {
    var el = ev.target.closest ? ev.target.closest("[data-action]") : null;
    if (!el) return;
    if (el.dataset.action === "add-vm") {
      ev.preventDefault();
      addVm(el.dataset.name || "Unnamed", el.dataset.role || "target");
    }
  });
})();
