"""Lab service: the beginner virtual-lab builder.

Provides the curated hypervisor + vulnerable-VM guidance and persists the
learner's planned VMs (``lab_vms``). The most important safety rule is
enforced here: vulnerable target VMs must use an isolated network (Host-Only
or Internal) and never bridge to the home/work network or the Internet.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from zorksec.db.models import LabVm
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)

SAFE_NETWORK_MODES = {"hostonly", "internal"}
UNSAFE_NETWORK_MODES = {"bridged", "nat"}


@dataclass
class VmTemplate:
    key: str
    name: str
    role: str  # analyst | target
    description: str
    download: str
    beginner_note: str


# Curated lab building blocks for newcomers.
HYPERVISORS = [
    {"key": "vmware", "name": "VMware Workstation Player / Pro",
     "note": "Recommended first choice; very stable for beginners.",
     "url": "https://www.vmware.com/products/workstation-player.html"},
    {"key": "virtualbox", "name": "Oracle VirtualBox",
     "note": "Free and open-source alternative; works on all major OSes.",
     "url": "https://www.virtualbox.org/"},
]

VM_TEMPLATES: list[VmTemplate] = [
    VmTemplate("kali", "Kali Linux (Analyst VM)", "analyst",
               "Your main attack/analysis machine where ZorkSec runs.",
               "https://www.kali.org/get-kali/",
               "This is YOU - the SOC analyst workstation. Give it internet for updates."),
    VmTemplate("metasploitable2", "Metasploitable 2", "target",
               "Deliberately vulnerable Linux box for practicing attacks/defense.",
               "https://sourceforge.net/projects/metasploitable/",
               "Classic first target. Keep it on an ISOLATED network only."),
    VmTemplate("dvwa", "DVWA (Damn Vulnerable Web App)", "target",
               "A vulnerable web application for learning web attacks safely.",
               "https://github.com/digininja/DVWA",
               "Great for practicing SQL injection and XSS in a safe place."),
    VmTemplate("juiceshop", "OWASP Juice Shop", "target",
               "Modern intentionally-insecure web app by OWASP.",
               "https://owasp.org/www-project-juice-shop/",
               "Teaches the OWASP Top 10 through fun challenges."),
    VmTemplate("windows-victim", "Windows Victim VM", "target",
               "An evaluation Windows VM for log analysis and DFIR practice.",
               "https://developer.microsoft.com/windows/downloads/virtual-machines/",
               "Use for Windows event-log and forensics labs (note eval expiry)."),
]


@dataclass
class IsolationCheck:
    ok: bool
    message: str


def check_isolation(role: str, network_mode: str) -> IsolationCheck:
    """Validate a VM's network mode against the safety policy.

    Target (vulnerable) VMs MUST be isolated. Analyst VMs may use NAT for
    updates. Bridged is always discouraged for lab targets.
    """
    mode = (network_mode or "").lower()
    if role == "target":
        if mode in SAFE_NETWORK_MODES:
            return IsolationCheck(True, "Isolated network - safe for a vulnerable target.")
        return IsolationCheck(
            False,
            f"UNSAFE: a vulnerable target must use Host-Only or Internal networking, "
            f"not '{mode}'. Never expose a vulnerable VM to your real network.",
        )
    # analyst VM
    if mode == "bridged":
        return IsolationCheck(
            True, "Analyst VM on bridged network - OK, but prefer NAT/Host-Only in shared spaces."
        )
    return IsolationCheck(True, "Analyst VM network mode accepted.")


class LabService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def templates(self) -> list[VmTemplate]:
        return VM_TEMPLATES

    def hypervisors(self) -> list[dict]:
        return HYPERVISORS

    def list_vms(self) -> list[LabVm]:
        return list(self.session.execute(select(LabVm).order_by(LabVm.created_at)).scalars().all())

    def add_vm(self, name: str, role: str, hypervisor: str, network_mode: str,
               notes: str = "") -> tuple[LabVm, IsolationCheck]:
        check = check_isolation(role, network_mode)
        vm = LabVm(
            name=name,
            role=role,
            hypervisor=hypervisor,
            network_mode=network_mode.lower(),
            isolated=check.ok if role == "target" else True,
            notes=notes,
        )
        self.session.add(vm)
        self.session.flush()
        logger.info("Lab VM '%s' added (role=%s, net=%s, safe=%s)",
                    name, role, network_mode, check.ok)
        return vm, check

    def remove_vm(self, vm_id: int) -> bool:
        vm = self.session.get(LabVm, vm_id)
        if vm is None:
            return False
        self.session.delete(vm)
        self.session.flush()
        return True
