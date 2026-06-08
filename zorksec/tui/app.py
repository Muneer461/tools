"""Interactive terminal UI for ZorkSec, built on `rich`.

Launch with ``tools`` (no arguments) or ``tools tui``. The UI is intentionally
beginner-oriented: every tool shows a plain-English note, install state, and a
health badge, and dangerous (isolation-required) tools are flagged.
"""

from __future__ import annotations

from collections import OrderedDict

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from zorksec.config import Settings, get_settings
from zorksec.db.session import init_db, session_scope
from zorksec.services.discovery_service import DiscoveryService
from zorksec.services.executor_service import ExecutorService
from zorksec.services.registry_service import RegistryService, ToolRow
from zorksec.tui.banner import render_banner_text

# Beginner-friendly recommendations (slugs) used by the 'r' command.
_RECOMMENDED = [
    "nmap", "yara", "sigma", "theharvester", "volatility3",
    "wazuh", "zeek", "osquery", "cyberchef", "lynis",
]

_HEALTH_COLORS = {
    "healthy": "green",
    "warning": "yellow",
    "deprecated": "red",
    "unknown": "grey50",
}


class TuiApp:
    def __init__(self, team: str = "both", settings: Settings | None = None,
                 console: Console | None = None) -> None:
        self.team = team
        self.settings = settings or get_settings()
        self.console = console or Console()
        self._rows: list[ToolRow] = []

    # ----- data -------------------------------------------------------------
    def bootstrap(self) -> None:
        """Ensure DB + catalog exist and refresh installed state."""
        init_db(self.settings)
        with session_scope(self.settings) as session:
            svc = RegistryService(session)
            if svc.tools.count() == 0:
                svc.seed_catalog()
            DiscoveryService(session).sync_installed_status()
        self.refresh()

    def refresh(self) -> None:
        with session_scope(self.settings) as session:
            self._rows = RegistryService(session).snapshot(self.team)

    def categories(self) -> "OrderedDict[str, list[ToolRow]]":
        grouped: "OrderedDict[str, list[ToolRow]]" = OrderedDict()
        for row in self._rows:
            grouped.setdefault(row.category, []).append(row)
        return grouped

    def search(self, term: str) -> list[ToolRow]:
        term = term.lower().strip()
        if not term:
            return []
        return [
            r for r in self._rows
            if term in r.name.lower() or term in r.slug.lower()
            or term in r.description.lower() or term in r.category.lower()
        ]

    def recommended(self) -> list[ToolRow]:
        by_slug = {r.slug: r for r in self._rows}
        return [by_slug[s] for s in _RECOMMENDED if s in by_slug]

    # ----- rendering --------------------------------------------------------
    def banner_panel(self) -> Panel:
        return Panel(Text(render_banner_text(), style="bold cyan"),
                     border_style="cyan", title="ZorkSec")

    def main_menu_renderable(self) -> Columns:
        cats = list(self.categories().keys())
        cards = []
        for idx, cat in enumerate(cats, start=1):
            count = len(self.categories()[cat])
            installed = sum(1 for r in self.categories()[cat] if r.installed)
            cards.append(Panel(f"[bold]{idx}.[/bold] {cat}\n"
                               f"[dim]{installed}/{count} installed[/dim]",
                               border_style="blue", width=34))
        return Columns(cards, equal=True, expand=False)

    def category_table(self, category: str) -> Table:
        table = Table(title=f"Category: {category}", header_style="bold")
        table.add_column("#", justify="right", style="cyan", width=3)
        table.add_column("Status", width=8)
        table.add_column("Tool")
        table.add_column("Team", width=6)
        table.add_column("Health", width=10)
        table.add_column("Why it matters")
        rows = self.categories().get(category, [])
        for idx, row in enumerate(rows, start=1):
            status = "[green]OK[/green]" if row.installed else "[grey50]--[/grey50]"
            iso = " [red](sandbox)[/red]" if row.requires_isolation else ""
            health = f"[{_HEALTH_COLORS.get(row.health_status, 'grey50')}]{row.health_status}[/]"
            table.add_row(str(idx), status, f"{row.name}{iso}", row.team, health, row.beginner_note)
        return table

    def tool_panel(self, row: ToolRow) -> Panel:
        lines = [
            f"[bold]{row.name}[/bold]  ([cyan]{row.slug}[/cyan])",
            "",
            row.description,
            "",
            f"[bold]Why it matters:[/bold] {row.beginner_note}",
            f"[bold]Category:[/bold] {row.category}    [bold]Team:[/bold] {row.team}",
            f"[bold]License:[/bold] {row.license}    [bold]Installed:[/bold] "
            f"{'yes' if row.installed else 'no'}",
            f"[bold]Health:[/bold] {row.health_status} ({row.health_score}/100)",
            f"[bold]Docs:[/bold] {row.docs_url or 'n/a'}",
        ]
        if row.requires_isolation:
            lines.append("\n[red]Warning:[/red] run this only inside an isolated VM/container.")
        lines.append("\n[dim]Actions: 1=Install  2=Run  3=Help  b=Back[/dim]")
        return Panel("\n".join(lines), border_style="magenta", title="Tool details")

    # ----- interaction ------------------------------------------------------
    def _ask(self, prompt: str) -> str:
        return Prompt.ask(prompt, console=self.console).strip()

    def run(self) -> int:
        self.console.clear()
        self.console.print(self.banner_panel())
        self.bootstrap()
        self.console.print(f"[green]Loaded {len(self._rows)} tools for profile "
                           f"'{self.team}'.[/green]")
        return self._main_loop()

    def _main_loop(self) -> int:
        while True:
            self.console.print(self.main_menu_renderable())
            self.console.print("[dim]Enter a category number, /search <term>, "
                               "r (recommend), t (tags), ? (help), q (quit)[/dim]")
            choice = self._ask("zorksec")
            if choice in ("q", "quit", "exit"):
                self.console.print("[cyan]Stay safe out there.[/cyan]")
                return 0
            if choice in ("?", "help"):
                self._print_help()
            elif choice == "r":
                self._show_recommended()
            elif choice == "t":
                self._show_tags()
            elif choice.startswith("/search"):
                self._do_search(choice[len("/search"):].strip())
            elif choice.isdigit():
                self._browse_category(int(choice))
            else:
                self.console.print("[yellow]Unknown command. Type ? for help.[/yellow]")

    def _browse_category(self, index: int) -> None:
        cats = list(self.categories().keys())
        if not (1 <= index <= len(cats)):
            self.console.print("[yellow]No such category number.[/yellow]")
            return
        category = cats[index - 1]
        while True:
            self.console.print(self.category_table(category))
            sel = self._ask("select tool # (or b=back)")
            if sel in ("b", "back", ""):
                return
            if sel.isdigit():
                rows = self.categories().get(category, [])
                i = int(sel)
                if 1 <= i <= len(rows):
                    self._tool_actions(rows[i - 1])
                else:
                    self.console.print("[yellow]No such tool number.[/yellow]")

    def _tool_actions(self, row: ToolRow) -> None:
        while True:
            self.console.print(self.tool_panel(row))
            action = self._ask("action [1/2/3/b]")
            if action in ("b", "back", ""):
                return
            if action == "3":
                self.console.print(Panel(row.beginner_note or row.description,
                                         title=f"About {row.name}", border_style="cyan"))
            elif action in ("1", "2"):
                self._execute(row, install=(action == "1"))
                self.refresh()
                row = next((r for r in self._rows if r.slug == row.slug), row)
            else:
                self.console.print("[yellow]Choose 1, 2, 3, or b.[/yellow]")

    def _execute(self, row: ToolRow, install: bool) -> None:
        verb = "Installing" if install else "Running"
        self.console.print(f"[bold]{verb} {row.name}...[/bold]")
        if not install and row.requires_isolation:
            confirm = self._ask("[red]This tool should run in isolation. Continue? (y/N)[/red]")
            if confirm.lower() not in ("y", "yes"):
                self.console.print("[yellow]Cancelled.[/yellow]")
                return
        with session_scope(self.settings) as session:
            executor = ExecutorService(session)
            line_printer = lambda text: self.console.print(f"  {text}", highlight=False)
            try:
                if install:
                    code = executor.install(row.slug, on_line=line_printer)
                else:
                    code = executor.run(row.slug, on_line=line_printer)
            except Exception as exc:  # surface, don't crash the TUI
                self.console.print(f"[red]Error: {exc}[/red]")
                return
        if code == 0:
            self.console.print(f"[green]Done (exit 0).[/green]")
        else:
            self.console.print(f"[red]Finished with exit code {code}.[/red]")

    def _do_search(self, term: str) -> None:
        results = self.search(term)
        if not results:
            self.console.print(f"[yellow]No tools match '{term}'.[/yellow]")
            return
        table = Table(title=f"Search: {term}")
        table.add_column("Tool")
        table.add_column("Category")
        table.add_column("Installed", width=9)
        for row in results:
            table.add_row(row.name, row.category, "yes" if row.installed else "no")
        self.console.print(table)

    def _show_recommended(self) -> None:
        table = Table(title="Recommended starter tools for beginners")
        table.add_column("Tool")
        table.add_column("Why it matters")
        for row in self.recommended():
            table.add_row(row.name, row.beginner_note)
        self.console.print(table)

    def _show_tags(self) -> None:
        blue = sum(1 for r in self._rows if r.team in ("blue", "both"))
        red = sum(1 for r in self._rows if r.team in ("red", "both"))
        self.console.print(Panel(
            f"Profile: [bold]{self.team}[/bold]\n"
            f"Blue-team tools: {blue}\nRed-team tools: {red}\n"
            f"Categories: {len(self.categories())}",
            title="Tags / profile", border_style="blue"))

    def _print_help(self) -> None:
        self.console.print(Panel(
            "[bold]Commands[/bold]\n"
            "  <number>        browse a category\n"
            "  /search <term>  search all tools\n"
            "  r               recommended starter tools\n"
            "  t               show profile tags/counts\n"
            "  ?               this help\n"
            "  q               quit\n\n"
            "[bold]Inside a tool[/bold]\n"
            "  1 Install   2 Run   3 Help   b Back",
            title="Help", border_style="cyan"))


def launch(team: str = "both", settings: Settings | None = None) -> int:
    return TuiApp(team=team, settings=settings).run()
