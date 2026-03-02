# src/pyspector/triage.py
import json
from pathlib import Path
from typing import List, Dict, Any
import hashlib

from textual.app import App, ComposeResult  # type: ignore
from textual.widgets import Header, Footer, DataTable, Static, Label  # type: ignore
from textual.containers import Vertical  # type: ignore
from textual.binding import Binding  # type: ignore


# Helper to create a unique, stable fingerprint for an issue
def create_fingerprint(issue: Dict[str, Any]) -> str:
    # Use rule ID, file path relative to a potential project root, and the line content
    # This makes the fingerprint stable across different checkout directories
    unique_string = f"{issue.get('rule_id', '')}|{issue.get('file_path', '')}|{issue.get('line_number', '')}|{issue.get('code', '').strip()}"
    return hashlib.sha1(unique_string.encode("utf-8")).hexdigest()


class PySpectorTriage(App):
    """An interactive TUI for triaging PySpector findings."""

    # Remove problematic bindings and handle keys directly
    def __init__(self, issues: List[Dict[str, Any]], baseline_path: Path):
        super().__init__()
        self.issues = issues
        self.baseline_path = baseline_path
        self.ignored_fingerprints = set()
        # Create fingerprint to issue mapping for easier lookup
        self.fingerprint_to_issue = {}
        for issue in issues:
            fp = create_fingerprint(issue)
            self.fingerprint_to_issue[fp] = issue
        # Store status message for when widgets are ready
        self.initial_status = "Status: Ready"
        # Load baseline data (but don't update UI yet)
        self._load_baseline_data()

    def _load_baseline_data(self):
        """Load baseline data without touching any UI elements."""
        if self.baseline_path.exists():
            try:
                with self.baseline_path.open("r") as f:
                    data = json.load(f)
                    self.ignored_fingerprints = set(
                        data.get("ignored_fingerprints", [])
                    )
                self.initial_status = f"Status: Loaded baseline with {len(self.ignored_fingerprints)} ignored issues"
            except (json.JSONDecodeError, IOError) as e:
                self.initial_status = f"Status: Error loading baseline: {str(e)}"
        else:
            self.initial_status = "Status: No baseline file found - starting fresh"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Label("PySpector Triage Mode", id="title"),
            Label(
                "Navigate with arrows. 'i' = Ignore/Unignore. 's' = Save & Quit. 'q' = Quit without saving.",
                id="instructions",
            ),
        )
        yield DataTable(id="issue_table")
        yield Footer()
        yield Static(id="status_bar", content="Status: Initializing...")

    def on_mount(self) -> None:
        """Called after all widgets are mounted and ready."""
        table = self.query_one("#issue_table", DataTable)
        table.cursor_type = "row"
        table.add_columns(
            "Status", "Severity", "File", "Line", "Rule ID", "Description"
        )

        # Update status bar with baseline loading result
        status_bar = self.query_one("#status_bar", Static)
        status_bar.update(self.initial_status)

        # Populate the table
        self.update_table()

        # Ensure the table has focus so key bindings work
        table.focus()

    def on_key(self, event):
        """Handle key presses directly."""
        print(f"KEY PRESSED: {event.key}")  # Debug output

        if event.key == "i":
            print("I KEY DETECTED - calling toggle_ignore")
            self.toggle_ignore()
            return True
        elif event.key == "s":
            print("S KEY DETECTED - calling save_and_quit")
            self.save_and_quit()
            return True
        elif event.key == "q":
            print("Q KEY DETECTED - calling quit")
            self.exit("Exited triage mode.")
            return True

        # Let other keys pass through (like arrow keys for navigation)
        return False

    def update_table(self):
        table = self.query_one("#issue_table", DataTable)
        current_cursor = table.cursor_row if table.row_count > 0 else 0
        table.clear()

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        # Sort issues by severity then by file path
        sorted_issues = sorted(
            self.issues,
            key=lambda x: (
                severity_order.get(x.get("severity", "LOW").split(".")[-1], 4),
                x.get("file_path", ""),
            ),
        )

        for issue in sorted_issues:
            fingerprint = create_fingerprint(issue)
            status = (
                "[Ignored]" if fingerprint in self.ignored_fingerprints else "[Active]"
            )

            # Handle severity display
            sev = issue.get("severity", "N/A")
            if "." in sev:
                sev = sev.split(".")[-1]

            fpath = issue.get("file_path", "N/A")
            line = str(issue.get("line_number", "N/A"))
            rule = issue.get("rule_id", "N/A")
            desc = issue.get("description", "N/A")

            # Truncate long file paths for better display
            if len(fpath) > 40:
                fpath = "..." + fpath[-37:]

            # Truncate long descriptions
            if len(desc) > 60:
                desc = desc[:57] + "..."

            styled_sev = f"[{self._get_severity_color(sev)}]{sev}[/]"
            table.add_row(status, styled_sev, fpath, line, rule, desc, key=fingerprint)

        # Restore cursor position
        if table.row_count > 0:
            if current_cursor >= table.row_count:
                current_cursor = table.row_count - 1
            table.move_cursor(row=current_cursor)

    def toggle_ignore(self):
        """Toggle ignore status for the current issue."""
        print("TOGGLE IGNORE FUNCTION CALLED!")
        table = self.query_one("#issue_table", DataTable)
        status_bar = self.query_one("#status_bar", Static)

        print(f"Table row count: {table.row_count}, cursor: {table.cursor_row}")

        if table.row_count == 0:
            status_bar.update("Status: No issues to toggle")
            return

        if table.cursor_row < 0 or table.cursor_row >= table.row_count:
            status_bar.update(
                f"Status: Invalid cursor position: {table.cursor_row}/{table.row_count}"
            )
            return

        try:
            # Get the sorted issues list (same as in update_table)
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_issues = sorted(
                self.issues,
                key=lambda x: (
                    severity_order.get(x.get("severity", "LOW").split(".")[-1], 4),
                    x.get("file_path", ""),
                ),
            )

            # Get the current issue by cursor position
            current_issue = sorted_issues[table.cursor_row]
            fingerprint = create_fingerprint(current_issue)

            print(f"Working with fingerprint: {fingerprint}")

            # Get issue info for status message
            file_path = current_issue.get("file_path", "Unknown")
            rule_id = current_issue.get("rule_id", "Unknown")
            line_num = current_issue.get("line_number", "Unknown")
            issue_desc = f" ({Path(file_path).name}:{line_num} - {rule_id})"

            # Toggle the ignore status
            if fingerprint in self.ignored_fingerprints:
                self.ignored_fingerprints.remove(fingerprint)
                status_bar.update(f"Status: Marked issue as ACTIVE{issue_desc}")
                print(f"Marked as ACTIVE: {fingerprint}")
            else:
                self.ignored_fingerprints.add(fingerprint)
                status_bar.update(f"Status: Marked issue as IGNORED{issue_desc}")
                print(f"Marked as IGNORED: {fingerprint}")

            # Refresh the table
            self.update_table()

        except Exception as e:
            import traceback

            error_details = traceback.format_exc()
            status_bar.update(f"Status: Error: {str(e)}")
            print(f"Toggle error: {error_details}")

    def save_and_quit(self):
        """Save the baseline and exit."""
        try:
            baseline_data = {
                "ignored_fingerprints": sorted(list(self.ignored_fingerprints))
            }
            with self.baseline_path.open("w") as f:
                json.dump(baseline_data, f, indent=2)

            self.exit(
                f"Baseline saved to '{self.baseline_path}' with {len(self.ignored_fingerprints)} ignored issues."
            )
        except IOError as e:
            status_bar = self.query_one("#status_bar", Static)
            status_bar.update(f"Status: Error saving baseline: {str(e)}")

    def _get_severity_color(self, severity: str) -> str:
        return {
            "CRITICAL": "bold magenta",
            "HIGH": "bold red",
            "MEDIUM": "bold yellow",
            "LOW": "bold blue",
        }.get(severity.upper(), "white")


def run_triage_tui(issues_data: List[Dict[str, Any]], baseline_path: Path):
    """Initializes and runs the Textual Triage App."""
    if not issues_data:
        print("No issues found in the report to triage.")
        return

    print(f"Starting triage mode with {len(issues_data)} issues...")
    print(f"Baseline file: {baseline_path}")

    try:
        app = PySpectorTriage(issues=issues_data, baseline_path=baseline_path)
        result = app.run()
        if result:
            print(result)
    except Exception as e:
        print(f"Error running triage app: {e}")
        import traceback

        traceback.print_exc()
