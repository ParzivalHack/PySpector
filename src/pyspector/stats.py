from __future__ import annotations

import threading
import time
from collections import Counter
from typing import Any, Dict, List, Optional

_TW = 70
_IW = _TW - 2   # 68
_LW = 32         # left  column
_RW = _IW - _LW - 1  # 35  right column



def _top() -> str:
    return "╔" + "═" * _IW + "╗"

def _sep_top() -> str:
    """First horizontal split: introduces the two-column layout."""
    return "╠" + "═" * _LW + "╦" + "═" * _RW + "╣"

def _sep() -> str:
    """Internal two-column divider."""
    return "╠" + "═" * _LW + "╬" + "═" * _RW + "╣"

def _bot() -> str:
    return "╚" + "═" * _LW + "╩" + "═" * _RW + "╝"

def _banner(text: str) -> str:
    """Full-width centred title row (single column)."""
    return "║" + text.center(_IW) + "║"

def _section_title(text: str) -> str:
    """Two-column section header row (title on left, blank right)."""
    left  = ("  " + text).ljust(_LW)
    right = " " * _RW
    return f"║{left}║{right}║"

def _row(label: str, value: str) -> str:
    left  = ("  " + label).ljust(_LW)
    right = ("  " + str(value)).ljust(_RW)
    return f"║{left}║{right}║"


class StatsCollector:

    def __init__(self) -> None:
        # Timing
        self._t_start: Optional[float] = None
        self._t_end:   Optional[float] = None

        # File metrics
        self.files_scanned: int = 0
        self.files_skipped: int = 0
        self.parse_errors:  int = 0
        self.total_loc:     int = 0

        # Rule metadata
        self.rules_count: int = 0
        # rule_id → "regex" | "ast" | "taint"
        self._rule_detection: Dict[str, str] = {}

        # Issue counters
        self.pre_filter_count:    int = 0   # raw from Rust (post dedup)
        self.severity_filtered:   int = 0   # dropped by --severity threshold
        self.baseline_ignored:    int = 0   # dropped by baseline file
        self.final_issues: List[Any] = []

        # Per-engine breakdown
        self.regex_findings: int = 0
        self.ast_findings:   int = 0
        self.taint_findings: int = 0

        # Resource usage (populated by background thread)
        self.peak_memory_mb:    Optional[float] = None
        self.cpu_cores_logical: Optional[int]   = None
        self.avg_cpu_percent:   Optional[float] = None
        self._cpu_samples: List[float] = []

        self._mon_thread: Optional[threading.Thread] = None
        self._stop_evt   = threading.Event()
        self._psutil_ok: bool = False


    def start(self) -> None:
        """Begin timing and background resource monitoring."""
        self._t_start = time.perf_counter()
        self._launch_monitor()

    def stop(self) -> None:
        """Stop timing and resource monitoring."""
        self._t_end = time.perf_counter()
        self._stop_evt.set()
        if self._mon_thread:
            self._mon_thread.join(timeout=2.0)
        if self._cpu_samples:
            self.avg_cpu_percent = sum(self._cpu_samples) / len(self._cpu_samples)


    def record_files(
        self,
        python_files_data: List[Dict[str, Any]],
        skipped: int = 0,
        errors:  int = 0,
    ) -> None:
        """Record file-level metrics after AST generation."""
        self.files_scanned = len(python_files_data)
        self.files_skipped = skipped
        self.parse_errors  = errors
        self.total_loc = sum(
            f.get("content", "").count("\n") + 1
            for f in python_files_data
        )

    def record_rules(self, rules_toml_str: str) -> None:
        try:
            import toml  # already a project dependency
            data = toml.loads(rules_toml_str)
            rules = data.get("rule", [])
            self.rules_count = len(rules)

            for sink in data.get("taint_sink", []):
                vid = sink.get("vulnerability_id", "")
                if vid:
                    self._rule_detection[vid] = "taint"

            for rule in rules:
                rid = rule.get("id", "")
                if rid in self._rule_detection:
                    continue  # already tagged via taint sink
                has_ast   = bool(rule.get("ast_match"))
                has_regex = bool(rule.get("pattern"))
                if has_regex:
                    self._rule_detection[rid] = "regex"
                elif has_ast:
                    self._rule_detection[rid] = "ast"
                else:
                    self._rule_detection[rid] = "taint"
        except Exception:
            pass

    def record_raw_issues(self, raw_issues: List[Any]) -> None:
        self.pre_filter_count = len(raw_issues)
        for issue in raw_issues:
            method = self._rule_detection.get(issue.rule_id, "regex")
            if method == "ast":
                self.ast_findings += 1
            elif method == "taint":
                self.taint_findings += 1
            else:
                self.regex_findings += 1

    def record_final_issues(
        self,
        final_issues:     List[Any],
        severity_filtered: int = 0,
        baseline_ignored:  int = 0,
    ) -> None:
        """Record the issues that survive all filters."""
        self.final_issues      = final_issues
        self.severity_filtered = severity_filtered
        self.baseline_ignored  = baseline_ignored


    @property
    def elapsed(self) -> float:
        if self._t_start is not None and self._t_end is not None:
            return max(self._t_end - self._t_start, 0.0)
        return 0.0

    @property
    def loc_per_sec(self) -> float:
        return self.total_loc / self.elapsed if self.elapsed > 0 else 0.0

    @property
    def vuln_density(self) -> float:
        """Issues per 1,000 LoC."""
        return (len(self.final_issues) / self.total_loc * 1_000) if self.total_loc else 0.0


    def _launch_monitor(self) -> None:
        try:
            import psutil
            self._psutil_ok = True
            self.cpu_cores_logical = psutil.cpu_count(logical=True)
            proc = psutil.Process()

            def _monitor() -> None:
                peak = 0.0
                while not self._stop_evt.wait(timeout=0.15):
                    try:
                        mem = proc.memory_info().rss / 1_048_576  # bytes → MB
                        peak = max(peak, mem)
                        cpu = proc.cpu_percent()
                        if cpu > 0:
                            self._cpu_samples.append(cpu)
                    except Exception:
                        break
                self.peak_memory_mb = peak

            self._mon_thread = threading.Thread(target=_monitor, daemon=True)
            self._mon_thread.start()
        except ImportError:
            self._psutil_ok = False


    def render_table(self) -> str:
        lines: List[str] = []

        lines.append(_top())
        lines.append(_banner("PYSPECTOR SCAN STATISTICS"))
        lines.append(_sep_top())   # first column split

        lines.append(_section_title("PERFORMANCE"))
        lines.append(_sep())

        elapsed_str = f"{self.elapsed:.2f}s"
        lines.append(_row("Total scan time",            elapsed_str))
        lines.append(_row("Lines of code scanned",      f"{self.total_loc:,}"))
        lines.append(_row("Throughput",                 f"{self.loc_per_sec:,.0f} LoC/sec"))
        lines.append(_row("Python files scanned",       str(self.files_scanned)))
        lines.append(_row("Files skipped",              str(self.files_skipped)))
        lines.append(_row("Parse errors",               str(self.parse_errors)))

        lines.append(_sep())
        lines.append(_section_title("RESOURCE USAGE"))
        lines.append(_sep())

        if self._psutil_ok:
            mem_str = (
                f"{self.peak_memory_mb:.0f} MB"
                if self.peak_memory_mb is not None
                else "n/a"
            )
            lines.append(_row("Peak memory usage", mem_str))

            if self.avg_cpu_percent is not None and self.cpu_cores_logical:
                cores_used = self.avg_cpu_percent / 100
                lines.append(_row(
                    "CPU cores utilized",
                    f"{cores_used:.1f} / {self.cpu_cores_logical} logical cores",
                ))
                lines.append(_row(
                    "Avg CPU utilization",
                    f"{self.avg_cpu_percent:.0f}% (multi-core, can exceed 100%)",
                ))
            else:
                lines.append(_row("CPU usage", "scan completed too quickly to sample"))
        else:
            lines.append(_row(
                "Resource tracking",
                "run  pip install psutil  to enable this section",
            ))

        lines.append(_sep())
        lines.append(_section_title("ANALYSIS BREAKDOWN"))
        lines.append(_sep())

        lines.append(_row("Rules evaluated",           str(self.rules_count)))
        lines.append(_row("Regex engine findings",     str(self.regex_findings)))
        lines.append(_row("AST engine findings",       str(self.ast_findings)))
        lines.append(_row("Taint engine findings",     str(self.taint_findings)))
        lines.append(_row("Severity-filtered out",     str(self.severity_filtered)))
        lines.append(_row("Baseline-ignored",          str(self.baseline_ignored)))

        lines.append(_sep())
        lines.append(_section_title("FINDINGS SUMMARY"))
        lines.append(_sep())

        sev_counts = Counter(
            str(i.severity).split(".")[-1].upper()
            for i in self.final_issues
        )
        lines.append(_row("Total issues (post-filter)", str(len(self.final_issues))))
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = sev_counts.get(sev, 0)
            lines.append(_row(f"  {sev.capitalize()}", str(n)))
        lines.append(_row(
            "Vulnerability density",
            f"{self.vuln_density:.2f} issues / 1,000 LoC",
        ))

        if self.final_issues:
            rule_counts = Counter(i.rule_id for i in self.final_issues)
            top_rules   = rule_counts.most_common(5)

            lines.append(_sep())
            lines.append(_section_title("TOP RULES TRIGGERED"))
            lines.append(_sep())
            for rule_id, count in top_rules:
                lines.append(_row(
                    f"  {rule_id}",
                    f"{count} hit{'s' if count != 1 else ''}",
                ))

        if self.final_issues:
            file_counts = Counter(i.file_path for i in self.final_issues)
            top_files   = file_counts.most_common(5)

            lines.append(_sep())
            lines.append(_section_title("MOST VULNERABLE FILES"))
            lines.append(_sep())
            for fpath, count in top_files:
                # Truncate very long paths gracefully
                display = fpath if len(fpath) <= 27 else "…" + fpath[-26:]
                lines.append(_row(
                    f"  {display}",
                    f"{count} issue{'s' if count != 1 else ''}",
                ))

        lines.append(_bot())

        return "\n".join(lines)