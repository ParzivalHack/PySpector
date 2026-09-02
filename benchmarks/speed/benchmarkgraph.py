#!/usr/bin/env python3
"""
PySpector vs Semgrep vs Bandit — Speed Benchmark Visualization
================================================================

Generates a professional, publication-ready multi-panel figure from the raw
per-run benchmark data (8 repos x 3 tools x 5 runs, executed via Satori CI,
16 vCPU / 120GB, post resource-provisioning-bug-fix, 2026-08-28).

Data is embedded directly (not read from the summary CSV) because the CSV
only contains per-repo medians — the per-run variance panel below needs the
individual run values, which only exist in the full console/raw-log output.

Run with: python3 pyspector_benchmark_graphs.py
Requires: numpy, matplotlib
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ---------------------------------------------------------------------------
# Raw data — transcribed directly from the benchmark run's raw per-run output.
# Each repo's "loc" is PySpector's own measured Python-only line count (the
# same denominator used for all three tools' throughput calculations).
# One run (fastapi/fastapi, bandit, run 5) failed (Satori exit code 1) and is
# excluded here exactly as it was excluded from the original run's medians.
# ---------------------------------------------------------------------------

DATA = {
    "flask": {
        "loc": 10493,
        "pyspector": {
            "time": [0.50, 0.51, 0.50, 0.36, 0.51],
            "throughput": [20959, 20599, 20926, 29397, 20756],
            "mem_mb": [125, 121, 124, 124, 126],
            "cores": [2.0, 2.0, 2.0, 3.9, 2.0],
        },
        "semgrep": {
            "time": [4.558, 6.574, 6.511, 6.593, 8.013],
            "throughput": [2302, 1596, 1612, 1592, 1309],
        },
        "bandit": {
            "time": [0.813, 1.424, 1.590, 0.809, 1.470],
            "throughput": [12907, 7369, 6599, 12970, 7138],
        },
    },
    "click": {
        "loc": 14111,
        "pyspector": {
            "time": [0.73, 0.75, 0.79, 0.75, 0.50],
            "throughput": [19219, 18828, 17818, 18803, 28323],
            "mem_mb": [120, 121, 168, 116, 167],
            "cores": [1.3, 1.3, 1.9, 1.3, 3.7],
        },
        "semgrep": {
            "time": [8.012, 10.884, 8.325, 8.923, 8.655],
            "throughput": [1761, 1296, 1695, 1581, 1630],
        },
        "bandit": {
            "time": [2.483, 2.293, 1.483, 1.442, 2.350],
            "throughput": [5683, 6154, 9515, 9786, 6005],
        },
    },
    "fastapi": {
        "loc": 34204,
        "pyspector": {
            "time": [1.72, 1.71, 1.17, 1.78, 1.72],
            "throughput": [19876, 19981, 29113, 19164, 19923],
            "mem_mb": [231, 232, 212, 229, 232],
            "cores": [2.0, 2.0, 2.6, 2.0, 2.0],
        },
        "semgrep": {
            "time": [31.006, 20.438, 31.692, 31.067, 30.907],
            "throughput": [1103, 1674, 1079, 1101, 1107],
        },
        "bandit": {
            # run 5 failed (Satori exit code 1) — excluded, n=4 for this cell
            "time": [7.551, 7.844, 4.724, 7.784],
            "throughput": [4530, 4361, 7240, 4394],
        },
    },
    "scrapy": {
        "loc": 41495,
        "pyspector": {
            "time": [2.19, 2.14, 2.15, 2.16, 2.19],
            "throughput": [18911, 19359, 19294, 19184, 18955],
            "mem_mb": [344, 344, 344, 343, 345],
            "cores": [2.2, 2.2, 2.2, 2.2, 2.2],
        },
        "semgrep": {
            "time": [5.929, 10.305, 9.253, 9.419, 9.114],
            "throughput": [6999, 4027, 4484, 4405, 4553],
        },
        "bandit": {
            "time": [8.107, 8.137, 4.531, 4.498, 4.472],
            "throughput": [5118, 5100, 9158, 9225, 9279],
        },
    },
    "ansible": {
        "loc": 208900,
        "pyspector": {
            "time": [12.52, 13.57, 12.44, 13.80, 13.51],
            "throughput": [16690, 15397, 16789, 15142, 15460],
            "mem_mb": [1457, 1450, 1458, 1461, 1458],
            "cores": [4.7, 4.5, 4.7, 4.4, 4.5],
        },
        "semgrep": {
            "time": [30.366, 24.805, 25.941, 25.063, 24.980],
            "throughput": [6879, 8422, 8053, 8335, 8363],
        },
        "bandit": {
            "time": [11.899, 8.671, 13.989, 20.805, 19.842],
            "throughput": [17556, 24092, 14933, 10041, 10528],
        },
    },
    "keras": {
        "loc": 212806,
        "pyspector": {
            "time": [12.63, 13.09, 8.49, 12.86, 12.64],
            "throughput": [16849, 16254, 25052, 16554, 16833],
            "mem_mb": [1590, 1591, 1592, 1595, 1592],
            "cores": [5.4, 5.4, 4.9, 5.3, 5.6],
        },
        "semgrep": {
            "time": [39.454, 22.636, 20.547, 39.875, 36.347],
            "throughput": [5394, 9401, 10357, 5337, 5855],
        },
        "bandit": {
            "time": [30.865, 13.293, 17.634, 28.456, 30.790],
            "throughput": [6895, 16009, 12068, 7478, 6912],
        },
    },
    "pandas": {
        "loc": 294267,
        "pyspector": {
            "time": [20.78, 21.09, 20.47, 21.34, 19.59],
            "throughput": [14164, 13955, 14374, 13792, 15018],
            "mem_mb": [1736, 1736, 1731, 1737, 1737],
            "cores": [8.6, 8.6, 8.6, 8.5, 8.8],
        },
        "semgrep": {
            "time": [33.051, 35.439, 34.421, 33.298, 35.785],
            "throughput": [8903, 8303, 8549, 8837, 8223],
        },
        "bandit": {
            "time": [40.137, 40.004, 66.439, 67.089, 65.516],
            "throughput": [7332, 7356, 4429, 4386, 4492],
        },
    },
    "django": {
        "loc": 348032,
        "pyspector": {
            "time": [22.63, 23.55, 22.33, 23.34, 22.41],
            "throughput": [15379, 14781, 15586, 14914, 15532],
            "mem_mb": [2164, 2169, 2167, 2163, 2167],
            "cores": [5.7, 5.6, 5.7, 5.5, 5.7],
        },
        "semgrep": {
            "time": [60.576, 61.488, 38.358, 37.678, 60.779],
            "throughput": [5745, 5660, 9073, 9237, 5726],
        },
        "bandit": {
            "time": [29.244, 29.334, 49.845, 29.301, 49.203],
            "throughput": [11901, 11864, 6982, 11878, 7073],
        },
    },
}

TOOLS = ["pyspector", "semgrep", "bandit"]
TOOL_LABELS = {"pyspector": "PySpector", "semgrep": "Semgrep", "bandit": "Bandit"}
TOOL_COLORS = {"pyspector": "#1f77b4", "semgrep": "#d62728", "bandit": "#2ca02c"}
TOOL_MARKERS = {"pyspector": "o", "semgrep": "s", "bandit": "^"}

# Repos sorted by PySpector's own measured LoC (the real, verified ordering —
# note this differs slightly from initially-assumed GitHub-reported sizes,
# e.g. fastapi's Python-only LoC is smaller than scrapy's).
REPOS_SORTED = sorted(DATA.keys(), key=lambda r: DATA[r]["loc"])

# ---------------------------------------------------------------------------
# Aggregate with numpy: median (robust, used for per-repo comparison) and
# pooled mean across all successful runs (matches the benchmark script's own
# "OVERALL BENCHMARK AVERAGES" methodology).
# ---------------------------------------------------------------------------

loc_values = np.array([DATA[r]["loc"] for r in REPOS_SORTED])

median_throughput = {tool: np.array([np.median(DATA[r][tool]["throughput"]) for r in REPOS_SORTED])
                      for tool in TOOLS}
median_time = {tool: np.array([np.median(DATA[r][tool]["time"]) for r in REPOS_SORTED])
                for tool in TOOLS}

overall_mean_throughput = {}
overall_mean_time = {}
for tool in TOOLS:
    pooled_throughput = np.concatenate([DATA[r][tool]["throughput"] for r in REPOS_SORTED]).astype(float)
    pooled_time = np.concatenate([DATA[r][tool]["time"] for r in REPOS_SORTED]).astype(float)
    overall_mean_throughput[tool] = np.mean(pooled_throughput)
    overall_mean_time[tool] = np.mean(pooled_time)

pyspector_mem = np.array([np.mean(DATA[r]["pyspector"]["mem_mb"]) for r in REPOS_SORTED])
pyspector_cores = np.array([np.mean(DATA[r]["pyspector"]["cores"]) for r in REPOS_SORTED])

n_successful = {tool: sum(len(DATA[r][tool]["time"]) for r in REPOS_SORTED) for tool in TOOLS}
n_expected = len(REPOS_SORTED) * 5

# ---------------------------------------------------------------------------
# Figure
# ---------------------------------------------------------------------------

plt.rcParams.update({
    "font.size": 10,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "axes.edgecolor": "#444444",
    "figure.facecolor": "white",
})

fig, axes = plt.subplots(2, 3, figsize=(19, 11))
fig.suptitle(
    "PySpector vs Semgrep vs Bandit — Speed Benchmark (8 repos, 5 runs/tool, Satori CI 16 vCPU/120GB)",
    fontsize=15, fontweight="bold", y=0.98,
)

# --- Panel 1: Median throughput vs LoC (log-log scaling curve) ---
ax = axes[0, 0]
for tool in TOOLS:
    ax.plot(loc_values, median_throughput[tool], marker=TOOL_MARKERS[tool],
             color=TOOL_COLORS[tool], label=TOOL_LABELS[tool], linewidth=2, markersize=8)
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Lines of Code (log scale)")
ax.set_ylabel("Median Throughput (LoC/sec, log scale)")
ax.set_title("Throughput Scaling Curve (median of 5 runs)")
ax.legend()
ax.yaxis.set_major_formatter(mticker.ScalarFormatter())

# --- Panel 2: Median scan time vs LoC (log-log scaling curve) ---
ax = axes[0, 1]
for tool in TOOLS:
    ax.plot(loc_values, median_time[tool], marker=TOOL_MARKERS[tool],
             color=TOOL_COLORS[tool], label=TOOL_LABELS[tool], linewidth=2, markersize=8)
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Lines of Code (log scale)")
ax.set_ylabel("Median Scan Time (seconds, log scale)")
ax.set_title("Scan Time Scaling Curve (median of 5 runs)")
ax.legend()

# --- Panel 3: Overall average throughput comparison (bar chart) ---
ax = axes[0, 2]
bars = ax.bar([TOOL_LABELS[t] for t in TOOLS],
              [overall_mean_throughput[t] for t in TOOLS],
              color=[TOOL_COLORS[t] for t in TOOLS])
for bar, tool in zip(bars, TOOLS):
    height = bar.get_height()
    ax.annotate(f"{height:,.0f}", (bar.get_x() + bar.get_width() / 2, height),
                textcoords="offset points", xytext=(0, 5), ha="center", fontweight="bold")
ax.set_ylabel("Average Throughput (LoC/sec)")
ax.set_title(f"Overall Average Throughput\n(mean across all successful runs, n={n_expected} attempted/tool)")

# --- Panel 4: Per-run throughput variance (all individual runs, not just median) ---
ax = axes[1, 0]
rng = np.random.default_rng(42)  # fixed seed: jitter is deterministic, for visual separation only
for tool in TOOLS:
    xs, ys = [], []
    for r in REPOS_SORTED:
        vals = DATA[r][tool]["throughput"]
        jittered_x = DATA[r]["loc"] * (1 + rng.uniform(-0.04, 0.04, size=len(vals)))
        xs.extend(jittered_x)
        ys.extend(vals)
    ax.scatter(xs, ys, color=TOOL_COLORS[tool], marker=TOOL_MARKERS[tool],
               label=TOOL_LABELS[tool], alpha=0.7, s=45, edgecolors="none")
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Lines of Code (log scale)")
ax.set_ylabel("Throughput per run (LoC/sec, log scale)")
ax.set_title("All Individual Runs (variance across 5 reps)\nx-jittered slightly for visibility only")
ax.legend()

# --- Panel 5: PySpector peak memory vs LoC ---
ax = axes[1, 1]
ax.plot(loc_values, pyspector_mem, marker="o", color=TOOL_COLORS["pyspector"], linewidth=2, markersize=8)
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Lines of Code (log scale)")
ax.set_ylabel("Peak Memory (MB, log scale)")
ax.set_title("PySpector Resource Consumption: Memory")

# --- Panel 6: PySpector CPU cores utilized vs LoC ---
ax = axes[1, 2]
ax.plot(loc_values, pyspector_cores, marker="o", color=TOOL_COLORS["pyspector"], linewidth=2, markersize=8)
ax.axhline(16, color="gray", linestyle="--", linewidth=1, alpha=0.6, label="16 vCPUs available")
ax.set_xscale("log")
ax.set_xlabel("Lines of Code (log scale)")
ax.set_ylabel("CPU Cores Utilized (of 16 available)")
ax.set_title("PySpector Resource Consumption: CPU Cores")
ax.set_ylim(0, 17)
ax.legend()

fig.text(
    0.5, 0.005,
    "Note: fastapi/fastapi Bandit run 5 failed (Satori exit code 1, container error) and is excluded "
    "(n=4 for that cell only, n=5 for every other cell). "
    "LoC values are PySpector's own measured Python-only line counts per repo.",
    ha="center", fontsize=8.5, style="italic", color="#555555",
)

plt.tight_layout(rect=[0, 0.02, 1, 0.96])

fig.savefig("pyspector_benchmark_graphs.png", dpi=200, bbox_inches="tight")
fig.savefig("pyspector_benchmark_graphs.pdf", bbox_inches="tight")

print("Saved: pyspector_benchmark_graphs.png (raster, for quick viewing)")
print("Saved: pyspector_benchmark_graphs.pdf (vector, for paper inclusion)")
print()
print("Overall mean throughput (sanity check vs original script's own reported values):")
for tool in TOOLS:
    print(f"  {TOOL_LABELS[tool]:10s}: {overall_mean_throughput[tool]:,.0f} LoC/sec "
          f"(n={n_successful[tool]}/{n_expected} successful runs)")
