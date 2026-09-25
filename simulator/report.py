"""
simulator/report.py

Turns a simulator/netsim.py results directory (events.json + metrics.json,
both real captured data -- see netsim.py's own docstring) into report
figures. Two of the six figures below run their own live measurement at
report-generation time rather than reading from the results directory:

  - fig_hmac_overhead.png runs a real microbenchmark of
    saf.crypto_utils.hmac_sha256 (the as-specified alpha vs. the hardened,
    sequence/message-bound alpha) on this machine, right now.
  - fig_scyther_claims.png shells out to the real scyther binary against
    the three real .spdl models, right now (same mechanism as the
    dashboard's /api/scyther endpoint).

Nothing in any figure is a placeholder or an assumed value.

Usage:
    python3 -m simulator.report <results_dir> [--out-dir <dir>]
"""

import argparse
import json
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from saf import crypto_utils as cu  # noqa: E402

# --- palette (validated categorical / status colors; see dataviz skill) ---
BLUE = "#2a78d6"       # categorical slot 1 -- legitimate / as-specified
ORANGE = "#eb6834"     # categorical slot 2 -- secondary series
GOOD = "#0ca30c"       # status: good / pass / hardened
CRITICAL = "#d03b3b"   # status: critical / denied / attacker
TEXT = "#0b0b0b"
MUTED = "#52514e"
SURFACE = "#fcfcfb"
GRID = "#e3e1dc"

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "text.color": TEXT, "axes.labelcolor": TEXT, "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.edgecolor": GRID, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.7,
    "axes.spines.top": False, "axes.spines.right": False, "font.size": 11,
    "figure.dpi": 150,
})


def fig_latency_hist(metrics: dict, events: list, out: Path):
    lat = [e for e in events if e["kind"] == "phase2_status_received"]
    # Recompute the same real per-message latencies netsim.py derived, so
    # the histogram matches metrics.json's summary exactly.
    from collections import deque
    pending = {}
    for e in events:
        if e["kind"] == "phase2_request_sent" and e["source"].startswith("client:"):
            key = (e["data"]["client_id"], e["data"]["identifier_msg"])
            pending.setdefault(key, deque()).append(e["ts"])
    values = []
    for e in lat:
        key = (e["data"]["client_id"], e["data"]["identifier_msg"])
        q = pending.get(key)
        if q:
            values.append((e["ts"] - q.popleft()) * 1000.0)

    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    ax.hist(values, bins=30, color=BLUE, edgecolor=SURFACE, linewidth=0.5)
    ymax = ax.get_ylim()[1]
    ax.set_ylim(0, ymax * 1.22)
    for i, (p, label, style) in enumerate([(0.50, "p50", "--"), (0.90, "p90", ":"), (0.99, "p99", "-.")]):
        v = sorted(values)[min(len(values) - 1, int(len(values) * p))]
        ax.axvline(v, color=CRITICAL, linestyle=style, linewidth=1.3)
        ax.text(v, ymax * (1.16 - 0.09 * i), f" {label}={v:.1f}ms", color=CRITICAL, fontsize=9, va="top")
    ax.set_xlabel("Phase-2 round-trip latency (ms) -- client publish to VerificationStatus, real measured")
    ax.set_ylabel("messages")
    ax.set_title(f"SAF Phase-2 authentication latency (n={len(values)} real messages, real Mosquitto broker)", fontsize=12)
    fig.tight_layout()
    fig.savefig(out / "fig_latency_hist.png")
    plt.close(fig)


def fig_outcomes(metrics: dict, out: Path):
    approved = metrics["phase2_approved"]
    reasons = metrics["phase2_denied_reasons"]
    labels = ["Approved"] + list(reasons.keys())
    values = [approved] + list(reasons.values())
    colors = [BLUE] + [CRITICAL] * len(reasons)

    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    bars = ax.bar([_wrap(l) for l in labels], values, color=colors, width=0.55)
    for b, v in zip(bars, values):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v}", ha="center", va="bottom", fontsize=10, color=TEXT)
    ax.set_ylabel("Phase-2 messages")
    ax.set_title(f"Live Phase-2 verification outcomes (n={metrics['phase2_messages_total']} real messages)")
    fig.tight_layout()
    fig.savefig(out / "fig_outcomes.png")
    plt.close(fig)


def _wrap(s: str, width: int = 16) -> str:
    import textwrap
    return "\n".join(textwrap.wrap(s, width))


def fig_registration(metrics: dict, out: Path):
    est = metrics["phase1_established"]
    den = metrics["phase1_denied"]
    cap = metrics["config"]["max_clients"]
    attempted = metrics["clients_attempted"]

    fig, ax = plt.subplots(figsize=(7.2, 4.8))
    bars = ax.bar(["Established\n(Approved)", "Denied\n(rate-limited)"], [est, den], color=[BLUE, CRITICAL], width=0.5)
    ax.set_ylim(0, max(est, den, cap) * 1.22)
    for b, v in zip(bars, [est, den]):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v}", ha="center", va="bottom", fontsize=11)
    ax.axhline(cap, color=MUTED, linestyle="--", linewidth=1.2)
    ax.text(1.42, cap, f" store.max_clients = {cap}", color=MUTED, fontsize=9, va="bottom")
    ax.set_ylabel("clients")
    ax.set_title(f"Section V-B rate-limiting policy, live: {attempted} clients attempted registration", fontsize=12)
    ax.set_xlim(-0.6, 2.3)
    fig.tight_layout()
    fig.savefig(out / "fig_registration.png")
    plt.close(fig)


def fig_topology(events: list, out: Path):
    import math
    reg = {}
    for e in events:
        if e["kind"] in ("phase1_established", "phase1_denied") and (
            e["source"].startswith("client:") or e["kind"] == "phase1_denied"
        ):
            cid = e["data"]["client_id"]
            reg.setdefault(cid, e["kind"])  # first outcome recorded wins

    ids = sorted(reg.keys())
    n = len(ids)
    fig, ax = plt.subplots(figsize=(7.5, 7.5))
    ax.set_aspect("equal")
    ax.axis("off")
    ax.add_patch(plt.Circle((0, 0), 0.12, color=TEXT, zorder=5))
    ax.text(0, -0.24, "SAF Gateway\n+ Mosquitto", ha="center", va="top", fontsize=10, color=TEXT)

    for i, cid in enumerate(ids):
        angle = 2 * math.pi * i / max(1, n)
        x, y = math.cos(angle), math.sin(angle)
        is_attacker = cid.startswith("Attacker")
        established = reg[cid] == "phase1_established"
        color = (CRITICAL if is_attacker else BLUE) if established else "#c9c7c1"
        ax.plot([0, x], [0, y], color=GRID, linewidth=0.8, zorder=1)
        ax.scatter([x], [y], s=90, color=color, zorder=4, edgecolor=SURFACE, linewidth=0.6)

    handles = [
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=BLUE, markersize=9, label="Legitimate client, registered"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=CRITICAL, markersize=9, label="Attacker client, registered"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="#c9c7c1", markersize=9, label="Denied registration (rate limit)"),
    ]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, 0.02), ncol=1, frameon=False, fontsize=9)
    ax.set_title(f"Simulated topology -- {n} clients, one real Mosquitto broker + SAFGateway", fontsize=12)
    fig.tight_layout()
    fig.savefig(out / "fig_topology.png")
    plt.close(fig)


def fig_hmac_overhead(out: Path, iterations: int = 200_000):
    """Live microbenchmark: as-specified alpha = HMAC_k(x||c) vs. the
    hardened, sequence/message-bound alpha = HMAC_k(x||c||idmsg||t_msg)
    verified in scyther/saf_phase2_hardened_final.spdl. Measured on this
    machine, right now -- not a number copied from the paper."""
    k = cu.generate_session_key()
    x = cu.sha256(b"benchmark-client-state")
    c_bytes = cu.counter_to_bytes(1)
    idmsg = cu.new_message_identifier().encode("utf-8")
    tmsg = repr(cu.current_timestamp()).encode("utf-8")

    t0 = time.perf_counter()
    for _ in range(iterations):
        cu.hmac_sha256(k, x + c_bytes)
    t_as_specified = (time.perf_counter() - t0) / iterations * 1e6  # microseconds/op

    t0 = time.perf_counter()
    for _ in range(iterations):
        cu.hmac_sha256(k, x + c_bytes + idmsg + tmsg)
    t_hardened = (time.perf_counter() - t0) / iterations * 1e6

    fig, ax = plt.subplots(figsize=(6, 4.5))
    bars = ax.bar(["As specified\nHMAC_k(x||c)", "Hardened\nHMAC_k(x||c||idmsg||t_msg)"],
                   [t_as_specified, t_hardened], color=[BLUE, GOOD], width=0.5)
    for b, v in zip(bars, [t_as_specified, t_hardened]):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.3f} µs", ha="center", va="bottom", fontsize=10)
    ax.set_ylabel("mean time per HMAC-SHA256 call (µs)")
    pct = (t_hardened / t_as_specified - 1) * 100
    ax.set_title(f"Live HMAC microbenchmark, {iterations:,} iters, {platform.processor() or platform.machine()}\n"
                 f"hardening costs +{pct:.1f}% per Phase-2 message ({t_hardened - t_as_specified:.3f} µs)")
    fig.tight_layout()
    fig.savefig(out / "fig_hmac_overhead.png")
    plt.close(fig)
    return {"as_specified_us": t_as_specified, "hardened_us": t_hardened, "iterations": iterations}


_CLAIM_RE = re.compile(
    r"claim\t(?P<protocol>\S+),(?P<role>\S+)\t(?P<claim_id>\S+)\t(?P<param>\S+)\t"
    r"(?:\x1b\[\d+m)?(?P<verdict>Ok|Fail)(?:\x1b\[0m)?\t\[(?P<comment>[^\]]*)\]"
)
SCYTHER_MODELS = {
    "Phase 1": REPO_ROOT / "scyther" / "saf_phase1.spdl",
    "Phase 2\n(as specified)": REPO_ROOT / "scyther" / "saf_phase2.spdl",
    "Phase 2\n(hardened)": REPO_ROOT / "scyther" / "saf_phase2_hardened_final.spdl",
}


def fig_scyther_claims(out: Path):
    """Live run of the real scyther binary against all three real .spdl
    models -- same mechanism the dashboard's /api/scyther endpoint uses."""
    scyther_bin = REPO_ROOT / "scyther" / "bin" / ("scyther-mac" if platform.system() == "Darwin" else "scyther-linux")
    results = {}
    for label, spdl in SCYTHER_MODELS.items():
        proc = subprocess.run([str(scyther_bin), "--unbounded", str(spdl)], capture_output=True, text=True, timeout=120)
        raw = proc.stdout + proc.stderr
        claims = _CLAIM_RE.findall(raw)
        ok = sum(1 for c in claims if c[4] == "Ok")
        fail = sum(1 for c in claims if c[4] == "Fail")
        results[label] = (ok, fail)

    labels = list(results.keys())
    ok_counts = [results[l][0] for l in labels]
    fail_counts = [results[l][1] for l in labels]

    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    width = 0.35
    xs = range(len(labels))
    ax.bar([x - width / 2 for x in xs], ok_counts, width, label="Ok (proof of correctness)", color=GOOD)
    ax.bar([x + width / 2 for x in xs], fail_counts, width, label="Fail (attack found)", color=CRITICAL)
    ax.set_xticks(list(xs))
    ax.set_xticklabels(labels)
    ax.set_ylabel("Scyther claims")
    ax.legend(frameon=False)
    ax.set_title("Live, unbounded Scyther verification of all three models (run just now)")
    fig.tight_layout()
    fig.savefig(out / "fig_scyther_claims.png")
    plt.close(fig)
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("results_dir", type=str, help="a simulator/results/<timestamp>/ directory from netsim.py")
    p.add_argument("--out-dir", type=str, default=None)
    args = p.parse_args()

    results_dir = Path(args.results_dir)
    events = json.loads((results_dir / "events.json").read_text())
    metrics = json.loads((results_dir / "metrics.json").read_text())
    out_dir = Path(args.out_dir) if args.out_dir else results_dir / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)

    fig_latency_hist(metrics, events, out_dir)
    fig_outcomes(metrics, out_dir)
    fig_registration(metrics, out_dir)
    fig_topology(events, out_dir)
    bench = fig_hmac_overhead(out_dir)
    scyther = fig_scyther_claims(out_dir)

    summary = {"hmac_benchmark": bench, "scyther_claims": scyther}
    (out_dir / "report_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"Wrote 6 figures + report_summary.json to {out_dir}")


if __name__ == "__main__":
    main()
