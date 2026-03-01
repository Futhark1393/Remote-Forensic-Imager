# Tests for ForenXtract (FX) TriageDashboard — chart generation, HTML output,
# and edge cases (missing data, empty JSON, malformed input).
# Uses real matplotlib/plotly but writes to temp directories.

import json
import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest

# Guard: skip if visualization dependencies are missing
pd = pytest.importorskip("pandas")
plt = pytest.importorskip("matplotlib.pyplot")
go = pytest.importorskip("plotly.graph_objects")

from fx.report.dashboard import TriageDashboard


# ═══════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def tmpdir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def _write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f)
    return path


def _sample_processes_json(tmpdir):
    """Create a sample processes JSON matching triage output format."""
    data = {
        "data": {
            "processes": [
                {"pid": "1", "user": "root", "cpu": "5.0", "mem": "2.1", "rss": "1024",
                 "tty": "?", "command": "systemd"},
                {"pid": "100", "user": "root", "cpu": "12.0", "mem": "8.5", "rss": "4096",
                 "tty": "?", "command": "kworker"},
                {"pid": "200", "user": "alice", "cpu": "25.0", "mem": "15.0", "rss": "8192",
                 "tty": "pts/0", "command": "firefox"},
                {"pid": "300", "user": "alice", "cpu": "3.0", "mem": "1.0", "rss": "512",
                 "tty": "pts/0", "command": "bash"},
                {"pid": "400", "user": "bob", "cpu": "0.5", "mem": "0.3", "rss": "256",
                 "tty": "pts/1", "command": "vim"},
            ]
        }
    }
    return _write_json(os.path.join(tmpdir, "processes.json"), data)


def _sample_network_json(tmpdir):
    """Create a sample network JSON matching triage output format."""
    data = {
        "data": {
            "connections": (
                "Proto State  Recv-Q Send-Q Local          Foreign\n"
                "tcp   ESTAB  0      0      10.0.0.1:22    10.0.0.2:54321\n"
                "tcp   LISTEN 0      128    0.0.0.0:80     0.0.0.0:*\n"
                "udp   UNCONN 0      0      0.0.0.0:53     0.0.0.0:*\n"
                "tcp   ESTAB  0      0      10.0.0.1:443   10.0.0.3:12345\n"
            )
        }
    }
    return _write_json(os.path.join(tmpdir, "network.json"), data)


def _sample_memory_json(tmpdir):
    """Create a sample memory JSON matching triage output format."""
    data = {
        "data": {
            "meminfo": {
                "MemTotal": "16384000 kB",
                "MemAvailable": "8192000 kB",
                "SwapTotal": "4096000 kB",
                "SwapFree": "3072000 kB",
            }
        }
    }
    return _write_json(os.path.join(tmpdir, "memory.json"), data)


# ═══════════════════════════════════════════════════════════════════════
# Dashboard initialization
# ═══════════════════════════════════════════════════════════════════════

class TestDashboardInit:
    def test_creates_dashboard_directory(self, tmpdir):
        dash = TriageDashboard("CASE-001", tmpdir)
        expected_dir = os.path.join(tmpdir, "triage", "dashboard")
        assert os.path.isdir(expected_dir)

    def test_dashboard_path_contains_case_no(self, tmpdir):
        dash = TriageDashboard("CASE-001", tmpdir)
        assert "CASE-001" in dash.dashboard_path

    def test_dashboard_path_is_html(self, tmpdir):
        dash = TriageDashboard("CASE-001", tmpdir)
        assert dash.dashboard_path.endswith(".html")


# ═══════════════════════════════════════════════════════════════════════
# Process chart generation
# ═══════════════════════════════════════════════════════════════════════

class TestProcessCharts:
    def test_returns_empty_for_none_path(self, tmpdir):
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_process_charts(None)
        assert result["stats"]["total_processes"] == 0
        assert result["charts"] == {}

    def test_returns_empty_for_missing_file(self, tmpdir):
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_process_charts("/nonexistent/file.json")
        assert result["stats"]["total_processes"] == 0

    def test_generates_charts_from_valid_data(self, tmpdir):
        proc_path = _sample_processes_json(tmpdir)
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_process_charts(proc_path)

        assert result["stats"]["total_processes"] == 5
        assert len(result["stats"]["top_cpu_consumers"]) > 0
        assert "top_cpu" in result["charts"]
        assert "top_mem" in result["charts"]
        assert "user_distribution" in result["charts"]

    def test_cpu_top_consumer_is_firefox(self, tmpdir):
        proc_path = _sample_processes_json(tmpdir)
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_process_charts(proc_path)
        top_cpu = result["stats"]["top_cpu_consumers"]
        assert top_cpu[0]["command"] == "firefox"

    def test_user_distribution_counts(self, tmpdir):
        proc_path = _sample_processes_json(tmpdir)
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_process_charts(proc_path)
        users = result["stats"]["process_count_by_user"]
        assert users.get("root", 0) == 2
        assert users.get("alice", 0) == 2

    def test_empty_process_list(self, tmpdir):
        path = _write_json(os.path.join(tmpdir, "empty_proc.json"),
                           {"data": {"processes": []}})
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_process_charts(path)
        assert result["stats"]["total_processes"] == 0

    def test_malformed_json_returns_empty(self, tmpdir):
        path = os.path.join(tmpdir, "bad.json")
        with open(path, "w") as f:
            f.write("{invalid json!!")
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_process_charts(path)
        assert result["stats"]["total_processes"] == 0


# ═══════════════════════════════════════════════════════════════════════
# Network chart generation
# ═══════════════════════════════════════════════════════════════════════

class TestNetworkCharts:
    def test_returns_empty_for_none_path(self, tmpdir):
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_network_charts(None)
        assert result["stats"]["total_connections"] == 0

    def test_returns_empty_for_unavailable_data(self, tmpdir):
        path = _write_json(os.path.join(tmpdir, "net.json"),
                           {"data": {"connections": "UNAVAILABLE"}})
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_network_charts(path)
        assert result["stats"]["total_connections"] == 0

    def test_generates_charts_from_valid_data(self, tmpdir):
        net_path = _sample_network_json(tmpdir)
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_network_charts(net_path)

        assert result["stats"]["total_connections"] == 4
        assert "connection_states" in result["charts"]
        assert "protocol_distribution" in result["charts"]

    def test_state_counts(self, tmpdir):
        net_path = _sample_network_json(tmpdir)
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_network_charts(net_path)
        states = result["stats"]["connection_states"]
        assert states.get("ESTAB", 0) == 2
        assert states.get("LISTEN", 0) == 1


# ═══════════════════════════════════════════════════════════════════════
# Memory chart generation
# ═══════════════════════════════════════════════════════════════════════

class TestMemoryCharts:
    def test_returns_empty_for_none_path(self, tmpdir):
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_memory_charts(None)
        assert result["stats"]["total_memory"] == 0

    def test_generates_charts_from_valid_data(self, tmpdir):
        mem_path = _sample_memory_json(tmpdir)
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_memory_charts(mem_path)

        assert result["stats"]["total_memory"] == 16384000
        assert result["stats"]["memory_available"] == 8192000
        assert result["stats"]["memory_used"] == 16384000 - 8192000
        assert "memory_usage" in result["charts"]
        assert "memory_breakdown" in result["charts"]

    def test_swap_calculation(self, tmpdir):
        mem_path = _sample_memory_json(tmpdir)
        dash = TriageDashboard("C1", tmpdir)
        result = dash.generate_memory_charts(mem_path)
        assert result["stats"]["swap_usage"] == 4096000 - 3072000


# ═══════════════════════════════════════════════════════════════════════
# Full dashboard generation
# ═══════════════════════════════════════════════════════════════════════

class TestFullDashboard:
    def test_generates_html_file(self, tmpdir):
        proc_path = _sample_processes_json(tmpdir)
        net_path = _sample_network_json(tmpdir)
        mem_path = _sample_memory_json(tmpdir)

        dash = TriageDashboard("DASH-001", tmpdir)
        result_path = dash.generate_dashboard(proc_path, net_path, mem_path)

        assert result_path is not None
        assert os.path.isfile(result_path)

    def test_html_contains_case_number(self, tmpdir):
        proc_path = _sample_processes_json(tmpdir)
        dash = TriageDashboard("DASH-001", tmpdir)
        result_path = dash.generate_dashboard(proc_path)

        with open(result_path, "r") as f:
            html = f.read()
        assert "DASH-001" in html

    def test_html_contains_plotly_js(self, tmpdir):
        dash = TriageDashboard("C1", tmpdir)
        result_path = dash.generate_dashboard()

        with open(result_path, "r") as f:
            html = f.read()
        # Either real plotly or fallback stub
        assert "<script>" in html

    def test_dashboard_with_no_data(self, tmpdir):
        """Dashboard should still generate valid HTML with no triage data."""
        dash = TriageDashboard("EMPTY-001", tmpdir)
        result_path = dash.generate_dashboard()

        assert result_path is not None
        assert os.path.isfile(result_path)
        with open(result_path, "r") as f:
            html = f.read()
        assert "<!DOCTYPE html>" in html
        assert "EMPTY-001" in html

    def test_fig_to_base64(self, tmpdir):
        """_fig_to_base64 should return a data:image/png;base64 string."""
        dash = TriageDashboard("C1", tmpdir)
        fig, ax = plt.subplots()
        ax.plot([1, 2, 3], [4, 5, 6])
        b64 = dash._fig_to_base64(fig)
        assert b64.startswith("data:image/png;base64,")

    def test_plotly_to_html(self, tmpdir):
        """_plotly_to_html should return an HTML div string."""
        dash = TriageDashboard("C1", tmpdir)
        fig = go.Figure(data=[go.Bar(x=["A"], y=[1])])
        html = dash._plotly_to_html(fig)
        assert "<div" in html

    def test_get_plotly_js_returns_string(self, tmpdir):
        dash = TriageDashboard("C1", tmpdir)
        js = dash._get_plotly_js()
        assert isinstance(js, str)
        assert len(js) > 0
