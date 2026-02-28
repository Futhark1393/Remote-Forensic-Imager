# Author: Futhark1393
# Description: Triage Data Dashboard — generates interactive visualizations and summary charts.
# Features: Process statistics, network connections, memory usage, timeline analysis.

import json
import os
import base64
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.figure import Figure
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd


class TriageDashboard:
    """
    Generates interactive HTML dashboard with triage data visualizations.
    Includes process statistics, network connections, memory usage, and more.
    """

    def __init__(self, case_no: str, output_dir: str):
        self.case_no = case_no
        self.output_dir = output_dir
        self.timestamp_utc = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        
        # Dashboard goes into triage/dashboard/ subdirectory
        dashboard_dir = os.path.join(output_dir, "triage", "dashboard")
        os.makedirs(dashboard_dir, exist_ok=True)
        
        self.dashboard_path = os.path.join(dashboard_dir, f"TriageDashboard_{case_no}_{self.timestamp_utc}.html")

    def _fig_to_base64(self, fig: Figure) -> str:
        """Convert matplotlib figure to base64-encoded PNG for embedding in HTML."""
        buffer = BytesIO()
        fig.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.read()).decode('utf-8')
        plt.close(fig)
        return f"data:image/png;base64,{img_base64}"

    def _plotly_to_html(self, fig: go.Figure) -> str:
        """Convert plotly figure to embedded HTML div."""
        return fig.to_html(include_plotlyjs='cdn', div_id=f"plot_{id(fig)}")

    def generate_process_charts(self, processes_json_path: Optional[str]) -> dict:
        """
        Generate charts from process list data.
        Returns dict with chart HTML and statistics.
        """
        charts = {}
        stats = {
            "total_processes": 0,
            "top_cpu_consumers": [],
            "top_mem_consumers": [],
            "process_count_by_user": {},
            "tty_distribution": {},
        }

        if not processes_json_path or not os.path.exists(processes_json_path):
            return {"charts": charts, "stats": stats}

        try:
            with open(processes_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                processes = data.get("data", {}).get("processes", [])
        except Exception as e:
            print(f"[!] Error reading processes JSON: {e}")
            return {"charts": charts, "stats": stats}

        if not processes:
            return {"charts": charts, "stats": stats}

        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(processes)
        stats["total_processes"] = len(processes)

        # ── Top CPU Consumers ─────────────────────────────────────────
        try:
            df['cpu'] = pd.to_numeric(df['cpu'], errors='coerce')
            top_cpu = df.nlargest(10, 'cpu')[['pid', 'command', 'cpu', 'mem']]
            stats["top_cpu_consumers"] = top_cpu.to_dict('records')

            fig = go.Figure(data=[
                go.Bar(x=top_cpu['command'], y=top_cpu['cpu'], marker_color='royalblue')
            ])
            fig.update_layout(
                title="Top 10 CPU Consumers (%)",
                xaxis_title="Process",
                yaxis_title="CPU %",
                height=400,
                hovermode='x unified'
            )
            charts['top_cpu'] = self._plotly_to_html(fig)
        except Exception as e:
            print(f"[!] Error generating CPU chart: {e}")

        # ── Top Memory Consumers ──────────────────────────────────────
        try:
            df['mem'] = pd.to_numeric(df['mem'], errors='coerce')
            top_mem = df.nlargest(10, 'mem')[['pid', 'command', 'mem', 'rss']]
            stats["top_mem_consumers"] = top_mem.to_dict('records')

            fig = go.Figure(data=[
                go.Bar(x=top_mem['command'], y=top_mem['mem'], marker_color='crimson')
            ])
            fig.update_layout(
                title="Top 10 Memory Consumers (%)",
                xaxis_title="Process",
                yaxis_title="Memory %",
                height=400,
                hovermode='x unified'
            )
            charts['top_mem'] = self._plotly_to_html(fig)
        except Exception as e:
            print(f"[!] Error generating Memory chart: {e}")

        # ── Process Count by User ─────────────────────────────────────
        try:
            user_counts = df['user'].value_counts().head(15)
            stats["process_count_by_user"] = user_counts.to_dict()

            fig = go.Figure(data=[
                go.Pie(labels=user_counts.index, values=user_counts.values)
            ])
            fig.update_layout(
                title="Process Distribution by User",
                height=400
            )
            charts['user_distribution'] = self._plotly_to_html(fig)
        except Exception as e:
            print(f"[!] Error generating user distribution chart: {e}")

        # ── TTY Distribution ──────────────────────────────────────────
        try:
            tty_counts = df['tty'].value_counts()
            stats["tty_distribution"] = tty_counts.to_dict()

            fig = go.Figure(data=[
                go.Bar(x=tty_counts.index, y=tty_counts.values, marker_color='seagreen')
            ])
            fig.update_layout(
                title="Process TTY Distribution",
                xaxis_title="TTY",
                yaxis_title="Count",
                height=400
            )
            charts['tty_distribution'] = self._plotly_to_html(fig)
        except Exception as e:
            print(f"[!] Error generating TTY chart: {e}")

        return {"charts": charts, "stats": stats}

    def generate_network_charts(self, network_json_path: Optional[str]) -> dict:
        """
        Generate charts from network state data.
        Returns dict with chart HTML and connection statistics.
        """
        charts = {}
        stats = {
            "total_connections": 0,
            "listening_ports": [],
            "established_connections": [],
            "connection_states": {},
        }

        if not network_json_path or not os.path.exists(network_json_path):
            return {"charts": charts, "stats": stats}

        try:
            with open(network_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                connections_raw = data.get("data", {}).get("connections", "")
        except Exception as e:
            print(f"[!] Error reading network JSON: {e}")
            return {"charts": charts, "stats": stats}

        if not connections_raw or connections_raw == "UNAVAILABLE":
            return {"charts": charts, "stats": stats}

        # Parse ss/netstat output (simplified parsing)
        try:
            lines = connections_raw.strip().split('\n')
            connections = []
            state_counts = {}

            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 6:
                    state = parts[1] if len(parts) > 1 else "UNKNOWN"
                    state_counts[state] = state_counts.get(state, 0) + 1
                    connections.append({
                        "proto": parts[0] if parts else "?",
                        "state": state,
                    })

            stats["total_connections"] = len(connections)
            stats["connection_states"] = state_counts

            # ── Connection States Pie Chart ───────────────────────────
            if state_counts:
                fig = go.Figure(data=[
                    go.Pie(labels=list(state_counts.keys()), values=list(state_counts.values()))
                ])
                fig.update_layout(
                    title="Network Connection States",
                    height=400
                )
                charts['connection_states'] = self._plotly_to_html(fig)

            # ── Protocol Distribution ─────────────────────────────────
            protos = [c.get("proto") for c in connections]
            proto_counts = {}
            for proto in protos:
                proto_counts[proto] = proto_counts.get(proto, 0) + 1

            if proto_counts:
                fig = go.Figure(data=[
                    go.Bar(x=list(proto_counts.keys()), y=list(proto_counts.values()), marker_color='teal')
                ])
                fig.update_layout(
                    title="Protocol Distribution",
                    xaxis_title="Protocol",
                    yaxis_title="Count",
                    height=400
                )
                charts['protocol_distribution'] = self._plotly_to_html(fig)

        except Exception as e:
            print(f"[!] Error parsing network data: {e}")

        return {"charts": charts, "stats": stats}

    def generate_memory_charts(self, memory_json_path: Optional[str]) -> dict:
        """
        Generate charts from memory state data.
        Returns dict with chart HTML and memory statistics.
        """
        charts = {}
        stats = {
            "total_memory": 0,
            "memory_available": 0,
            "memory_used": 0,
            "swap_usage": 0,
        }

        if not memory_json_path or not os.path.exists(memory_json_path):
            return {"charts": charts, "stats": stats}

        try:
            with open(memory_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                meminfo = data.get("data", {}).get("meminfo", {})
        except Exception as e:
            print(f"[!] Error reading memory JSON: {e}")
            return {"charts": charts, "stats": stats}

        try:
            total = int(meminfo.get("MemTotal", "0").split()[0])
            available = int(meminfo.get("MemAvailable", "0").split()[0])
            used = total - available
            swap_total = int(meminfo.get("SwapTotal", "0").split()[0])
            swap_free = int(meminfo.get("SwapFree", "0").split()[0])
            swap_used = swap_total - swap_free

            stats["total_memory"] = total
            stats["memory_available"] = available
            stats["memory_used"] = used
            stats["swap_usage"] = swap_used

            # ── Memory Usage Gauge ────────────────────────────────────
            if total > 0:
                mem_percent = (used / total) * 100
                fig = go.Figure(data=[go.Indicator(
                    mode="gauge+number+delta",
                    value=mem_percent,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "RAM Usage (%)"},
                    gauge={
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "crimson"},
                        'steps': [
                            {'range': [0, 50], 'color': "lightgreen"},
                            {'range': [50, 80], 'color': "lightyellow"},
                            {'range': [80, 100], 'color': "lightcoral"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': 90
                        }
                    }
                )])
                fig.update_layout(height=400, font={'size': 16})
                charts['memory_usage'] = self._plotly_to_html(fig)

            # ── Memory Breakdown ──────────────────────────────────────
            labels = ['Used', 'Available']
            values = [used, available]
            colors = ['#FF6B6B', '#51CF66']

            fig = go.Figure(data=[go.Pie(labels=labels, values=values, marker=dict(colors=colors))])
            fig.update_layout(
                title="Memory Breakdown (KB)",
                height=400
            )
            charts['memory_breakdown'] = self._plotly_to_html(fig)

        except Exception as e:
            print(f"[!] Error parsing memory data: {e}")

        return {"charts": charts, "stats": stats}

    def generate_dashboard(self, 
                          processes_json_path: Optional[str] = None,
                          network_json_path: Optional[str] = None,
                          memory_json_path: Optional[str] = None) -> str:
        """
        Generate complete HTML dashboard with all triage visualizations.
        
        Returns path to generated HTML file.
        """
        process_data = self.generate_process_charts(processes_json_path)
        network_data = self.generate_network_charts(network_json_path)
        memory_data = self.generate_memory_charts(memory_json_path)

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForenXtract (FX) Triage Dashboard - Case {self.case_no}</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.95;
        }}
        
        .metadata {{
            background: #f8f9fa;
            padding: 20px 30px;
            border-bottom: 1px solid #e9ecef;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}
        
        .metadata-item {{
            padding: 10px;
            border-left: 4px solid #667eea;
        }}
        
        .metadata-item strong {{
            color: #667eea;
            display: block;
            margin-bottom: 5px;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .section {{
            margin-bottom: 50px;
        }}
        
        .section h2 {{
            color: #667eea;
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.2);
        }}
        
        .stat-card .value {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .stat-card .label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        
        .chart-container {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .chart-container > div {{
            width: 100%;
        }}
        
        .two-column {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }}
        
        @media (max-width: 1024px) {{
            .two-column {{
                grid-template-columns: 1fr;
            }}
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px 30px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e9ecef;
            font-size: 0.9em;
        }}
        
        .info-box {{
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }}
        
        .info-box strong {{
            color: #2196F3;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 ForenXtract (FX) Triage Dashboard</h1>
            <p>Live Forensic Triage Data Visualization</p>
        </div>
        
        <div class="metadata">
            <div class="metadata-item">
                <strong>Case Number</strong>
                <span>{self.case_no}</span>
            </div>
            <div class="metadata-item">
                <strong>Generated</strong>
                <span>{self.timestamp_utc}</span>
            </div>
            <div class="metadata-item">
                <strong>Dashboard Type</strong>
                <span>Interactive Triage Analysis</span>
            </div>
        </div>
        
        <div class="content">
            <div class="info-box">
                <strong>ℹ️ Dashboard Overview:</strong> This dashboard visualizes live forensic triage data collected before disk acquisition. 
                All data is read-only and tamper-evident.
            </div>
"""

        # ────────────────────────────────────────────────────────────────
        # PROCESS STATISTICS SECTION
        # ────────────────────────────────────────────────────────────────
        if process_data["stats"]["total_processes"] > 0:
            stats = process_data["stats"]
            html_content += f"""
            <div class="section">
                <h2>📊 Process Statistics</h2>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="value">{stats['total_processes']}</div>
                        <div class="label">Total Processes</div>
                    </div>
                    <div class="stat-card">
                        <div class="value">{len(stats['top_cpu_consumers'])}</div>
                        <div class="label">Top CPU Tracked</div>
                    </div>
                    <div class="stat-card">
                        <div class="value">{len(stats['process_count_by_user'])}</div>
                        <div class="label">Unique Users</div>
                    </div>
                    <div class="stat-card">
                        <div class="value">{len(stats['tty_distribution'])}</div>
                        <div class="label">TTY Types</div>
                    </div>
                </div>
"""
            
            if "top_cpu" in process_data["charts"]:
                html_content += f"""
                <div class="two-column">
                    <div class="chart-container">
                        {process_data["charts"]["top_cpu"]}
                    </div>
                    <div class="chart-container">
                        {process_data["charts"]["top_mem"] if "top_mem" in process_data["charts"] else "<p>No memory data</p>"}
                    </div>
                </div>
"""
            
            if "user_distribution" in process_data["charts"]:
                html_content += f"""
                <div class="two-column">
                    <div class="chart-container">
                        {process_data["charts"]["user_distribution"]}
                    </div>
                    <div class="chart-container">
                        {process_data["charts"]["tty_distribution"] if "tty_distribution" in process_data["charts"] else "<p>No TTY data</p>"}
                    </div>
                </div>
"""
            
            html_content += """
            </div>
"""

        # ────────────────────────────────────────────────────────────────
        # NETWORK STATISTICS SECTION
        # ────────────────────────────────────────────────────────────────
        if network_data["stats"]["total_connections"] > 0:
            stats = network_data["stats"]
            html_content += f"""
            <div class="section">
                <h2>🌐 Network Connections</h2>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="value">{stats['total_connections']}</div>
                        <div class="label">Total Connections</div>
                    </div>
                    <div class="stat-card">
                        <div class="value">{len(stats['connection_states'])}</div>
                        <div class="label">Connection States</div>
                    </div>
                </div>
"""
            
            if "connection_states" in network_data["charts"]:
                html_content += f"""
                <div class="two-column">
                    <div class="chart-container">
                        {network_data["charts"]["connection_states"]}
                    </div>
                    <div class="chart-container">
                        {network_data["charts"]["protocol_distribution"] if "protocol_distribution" in network_data["charts"] else "<p>No protocol data</p>"}
                    </div>
                </div>
"""
            
            html_content += """
            </div>
"""

        # ────────────────────────────────────────────────────────────────
        # MEMORY STATISTICS SECTION
        # ────────────────────────────────────────────────────────────────
        if memory_data["stats"]["total_memory"] > 0:
            stats = memory_data["stats"]
            total_gb = stats["total_memory"] / 1024 / 1024
            used_gb = stats["memory_used"] / 1024 / 1024
            html_content += f"""
            <div class="section">
                <h2>💾 Memory State</h2>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="value">{total_gb:.2f} GB</div>
                        <div class="label">Total Memory</div>
                    </div>
                    <div class="stat-card">
                        <div class="value">{used_gb:.2f} GB</div>
                        <div class="label">Memory Used</div>
                    </div>
                    <div class="stat-card">
                        <div class="value">{(used_gb / total_gb * 100):.1f}%</div>
                        <div class="label">Memory %</div>
                    </div>
                </div>
"""
            
            if "memory_usage" in memory_data["charts"]:
                html_content += f"""
                <div class="two-column">
                    <div class="chart-container">
                        {memory_data["charts"]["memory_usage"]}
                    </div>
                    <div class="chart-container">
                        {memory_data["charts"]["memory_breakdown"] if "memory_breakdown" in memory_data["charts"] else "<p>No breakdown data</p>"}
                    </div>
                </div>
"""
            
            html_content += """
            </div>
"""

        html_content += """
        </div>
        
        <div class="footer">
            <strong>ForenXtract (FX)</strong> — Digital Forensic Acquisition Framework<br>
            This dashboard was autogenerated. All triage data is tamper-evident and cryptographically verified.<br>
            <em>Case-first remote acquisition with explicit session state machine.</em>
        </div>
    </div>
</body>
</html>
"""

        # Write HTML file
        os.makedirs(self.output_dir, exist_ok=True)
        try:
            with open(self.dashboard_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[+] Dashboard generated: {self.dashboard_path}")
        except Exception as e:
            print(f"[!] Error writing dashboard: {e}")
            return None

        return self.dashboard_path
