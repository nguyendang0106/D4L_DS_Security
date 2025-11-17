from dash import Dash, html, dcc, dash_table
from dash.dependencies import Input, Output, State, ALL
import plotly.graph_objects as go
import pandas as pd
import threading
import time
import random

# ---------------------------
# Simple packet stream simulator
# ---------------------------
PACKET_LOG = []
PROTOCOLS = ["TCP", "UDP"]

app = Dash(__name__)
server = app.server

# Theme colors (Clean Professional)
DARK_BG = "#0f1720"
CARD_BG = "#111418"
CARD_BORDER = "#1f2933"
TEXT = "#E6EEF3"
MUTED = "#9AA6B2"
ACCENT = "#3aa6ff"
ALERT = "#ff6b6b"

LAST_RETRAIN_TIME = time.time()
LAST_RETRAIN_PACKET_COUNT = 0


def classify_packet(packet):
    """Trivial classifier placeholder. Returns (label, confidence)."""
    # Keep unknown most of the time to demonstrate UI
    r = random.random()
    if r < 0.05:
        return "ddos", round(random.uniform(0.7, 1.0), 2)
    elif r < 0.08:
        return "ransomware", round(random.uniform(0.7, 1.0), 2)
    return "unknown", round(random.uniform(0.1, 0.5), 2)


def run_retrain():
    print("[retrain] triggered at", pd.Timestamp.now())


# Background thread to simulate packets
def simulate_packet_arrival():
    while True:
        ts = pd.Timestamp.now()
        packet = {
            "timestamp": ts,
            "src": f"192.168.1.{random.randint(1, 254)}",
            "dst": f"10.0.0.{random.randint(1, 254)}",
            "protocol": random.choice(PROTOCOLS),
            "category": "unknown",
            "confidence": round(random.uniform(0.05, 0.99), 2),
        }
        cat, conf = classify_packet(packet)
        packet["category"] = cat
        packet["confidence"] = conf
        PACKET_LOG.append(packet)

        # Keep only last 1000 packets to prevent memory issues
        if len(PACKET_LOG) > 1000:
            PACKET_LOG.pop(0)

        time.sleep(random.uniform(5, 10))


threading.Thread(target=simulate_packet_arrival, daemon=True).start()


# ---------------------------
# Layout
# ---------------------------
app.layout = html.Div(
    style={
        "backgroundColor": DARK_BG,
        "height": "100vh",
        "padding": "28px",
        "overflow": "hidden",
        "display": "flex",
        "flexDirection": "column",
    },
    children=[
        dcc.Store(
            id="store-retrain",
            data={"mode": "manual", "periodic_type": None, "periodic_value": None},
        ),
        html.Div(
            style={
                "display": "flex",
                "alignItems": "center",
                "justifyContent": "space-between",
                "gap": "12px",
                "marginBottom": "20px",
            },
            children=[
                html.H1(
                    "AISec — Live Monitor",
                    style={"color": TEXT, "margin": 0},
                ),
                html.Div(
                    style={"display": "flex", "gap": "8px", "alignItems": "center"},
                    children=[
                        html.Button(
                            "Settings",
                            id="settings-btn",
                            n_clicks=0,
                            style={
                                "backgroundColor": ACCENT,
                                "border": "none",
                                "color": "#fff",
                                "padding": "8px 12px",
                                "borderRadius": "8px",
                            },
                        ),
                        html.Button(
                            "Force Retrain",
                            id="run-retrain-btn",
                            n_clicks=0,
                            style={
                                "backgroundColor": CARD_BORDER,
                                "border": "none",
                                "color": TEXT,
                                "padding": "8px 12px",
                                "borderRadius": "8px",
                            },
                        ),
                    ],
                ),
            ],
        ),
        # Cards
        html.Div(
            style={
                "display": "flex",
                "gap": "16px",
                "flexWrap": "wrap",
                "marginBottom": "16px",
            },
            children=[
                html.Div(
                    style={
                        "backgroundColor": CARD_BG,
                        "padding": "18px",
                        "flex": "1 1 220px",
                        "borderRadius": "10px",
                        "border": f"1px solid {CARD_BORDER}",
                    },
                    children=[
                        html.Div("Total Packets", style={"color": MUTED}),
                        html.H2(
                            id="total-packets",
                            style={"color": ACCENT, "margin": "6px 0 0 0"},
                        ),
                    ],
                ),
                html.Div(
                    style={
                        "backgroundColor": CARD_BG,
                        "padding": "18px",
                        "flex": "1 1 220px",
                        "borderRadius": "10px",
                        "border": f"1px solid {CARD_BORDER}",
                    },
                    children=[
                        html.Div("Classified (malicious)", style={"color": MUTED}),
                        html.H2(
                            id="malicious-packets",
                            style={"color": ALERT, "margin": "6px 0 0 0"},
                        ),
                    ],
                ),
                html.Div(
                    style={
                        "backgroundColor": CARD_BG,
                        "padding": "18px",
                        "flex": "1 1 220px",
                        "borderRadius": "10px",
                        "border": f"1px solid {CARD_BORDER}",
                    },
                    children=[
                        html.Div("Unknown", style={"color": MUTED}),
                        html.H2(
                            id="unknown-count",
                            style={"color": TEXT, "margin": "6px 0 0 0"},
                        ),
                    ],
                ),
                html.Div(
                    style={
                        "backgroundColor": CARD_BG,
                        "padding": "18px",
                        "flex": "1 1 220px",
                        "borderRadius": "10px",
                        "border": f"1px solid {CARD_BORDER}",
                    },
                    children=[
                        html.Div("Last Packet", style={"color": MUTED}),
                        html.Div(
                            id="last-time", style={"color": TEXT, "marginTop": "6px"}
                        ),
                    ],
                ),
            ],
        ),
        # Main area: graph + table
        html.Div(
            style={
                "display": "grid",
                "gridTemplateColumns": "1fr 420px",
                "gap": "16px",
                "flex": "1",
                "minHeight": "0",
                "overflow": "hidden",
            },
            children=[
                html.Div(
                    style={
                        "backgroundColor": CARD_BG,
                        "padding": "18px",
                        "borderRadius": "10px",
                        "border": f"1px solid {CARD_BORDER}",
                        "display": "flex",
                        "flexDirection": "column",
                        "overflow": "hidden",
                    },
                    children=[
                        html.Div(
                            "Packet Category Timeline",
                            style={"color": MUTED, "marginBottom": "12px"},
                        ),
                        dcc.Graph(
                            id="timeline-graph",
                            config={"displayModeBar": False},
                            style={"flex": "1", "minHeight": "0"},
                        ),
                    ],
                ),
                html.Div(
                    style={
                        "backgroundColor": CARD_BG,
                        "padding": "18px",
                        "borderRadius": "10px",
                        "border": f"1px solid {CARD_BORDER}",
                        "display": "flex",
                        "flexDirection": "column",
                        "overflow": "hidden",
                    },
                    children=[
                        html.Div(
                            "Unknown Packets",
                            style={"color": MUTED, "marginBottom": "12px"},
                        ),
                        html.Div(
                            style={"flex": "1", "minHeight": "0", "overflow": "auto"},
                            children=[
                                dash_table.DataTable(
                                    id="unknown-table",
                                    columns=[
                                        {
                                            "name": "Time",
                                            "id": "timestamp",
                                            "type": "text",
                                        },
                                        {"name": "Src", "id": "src", "type": "text"},
                                        {"name": "Dst", "id": "dst", "type": "text"},
                                        {
                                            "name": "Proto",
                                            "id": "protocol",
                                            "type": "text",
                                        },
                                        {
                                            "name": "Confidence",
                                            "id": "confidence",
                                            "type": "numeric",
                                            "format": {"specifier": ".2f"},
                                        },
                                        {
                                            "name": "Category",
                                            "id": "category",
                                            "presentation": "dropdown",
                                        },
                                    ],
                                    data=[],
                                    editable=True,
                                    row_deletable=False,
                                    style_cell={
                                        "backgroundColor": CARD_BG,
                                        "color": TEXT,
                                        "border": "none",
                                        "padding": "6px",
                                    },
                                    dropdown={
                                        "category": {
                                            "options": [
                                                {
                                                    "label": "unknown",
                                                    "value": "unknown",
                                                },
                                                {"label": "ddos", "value": "ddos"},
                                                {"label": "dotnet", "value": "dotnet"},
                                                {
                                                    "label": "ransomware",
                                                    "value": "ransomware",
                                                },
                                            ]
                                        }
                                    },
                                ),
                            ],
                        ),
                        html.Div(
                            style={
                                "display": "flex",
                                "gap": "8px",
                                "justifyContent": "flex-end",
                                "marginTop": "12px",
                            },
                            children=[
                                html.Button(
                                    "Refresh",
                                    id="refresh-unknown",
                                    n_clicks=0,
                                    style={
                                        "backgroundColor": CARD_BORDER,
                                        "color": TEXT,
                                        "border": "none",
                                        "padding": "8px 10px",
                                        "borderRadius": "8px",
                                    },
                                ),
                                html.Button(
                                    "Apply Labels",
                                    id="apply-labels",
                                    n_clicks=0,
                                    style={
                                        "backgroundColor": ACCENT,
                                        "color": "#fff",
                                        "border": "none",
                                        "padding": "8px 10px",
                                        "borderRadius": "8px",
                                    },
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        ),
        # Hidden interval + debug
        dcc.Interval(id="interval", interval=1000, n_intervals=0),
        # Hidden dummy output
        html.Div(id="dummy-output", style={"display": "none"}),
    ],
)


# ---------------------------
# Callbacks
# ---------------------------
@app.callback(
    Output("timeline-graph", "figure"),
    Output("total-packets", "children"),
    Output("malicious-packets", "children"),
    Output("unknown-count", "children"),
    Output("last-time", "children"),
    Input("interval", "n_intervals"),
    State("store-retrain", "data"),
)
def update_dashboard(n, retrain_cfg):
    df = pd.DataFrame(PACKET_LOG)

    if df.empty:
        fig = go.Figure().update_layout(template="plotly_dark")
        return fig, "0", "0", "0", "—"

    # ensure correct types
    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp_dt"] = pd.to_datetime(df["timestamp"]).dt.tz_localize(None)
        df["timestamp_str"] = df["timestamp_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")
    else:
        df["timestamp_dt"] = pd.NaT
        df["timestamp_str"] = ""

    # retrain logic (respect store)
    global LAST_RETRAIN_TIME, LAST_RETRAIN_PACKET_COUNT
    num_packets = len(df)
    now = time.time()

    mode = retrain_cfg.get("mode")
    ptype = retrain_cfg.get("periodic_type")
    pvalue = retrain_cfg.get("periodic_value")

    if mode == "periodic" and ptype and pvalue:
        try:
            pvalue_f = float(pvalue)
            if ptype == "time" and now - LAST_RETRAIN_TIME >= pvalue_f * 60:
                run_retrain()
                LAST_RETRAIN_TIME = now
            elif ptype == "count" and num_packets - LAST_RETRAIN_PACKET_COUNT >= int(
                pvalue_f
            ):
                run_retrain()
                LAST_RETRAIN_PACKET_COUNT = num_packets
        except Exception:
            pass

    # Build timeline
    fig = go.Figure()
    colors = {
        "unknown": "#9aa6b2",
        "ddos": "#ff6b6b",
        "dotnet": "#3aa6ff",
        "ransomware": "#ffa62b",
    }

    for cat in df["category"].unique():
        sub = df[df["category"] == cat]
        fig.add_trace(
            go.Scatter(
                x=sub["timestamp_dt"],
                y=sub["confidence"],
                mode="markers",
                name=cat,
                hovertemplate="%{x|%Y-%m-%d %H:%M:%S}<br>conf: %{y}",
                marker=dict(size=9, color=colors.get(cat, "#888")),
            )
        )

    fig.update_layout(
        template="plotly_dark",
        plot_bgcolor=CARD_BG,
        paper_bgcolor=CARD_BG,
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        margin=dict(l=40, r=20, t=20, b=40),
    )

    total = len(df)
    malicious = len(df[df["category"] != "unknown"]) if "category" in df.columns else 0
    unknown = len(df[df["category"] == "unknown"]) if "category" in df.columns else 0
    last = df.iloc[-1]["timestamp_str"] if not df.empty else "—"

    return fig, str(total), str(malicious), str(unknown), last


@app.callback(Output("unknown-table", "data"), Input("interval", "n_intervals"))
def update_unknown_table(_):
    df = pd.DataFrame(PACKET_LOG)
    if df.empty:
        return []

    # Filter for UNKNOWN packets only
    df_unknown = df[df["category"] == "unknown"].copy()

    if df_unknown.empty:
        return []

    # Prepare display-friendly structure
    if "timestamp" in df_unknown.columns:
        df_unknown["timestamp"] = (
            pd.to_datetime(df_unknown["timestamp"])
            .dt.tz_localize(None)
            .dt.strftime("%Y-%m-%d %H:%M:%S")
        )

    # Keep last 200 unknown packets to avoid massive payloads
    df_unknown = df_unknown.tail(200)
    return df_unknown.to_dict(orient="records")


@app.callback(
    Output("dummy-output", "children", allow_duplicate=True),
    Input("apply-labels", "n_clicks"),
    State("unknown-table", "data"),
    prevent_initial_call=True,
)
def apply_labels(n_clicks, table_data):
    if not table_data:
        return ""

    # Build a quick lookup from timestamp+src+dst to index in PACKET_LOG
    lookup = {}
    for idx, pkt in enumerate(PACKET_LOG):
        ts_str = (
            pd.Timestamp(pkt["timestamp"])
            .tz_localize(None)
            .strftime("%Y-%m-%d %H:%M:%S")
        )
        key = (
            ts_str,
            pkt["src"],
            pkt["dst"],
            pkt.get("protocol"),
        )
        lookup[key] = idx

    for row in table_data:
        key = (
            row.get("timestamp"),
            row.get("src"),
            row.get("dst"),
            row.get("protocol"),
        )
        if key in lookup:
            idx = lookup[key]
            PACKET_LOG[idx]["category"] = row.get(
                "category", PACKET_LOG[idx].get("category")
            )
            try:
                PACKET_LOG[idx]["confidence"] = float(
                    row.get("confidence", PACKET_LOG[idx].get("confidence", 1.0))
                )
            except Exception:
                pass

    return ""


if __name__ == "__main__":
    print("Running improved dashboard on http://127.0.0.1:8050/")
    app.run(debug=False, port=8050)
