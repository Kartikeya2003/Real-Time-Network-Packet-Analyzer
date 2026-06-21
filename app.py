import json
import streamlit as st
import pandas as pd
from collections import Counter

# ---------------- PAGE ----------------

st.set_page_config(
    page_title="Packet Analyzer",
    layout="wide"
)

# ---------------- CSS ----------------

st.markdown("""
<style>

/* Background */
.stApp {
    background: linear-gradient(
        135deg,
        #020617 0%,
        #0f172a 50%,
        #111827 100%
    );
}

/* Title */
h1 {
    color: white !important;
    font-size: 3rem !important;
    font-weight: 800 !important;
}

/* Headers */
h2,h3 {
    color: white !important;
}

/* Metric cards */
[data-testid="metric-container"] {
    background: rgba(15,23,42,0.9);
    border: 1px solid rgba(56,189,248,0.25);
    border-radius: 16px;
    padding: 15px;
    box-shadow: 0 0 15px rgba(56,189,248,0.15);
}

/* Search box */
.stTextInput input {
    background-color: #0f172a;
    color: white;
    border-radius: 10px;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    border-radius: 12px;
    overflow: hidden;
}

/* Download button */
.stDownloadButton button {
    background: linear-gradient(
        90deg,
        #0284c7,
        #38bdf8
    );
    color: white;
    border: none;
    border-radius: 10px;
    font-weight: bold;
}

footer {
    visibility: hidden;
}

</style>
""", unsafe_allow_html=True)

# ---------------- LOAD DATA ----------------

try:
    with open("packets.json", "r") as f:
        packets = json.load(f)

except Exception as e:
    st.error(e)
    packets = []

# ---------------- TITLE ----------------

st.title("📡 Network Packet Analyzer")

# ---------------- METRICS ----------------

protocols = Counter(p["protocol"] for p in packets)

icmp_count = protocols.get("ICMP", 0)
total_packets = len(packets)

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("TCP", protocols.get("TCP", 0))
c2.metric("UDP", protocols.get("UDP", 0))
c3.metric("ARP", protocols.get("ARP", 0))
c4.metric("Total Packets", total_packets)
c5.metric("ICMP", icmp_count)

st.divider()

# ---------------- SEARCH ----------------

st.subheader("Recent Packets")

search = st.text_input("Search")

filtered = [
    p for p in packets
    if search.lower() in str(p).lower()
]

df = pd.DataFrame(filtered)

if not df.empty:

    if "sport" in df.columns:
        df["sport"] = df["sport"].astype(str)

    if "dport" in df.columns:
        df["dport"] = df["dport"].astype(str)

st.dataframe(
    df,
    width="stretch"
)

st.divider()

# ---------------- PROTOCOL DISTRIBUTION ----------------

st.subheader("Protocol Distribution")

st.bar_chart(dict(protocols))

st.download_button(
    label="Download Packet Log",
    data=json.dumps(packets, indent=4),
    file_name="packets.json",
    mime="application/json"
)

st.divider()

# ---------------- PROTOCOL BREAKDOWN ----------------

st.subheader("Protocol Breakdown")

if len(protocols) > 0:

    max_count = max(protocols.values())

    for proto, count in protocols.items():

        st.progress(
            count / max_count,
            text=f"{proto} : {count}"
        )

st.divider()

# ---------------- TOP IPS ----------------

sources = Counter(
    p["source"]
    for p in packets
)

destinations = Counter(
    p["destination"]
    for p in packets
)

left, right = st.columns(2)

with left:

    st.subheader("Top Source IPs")

    st.bar_chart(
        dict(
            sources.most_common(10)
        )
    )

with right:

    st.subheader("Top Destination IPs")

    st.bar_chart(
        dict(
            destinations.most_common(10)
        )
    )

st.divider()

# ---------------- TOP SERVICES ----------------

services = Counter(
    p["service"]
    for p in packets
)

st.subheader("Top Services")

st.bar_chart(
    dict(
        services.most_common(10)
    )
)
