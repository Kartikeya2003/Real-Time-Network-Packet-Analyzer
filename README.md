# Real-Time-Network-Packet-Analyzer
Real-time network packet analyzer built using Python, Scapy and Streamlit.
# 📡 Real-Time Network Packet Analyzer

A Python-based Network Packet Analyzer built using **Scapy**, **Streamlit**, and **Kali Linux** to capture, analyze, and visualize live network traffic through an interactive dashboard.

This project was developed as part of my cybersecurity learning journey while pursuing a **Master of Cyber Security at RMIT University**.

---

## 🚀 Features

* Real-time packet capture
* IPv4, IPv6, ARP, TCP, UDP, and ICMP traffic monitoring
* Service detection:

  * HTTP
  * HTTPS
  * DNS
  * SSH
  * DHCP
* Protocol distribution visualization
* Top Source IP analysis
* Top Destination IP analysis
* Searchable packet logs
* JSON packet storage
* Downloadable packet log export
* Interactive Streamlit dashboard

---

## 🛠️ Technologies Used

* Python 3
* Scapy
* Streamlit
* Pandas
* JSON
* Kali Linux

---

## 📂 Project Structure

```text
.
├── sniffer.py
├── app.py
├── packets.json
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Project

### Terminal 1 – Start Packet Capture

```bash
sudo python3 sniffer.py
```

### Terminal 2 – Launch Dashboard

```bash
streamlit run app.py
```

Open:

```text
http://localhost:8501
```

---

## 📊 Dashboard Overview

The dashboard provides:

* Live packet statistics
* Protocol distribution
* Recent packet activity
* Source/Destination IP analytics
* Service usage analytics

---

## 🔍 Learning Outcomes

Through this project I gained hands-on experience with:

* Network packet inspection
* Protocol analysis
* Linux networking
* Python-based security tooling
* Real-time data visualization
* Streamlit dashboard development
* Troubleshooting packet capture permissions and networking issues

---

## 📈 Future Improvements

* GeoIP lookup
* Port scan detection
* ARP spoofing detection
* SYN flood detection
* Packet filtering
* SQLite database integration
* Cloud deployment

---

## 👨‍💻 Author

Kartikeya Mane

Master of Cyber Security
RMIT University, Melbourne

LinkedIn: [Add Your LinkedIn URL]
