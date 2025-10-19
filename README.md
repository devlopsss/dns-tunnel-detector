
# DNS Tunnel Detector — ML-based DNS Exfiltration/DGA Detection (Syslog-ready)

A lightweight tool that detects suspicious DNS behavior (exfiltration, DGA) from **queried domain names (qnames)**.

Two usage modes:
- **Offline** — CSV `label,qname` → feature extraction → supervised training (RandomForest) → predictions → optional Syslog alerts (batch)
- **Real time** — sniff UDP/53 (Scapy) → score each query → **RFC5424 Syslog** alerts (UDP/TCP) to a SIEM

By default, alerts are concise and easy to parse:  
`DNS alert || proba=0.913 || qname=example.com`  
A **full** mode adds investigative features (entropy, length, character ratios) into Structured-Data.

---

## Why this is useful

- **Privacy-friendly**: operates on domain names, not payloads
- **SIEM-ready**: emits RFC5424 Syslog (UDP or TCP)
- **Reproducible & educational**: end-to-end ML pipeline with commented code and docs
- **Minimal dependencies**: `scapy`, `scikit-learn`, `pandas`, `numpy`, `joblib`

---

## Repository structure

dns-tunnel-detector/
├─ scripts/
│ ├─ prepare_features.py # CSV -> features
│ ├─ train_supervised.py # features -> model/scaler
│ ├─ predict_supervised.py # test.csv -> predictions.csv
│ ├─ evaluate_supervised.py # evaluate if labels available
│ ├─ analyze_predictions.py # quick charts & report (optional)
│ ├─ alerts_to_syslog.py # predictions.csv -> Syslog (batch)
│ └─ realtime_syslog_detector.py # sniff UDP/53 -> Syslog (real time)
├─ models/ # ML artifacts (.pkl) — NOT versioned (keep .gitkeep)
├─ data/ # local datasets — NOT versioned (keep .gitkeep)
├─ docs/ # detailed guides (install, pipeline, syslog, troubleshooting)
├─ .gitignore
├─ LICENSE
├─ Makefile # optional quality-of-life shortcuts
└─ CHANGELOG.md



> **Do not** version `data/` and `models/` (only keep `.gitkeep`).

---

## Requirements

- Linux (Ubuntu/Debian/Kali), **Python 3.10+**
- Root privileges to sniff packets (or `CAP_NET_RAW`)
- In a VM (VirtualBox/VMware): **NAT** or **Bridged** interface with visible DNS traffic

---

## Installation

```

git clone https://github.com/devlopsss/dns-tunnel-detector.git
cd dns-tunnel-detector
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

```

Quick sanity check:


```
python - <<'PY'
import joblib, sklearn, pandas, numpy
print("OK deps")
PY
```


|If you use sudo, run scripts like:
|`sudo -E env PATH="$PATH" python scripts/...`
|to preserve the virtualenv Python.

Dataset & attribution

This project uses the “DNS Tunneling Queries for Binary Classification” dataset (Kaggle mirror by Saurabh Shahane, originally published on Mendeley Data):

Bubnov, Yakov (2019), DNS Tunneling Queries for Binary Classification, Mendeley Data, V1, doi: 10.17632/mzn9hvdcxg.1

Kaggle mirror: DNS Tunneling Queries Classification (Saurabh Shahane)

Labels

0 = regular domain

1 = tunneled domain (DNS tunneling)

Why this dataset?
It provides labeled domain names specifically for binary classification of DNS tunneling vs regular traffic—ideal for this supervised pipeline.




Offline pipeline (end-to-end)

1) Feature extraction
```
python scripts/prepare_features.py --in data/raw_dns.csv --out data/features.csv

```
2) Train

`python scripts/train_supervised.py --in data/features.csv --out-model models/rf_model.pkl --out-scaler models/scaler.pkl
`

3) Predict on a test set

`python scripts/predict_supervised.py --model models/rf_model.pkl --scaler models/scaler.pkl --in data/test.csv --out data/predictions_test.csv
`

4) (Optional) Evaluate if you have labels
`
python scripts/evaluate_supervised.py --raw data/test.csv --pred data/predictions_test.csv --out data/eval_test.txt
`
5) (Optional) Analyze (charts/report)
`
python scripts/analyze_predictions.py --pred data/predictions_test.csv --model models/rf_model.pkl --out data/analysis_report.txt
`
Syslog alerts (batch)

Simple UDP receiver for tests
`
nc -ul 514`


Send alerts from predictions (simple mode: proba then qname)
`
python scripts/alerts_to_syslog.py --pred data/predictions_test.csv --host 127.0.0.1 --port 514 --mode simple --separator " || " --min-prob-emit 0.80`


Full mode (features in Structured-Data)
`
python scripts/alerts_to_syslog.py --pred data/predictions_test.csv --host 127.0.0.1 --port 514 --mode full --high 0.90 --medium 0.70`


TCP variant
`
python scripts/alerts_to_syslog.py --pred data/predictions_test.csv --host 127.0.0.1 --port 514 --tcp --mode simple
`

Messages include two line breaks (\n\n) so each alert is visually separated in nc/rsyslog.

Real-time detection → Syslog

1) Identify interface & confirm DNS traffic
```
ip link show
sudo tcpdump -i eth0 udp port 53 -n -c 10
```

2) Launch the detector (simple mode)
`
sudo -E env PATH="$PATH" python scripts/realtime_syslog_detector.py --iface eth0 --model models/rf_model.pkl --scaler models/scaler.pkl --syslog-host 127.0.0.1 --syslog-port 514 --mode simple --separator " || " --min-prob-emit 0.80
`

3) View alerts (other terminal)

`nc -ul 514`

4) Generate test traffic
```
dig facebook.com
dig az9K3sLx82.example.com
```

Tunable settings

- `--min-prob-emit` — minimum probability to emit an alert (e.g., 0.80)
- 
- `--high, --medium` — severity thresholds (used in “full” mode)
- 
- `--mode simple|full` — compact vs. detailed alerts
- 
- `--separator " || "` — visual separator in MSG
- 
- `--tcp` — Syslog over TCP (default is UDP)
- 
- `--emit-all` (real time) — emit every request (debugging)

Legal & ethics

Only analyze networks you are authorized to monitor.

Anonymize data before sharing or publishing.

Respect your organization’s security policies.

License

MIT — see LICENSE.

Acknowledgements

Dataset: Bubnov, Yakov (2019), DNS Tunneling Queries for Binary Classification, Mendeley Data, V1, doi: 10.17632/mzn9hvdcxg.1 (Kaggle mirror by Saurabh Shahane).

Built as part of an engineering curriculum (network/cybersecurity modules). Contributions welcome (issues/PRs).
