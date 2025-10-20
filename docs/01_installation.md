# 01 — Installation

## Prérequis
- Linux (Ubuntu/Debian/Kali), Python 3.10+, droits root pour sniffer (ou CAP_NET_RAW).
- VM : interface réseau correcte (`eth0`, `ens33`, `wlan0`...), NAT/Bridge conseillés.

## Étapes
```bash
git clone https://github.com/<ton-user>/dns-tunnel-detector.git
cd dns-tunnel-detector
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
