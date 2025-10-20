# DNS Tunnel Detector — détection d’exfiltration DNS (Supervisé + Syslog)

Projet pédagogique et opérationnel pour détecter de l’exfiltration DNS / DGA :
- **Offline** : CSV `label,qname` → features → modèle supervisé (RandomForest) → prédictions → (option) alertes Syslog (batch).
- **Temps réel** : sniff UDP/53, calcule la proba malicieuse et **envoie des alertes Syslog RFC5424** vers un SIEM.

## 🚀 Quickstart

bash
git clone https://github.com/<ton-user>/dns-tunnel-detector.git
cd dns-tunnel-detector
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt


Tester un récepteur Syslog (simple) :

nc -ul 514


Temps réel (simple, proba puis qname) :

sudo -E env PATH="$PATH" python scripts/realtime_syslog_detector.py \
--iface eth0 \
--model models/rf_model.pkl --scaler models/scaler.pkl \
--syslog-host 127.0.0.1 --syslog-port 514 \
--mode simple --separator " || " --min-prob-emit 0.80


Batch → Syslog depuis un CSV de prédictions :

python scripts/alerts_to_syslog.py \
--pred data/predictions_test.csv \
--host 127.0.0.1 --port 514 \
--mode simple --separator " || " --min-prob-emit 0.80


Structure

scripts/ : pipeline ML + alerting Syslog (batch & temps réel)
models/ : modèles .pkl (non versionnés, gardez un .gitkeep)
docs/ : guides détaillés (install, pipeline, syslog, troubleshooting)


Dépendances

Python 3.10+
pandas, numpy, scikit-learn, joblib, scapy, matplotlib (analyse), requests (optionnel)


Documentation

00_overview
 — présentation & objectifs

01_installation
 — installation et erreurs courantes

02_pipeline_offline
 — entraînement & prédiction

03_syslog_batch
 — envoi d’alertes à partir d’un CSV

04_syslog_realtime
 — sniff live + alertes

05_troubleshooting
 — dépannage (venv/sudo/syslog)


Avertissement

N’analysez que des trafics pour lesquels vous avez autorisation. Anonymisez avant publication.
