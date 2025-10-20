
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