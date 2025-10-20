# Où trouver les données & comment entraîner / scorer (IsolationForest)

## Où sont les données ?
Après les étapes `scan` et `aggregate`, tes fichiers se trouvent dans le dossier `data/` :
- `data/normal.agg.csv`        : fenêtres agrégées (trafic normal)
- `data/suspicious.agg.csv`    : fenêtres agrégées (trafic suspect)
- (optionnel) `*.flagged.csv`  : version annotée par les règles heuristiques

> Tu peux générer d'autres fichiers agrégés en répétant :
> ```bash
> python -m dnsdetector.cli scan --pcap <ton_fichier.pcap> --out data/events_xxx.jsonl
> python -m dnsdetector.cli aggregate --events data/events_xxx.jsonl --win 300 --out-csv data/xxx.agg.csv
> ```

## Entraîner le modèle (sur du **normal**)
Utilise **uniquement** des CSV d'agrégation représentant un trafic normal (sans attaque) :
```bash
python scripts/train.py --out-model models/model.pkl --out-scaler models/scaler.pkl data/normal.agg.csv
```
Tu peux fournir plusieurs fichiers normaux :
```bash
python scripts/train.py --out-model models/model.pkl --out-scaler models/scaler.pkl data/normal1.agg.csv data/normal2.agg.csv
```

### Paramètres importants (train.py)
- `--features`      : colonnes utilisées (défaut : mean_entropy, mean_length, qps, nxd_ratio, txt_ratio, max_label)
- `--contamination` : fraction d'anomalies attendues pendant l'entraînement
                      (0.01–0.05 recommandé si tu n'entraînes que sur du normal)
- `--estimators`    : nombre d'arbres (plus grand = plus stable)
- `--out-model` / `--out-scaler` : chemins de sortie

## Scorer un fichier (détection)
```bash
python scripts/score.py --model models/model.pkl --scaler models/scaler.pkl --out data/suspicious.scored.csv data/suspicious.agg.csv
```

Le script ajoute :
- `anomaly` (booléen) : True si le modèle juge la fenêtre anormale
- `if_score` (0→1) : score "gravité" (plus grand = plus anormal)

## Interprétation rapide
- Commence par trier sur `anomaly == True` puis `if_score` décroissant.
- Fenêtres avec `mean_entropy` élevée, `mean_length` élevée, `max_label` proche 63 → très suspectes.
- Ajuste `--contamination` si tu as trop / pas assez d'anomalies (biais d'entraînement).

## Bonnes pratiques
- Toujours scaler les features de la même façon entre train et score (d'où `scaler.pkl`).
- Versionner `models/model.pkl` et `models/scaler.pkl`.
- Documenter `features` utilisées et la version du code (README).
