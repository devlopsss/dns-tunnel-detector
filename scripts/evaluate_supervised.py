#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# evaluate_supervised.py — Compare les prédictions au label réel issu du CSV brut (format "0,facebook.com.")
# usage:
#   python scripts/evaluate_supervised.py --raw data/raw_dns.csv --pred data/predictions.csv --out data/eval_report.txt

import argparse                       # importe argparse pour parser la ligne de commande
import pandas as pd                   # pandas pour lire/manipuler les CSV
import numpy as np                    # numpy pour quelques opérations numériques
import os                             # os pour vérifier l'existence de fichiers
from sklearn.metrics import (         # métriques de classification (sklearn)
    classification_report,            # rapport précision/rappel/F1
    confusion_matrix,                 # matrice de confusion
    roc_auc_score                     # AUC ROC (si proba dispo)
)

def parse_raw_onecol(path: str) -> pd.DataFrame:
    """Lit un CSV 'une seule colonne' au format 'label,qname' et renvoie DataFrame label(int)/qname(str)."""
    df_raw = pd.read_csv(path, header=None, dtype=str, na_filter=False)            # lit le fichier sans header
    # si 1 seule colonne "0,facebook.com." -> on split sur la première virgule
    parts = df_raw.iloc[:,0].astype(str).str.split(',', n=1, expand=True)          # découpe "label,qname"
    if parts.shape[1] == 1:                                                        # s'il n'y a pas de virgule
        # alors on suppose que la colonne est déjà "qname" (pas de label) -> on met label NaN
        parts = pd.concat([pd.Series([np.nan]*len(parts)), parts.iloc[:,0]], axis=1)  # construit 2 colonnes
    parts.columns = ['label_raw','qname']                                           # nomme les colonnes
    # normalise label en 0/1 (0=normal, 1=malicious)
    def norm_label(x: str):
        s = str(x).strip().lower()                                                 # normalise la casse
        if s in ('0','normal','benign','false','no','n'): return 0                 # cas "normal"
        if s in ('1','malicious','malware','true','yes','y'): return 1             # cas "malicious"
        try: return 1 if int(float(s)) != 0 else 0                                  # tente conversion numérique
        except: return np.nan                                                       # sinon NaN
    parts['label'] = parts['label_raw'].apply(norm_label)                           # applique la normalisation
    parts['qname'] = parts['qname'].astype(str).str.strip().str.rstrip('.')         # nettoie le qname (retire le '.' final)
    return parts[['label','qname']]                                                 # renvoie seulement label/qname

def main():
    parser = argparse.ArgumentParser(description="Évalue predictions.csv contre raw_dns.csv (labels réels)")
    parser.add_argument('--raw', required=True, help='Chemin CSV brut (ex: data/raw_dns.csv)')          # chemin brut
    parser.add_argument('--pred', required=True, help='Chemin CSV prédictions (ex: data/predictions.csv)') # chemin prédictions
    parser.add_argument('--out', default='data/eval_report.txt', help='Chemin du rapport texte')        # sortie rapport
    args = parser.parse_args()                                                                          # parse les args

    if not os.path.exists(args.raw):                                                                     # vérifier fichier raw
        raise FileNotFoundError(args.raw)
    if not os.path.exists(args.pred):                                                                    # vérifier fichier préd
        raise FileNotFoundError(args.pred)

    raw = parse_raw_onecol(args.raw)                                                                     # lit & normalise raw (label/qname)
    pred = pd.read_csv(args.pred)                                                                        # lit predictions.csv
    # homogénéise la colonne qname (retire '.' final si présent)
    pred['qname'] = pred['qname'].astype(str).str.strip().str.rstrip('.')                                # nettoie le qname côté prédictions

    # jointure sur qname pour aligner les échantillons
    df = pd.merge(pred, raw, on='qname', how='inner')                                                     # inner join (qnames communs)
    # filtre lignes avec label non manquant
    df = df[~df['label'].isna()].copy()                                                                   # garde seulement labels valides

    # récupère y_true (label réel) et y_pred (prédiction binaire)
    y_true = df['label'].astype(int).values                                                               # labels vrais en int
    y_pred = df['predicted_label'].astype(int).values                                                     # prédictions 0/1
    # récupère proba si disponible
    proba = df['proba_malicious'].values if 'proba_malicious' in df.columns else None                    # probas (si dispo)

    # calcule rapport de classification
    report = classification_report(y_true, y_pred, digits=4)                                              # précision/rappel/F1
    # calcule matrice de confusion
    cm = confusion_matrix(y_true, y_pred)                                                                 # matrice confusion
    # calcule AUC si proba dispo et au moins 2 classes
    auc = None                                                                                            # valeur par défaut
    if proba is not None and len(np.unique(y_true)) == 2:                                                 # AUC seulement si binaire
        try:
            auc = roc_auc_score(y_true, proba)                                                            # calcule AUC
        except Exception:
            auc = None                                                                                    # tolère erreurs

    # construit un petit texte de résultat
    lines = []                                                                                            # liste lignes rapport
    lines.append(f"Nb échantillons évalués: {len(df)}")                                                   # nb total
    lines.append("")                                                                                      # ligne vide
    lines.append("=== Classification report ===")                                                         # titre
    lines.append(report)                                                                                  # rapport sklearn
    lines.append("")                                                                                      # ligne vide
    lines.append("=== Confusion matrix === [ [TN FP] ; [FN TP] ]")                                        # titre matrice
    lines.append(str(cm))                                                                                 # affiche matrice
    if auc is not None:                                                                                   # si AUC dispo
        lines.append("")                                                                                  # ligne vide
        lines.append(f"AUC ROC: {auc:.4f}")                                                               # affiche AUC

    # identifie les "top faux positifs" (préd=1 mais label=0) et "top faux négatifs" (préd=0 mais label=1)
    df['err_type'] = np.where((df['predicted_label']==1) & (df['label']==0), 'FP',
                       np.where((df['predicted_label']==0) & (df['label']==1), 'FN', 'OK'))              # tag erreurs
    top_fp = df[df['err_type']=='FP'].sort_values('proba_malicious', ascending=False).head(20)            # top 20 FP
    top_fn = df[df['err_type']=='FN'].sort_values('proba_malicious', ascending=True).head(20)             # top 20 FN

    lines.append("")                                                                                      # ligne vide
    lines.append("=== Top 20 Faux Positifs (prob. décroissante) ===")                                     # titre FP
    for _, r in top_fp.iterrows():                                                                        # itère FP
        lines.append(f"{r['qname']}  proba={r.get('proba_malicious',np.nan):.3f}")

    lines.append("")                                                                                      # ligne vide
    lines.append("=== Top 20 Faux Négatifs (prob. croissante) ===")                                       # titre FN
    for _, r in top_fn.iterrows():                                                                        # itère FN
        lines.append(f"{r['qname']}  proba={r.get('proba_malicious',np.nan):.3f}")

    # écrit le rapport texte
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)                                          # crée dossier si besoin
    with open(args.out, 'w', encoding='utf-8') as f:                                                      # ouvre fichier sortie
        f.write("\n".join(lines))                                                                         # écrit tout le rapport

    print(f"[OK] Rapport d'évaluation écrit dans: {args.out}")                                            # message succès
    print(f"[INFO] Lignes évaluées (post-join): {len(df)}")                                               # info nb lignes

if __name__ == "__main__":                                                                               # point d'entrée
    main()                                                                                                # lance main
