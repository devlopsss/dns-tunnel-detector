#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# predict_supervised.py — Applique un modèle entraîné sur un CSV simple "label,qname" ou un CSV qname seul.
# usage: python scripts/predict_supervised.py --model models/rf_model.pkl --scaler models/scaler.pkl --in data/input.csv --out data/predictions.csv

import argparse                                     # parser arguments
import pandas as pd                                 # pandas
import joblib                                       # charger modèle et scaler
import os                                           # os utils
import sys                                          # utils système
import math                                         # math utilisé par les features
from collections import Counter                     # pour entropie

def shannon_entropy(s: str) -> float:               # recoder entropie (copie simple)
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in c.values())

def extract_features(qname: str) -> dict:           # extrait les mêmes features que prepare_features.py
    q = '' if qname is None else str(qname).strip()
    q = q.rstrip('.')
    labels = [lab for lab in q.split('.') if lab != '']
    length = len(q)
    max_label = max((len(l) for l in labels), default=0)
    num_labels = len(labels)
    entropy = shannon_entropy(q.replace('.', ''))
    alpha_ratio = sum(ch.isalpha() for ch in q) / max(1, length)
    digit_ratio = sum(ch.isdigit() for ch in q) / max(1, length)
    special_ratio = sum((not ch.isalnum() and ch != '.') for ch in q) / max(1, length)
    avg_label_len = (sum(len(l) for l in labels) / num_labels) if num_labels > 0 else 0.0
    vowel_ratio = sum(ch.lower() in 'aeiouy' for ch in q) / max(1, length)
    return {
        'qname': q,
        'entropy': float(entropy),
        'length': float(length),
        'max_label': float(max_label),
        'num_labels': int(num_labels),
        'avg_label_len': float(avg_label_len),
        'alpha_ratio': float(alpha_ratio),
        'digit_ratio': float(digit_ratio),
        'special_ratio': float(special_ratio),
        'vowel_ratio': float(vowel_ratio)
    }

def main(argv=None):                                # point d'entrée
    ap = argparse.ArgumentParser(description="Score un CSV de qnames avec un modèle entraîné")
    ap.add_argument('--model', required=True, help='Chemin vers le modèle .pkl (joblib)')  # modèle requis
    ap.add_argument('--scaler', required=True, help='Chemin vers le scaler .pkl (joblib)')  # scaler requis
    ap.add_argument('--in', dest='in_path', required=True, help='CSV d\'entrée (peut être label,qname ou qname seul)')  # input
    ap.add_argument('--out', dest='out_path', default='data/predictions.csv', help='CSV de sortie avec prédictions')  # output
    ap.add_argument('--prob-threshold', dest='prob_thresh', type=float, default=0.5, help='Seuil de probabilité pour classer comme malicieux')  # seuil
    args = ap.parse_args(argv)                       # parse args

    model_path = args.model                           # chemin modèle
    scaler_path = args.scaler                         # chemin scaler
    in_path = args.in_path                            # chemin input
    out_path = args.out_path                          # chemin output

    # vérifier fichiers
    if not os.path.exists(model_path):                # model absent ?
        raise FileNotFoundError(f"Model not found: {model_path}")
    if not os.path.exists(scaler_path):               # scaler absent ?
        raise FileNotFoundError(f"Scaler not found: {scaler_path}")
    if not os.path.exists(in_path):                   # input absent ?
        raise FileNotFoundError(f"Input file not found: {in_path}")

    # charger modèles
    clf = joblib.load(model_path)                     # charger classifieur
    scaler = joblib.load(scaler_path)                 # charger scaler

    # lire input : peut être un CSV avec deux colonnes (label,qname) ou une colonne par ligne contenant "0,facebook.com."
    # on tente une lecture robuste : si le CSV a au moins 2 colonnes, on cherche une colonne qui ressemble à qname
    df_raw = pd.read_csv(in_path, header=None, dtype=str, na_filter=False)  # lecture initiale
    # heuristique : si première ligne commence par 'label' on relit avec header
    first_label = str(df_raw.iloc[0,0]).lower() if df_raw.shape[0] > 0 else ''
    if first_label in ('label','qname'):              # si header détecté
        df_raw = pd.read_csv(in_path, dtype=str)      # relire avec header
    # si plusieurs colonnes, choisir la 2ème comme qname (ou construire qname à partir des colonnes si nécessaire)
    if df_raw.shape[1] >= 2:
        # supposer colonne 0 = label, colonne 1 = qname
        df_input = pd.DataFrame({'qname': df_raw.iloc[:,1].astype(str).str.strip()})  # construire df_input
    else:
        # si une seule colonne, tenter de splitter sur la première virgule (format "0,facebook.com.")
        single = df_raw.iloc[:,0].astype(str)
        parts = single.str.split(',', n=1, expand=True)  # séparer en deux parties max
        if parts.shape[1] == 2:
            df_input = pd.DataFrame({'qname': parts[1].astype(str).str.strip()})  # prendre seconde partie
        else:
            # sinon considérer la colonne comme qname directement
            df_input = pd.DataFrame({'qname': single.astype(str).str.strip()})

    # extraire features pour chaque ligne
    feats = [extract_features(q) for q in df_input['qname'].tolist()]  # liste de dicts
    df_feat = pd.DataFrame(feats)                       # DataFrame features

    # sélectionner colonnes features utilisées par l'entraînement (ordre stable)
    feature_cols = ['entropy','length','max_label','avg_label_len','num_labels','alpha_ratio','digit_ratio','special_ratio','vowel_ratio']
    present_cols = [c for c in feature_cols if c in df_feat.columns]  # colonnes présentes

    # transformer en matrice numpy pour le scaler
    X = df_feat[present_cols].astype(float).values   # matrice X float

    # scaler.transform (attention aux exceptions)
    X_scaled = scaler.transform(X)                  # normaliser selon scaler entraîné

    # prédictions probas et classes
    proba = clf.predict_proba(X_scaled)[:,1] if hasattr(clf, "predict_proba") else None  # probas de la classe 1
    pred = (proba >= args.prob_thresh).astype(int) if proba is not None else clf.predict(X_scaled)  # seuil si proba dispo

    # assembler DataFrame de sortie
    out_df = df_input.copy()                         # commencer avec qname
    out_df = pd.concat([out_df, df_feat[present_cols]], axis=1)  # ajouter features
    out_df['proba_malicious'] = proba if proba is not None else pd.Series(clf.predict(X_scaled))
    out_df['predicted_label'] = pred                 # ajouter colonne prédite (0/1)
    # sauvegarder CSV
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)  # créer dossier si besoin
    out_df.to_csv(out_path, index=False)             # sauvegarder résultats
    print(f"[OK] Prédictions sauvegardées dans: {out_path}")  # message de succès

if __name__ == '__main__':                            # point d'entrée
    main()                                            # lancer main
