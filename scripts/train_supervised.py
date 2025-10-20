#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# train_supervised.py — Entraîne un classifieur supervisé (RandomForest) à partir d'un CSV de features.
# usage: python scripts/train_supervised.py --in data/features.csv --out-model models/rf_model.pkl --out-scaler models/scaler.pkl

import argparse                                     # gestion des arguments
import pandas as pd                                 # pandas pour les DataFrame
import os                                           # utils système
import joblib                                       # pour sauvegarder le modèle (joblib)
from sklearn.ensemble import RandomForestClassifier # classifieur RandomForest
from sklearn.model_selection import train_test_split# split train/test
from sklearn.preprocessing import StandardScaler    # scaler des features (StandardScaler)
from sklearn.metrics import classification_report, confusion_matrix  # métriques
import numpy as np                                  # utilitaires numériques

def main(argv=None):                                # fonction principale
    ap = argparse.ArgumentParser(description="Entraîne un RandomForest sur CSV de features")  # parser
    ap.add_argument('--in', dest='in_path', required=True, help='CSV en entrée (features.csv)')  # input
    ap.add_argument('--out-model', dest='out_model', default='models/rf_model.pkl', help='Chemin pour sauvegarder le modèle')  # output model
    ap.add_argument('--out-scaler', dest='out_scaler', default='models/scaler.pkl', help='Chemin pour sauvegarder le scaler')  # output scaler
    ap.add_argument('--test-size', type=float, default=0.2, help='Fraction pour test (défaut 0.2)')  # taille test
    ap.add_argument('--random-state', type=int, default=42, help='Seed pour reproductibilité')  # seed
    ap.add_argument('--n-estimators', type=int, default=200, help='n_estimators RandomForest (défaut 200)')  # arbres
    args = ap.parse_args(argv)                       # parse args

    in_path = args.in_path                           # chemin input
    out_model = args.out_model                       # chemin sortie modèle
    out_scaler = args.out_scaler                     # chemin sortie scaler

    if not os.path.exists(in_path):                  # vérifier existence fichier input
        raise FileNotFoundError(f"Fichier non trouvé: {in_path}")  # erreur claire

    df = pd.read_csv(in_path)                        # lire CSV de features
    # colonnes candidates (on garde celles présentes)
    candidate_features = ['entropy','length','max_label','avg_label_len','num_labels','alpha_ratio','digit_ratio','special_ratio','vowel_ratio']
    features = [c for c in candidate_features if c in df.columns]  # intersector
    if not features:                                 # si aucune feature trouvée
        raise ValueError("Aucune colonne de features reconnue dans le CSV d'entrée.")  # erreur

    # labels
    if 'label' not in df.columns:                    # si pas de colonne label
        raise ValueError("La colonne 'label' est requise dans le CSV d'entrée.")  # erreur
    y = pd.to_numeric(df['label'], errors='coerce')  # convertir label en numérique (NaN si non convertible)
    if y.isna().any():                              # si valeurs NaN
        print("[WARN] Certaines valeurs de label sont NaN et seront retirées.", flush=True)  # avertir
    # filtrer lignes valides (features non nulles et label présent)
    valid = ~y.isna()
    X = df.loc[valid, features].astype(float)       # matrice X
    y = y.loc[valid].astype(int)                    # vecteur y

    # split train/test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=args.test_size, random_state=args.random_state, stratify=y if len(np.unique(y))>1 else None)  # split

    # normaliser features — important pour certains modèles (ici RandomForest supporte mais c'est pratique pour d'autres)
    scaler = StandardScaler()                       # crée scaler
    X_train_scaled = scaler.fit_transform(X_train)  # entraîne scaler sur train
    X_test_scaled = scaler.transform(X_test)        # applique scaler au test

    # entraîner RandomForest
    clf = RandomForestClassifier(n_estimators=args.n_estimators, random_state=args.random_state, n_jobs=-1)  # classifieur
    clf.fit(X_train_scaled, y_train)                # fit modèle

    # prédictions & métriques
    y_pred = clf.predict(X_test_scaled)             # prédire classes
    y_proba = clf.predict_proba(X_test_scaled)[:,1] if hasattr(clf, "predict_proba") else None  # probabilités si disponibles

    print("[INFO] Rapport de classification (test set):")  # afficher rapport
    print(classification_report(y_test, y_pred))  # print metrics

    print("[INFO] Matrice de confusion:")         # afficher confusion matrix
    print(confusion_matrix(y_test, y_pred))      # print matrix

    # sauvegarder scaler et modèle
    os.makedirs(os.path.dirname(out_model) or '.', exist_ok=True)  # crée dossiers
    joblib.dump(clf, out_model)                     # sauvegarde modèle
    joblib.dump(scaler, out_scaler)                 # sauvegarde scaler

    print(f"[OK] Modèle sauvegardé: {out_model}")   # message succès
    print(f"[OK] Scaler sauvegardé: {out_scaler}") # message succès

if __name__ == '__main__':                          # point d'entrée
    main()                                          # exécuter main
