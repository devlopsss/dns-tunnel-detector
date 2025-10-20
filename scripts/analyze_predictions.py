#!/usr/bin/env python3
# coding: utf-8
# analyze_predictions.py
# Analyse approfondie d'un fichier predictions CSV produit par predict_supervised.py
# - calcule résumés, compte TP/FP si labels dispo, affiche distributions et calibration
# - affiche importances features si le modèle RandomForest est fourni
#
# Usage:
#   python scripts/analyze_predictions.py --pred data/predictions_test.csv --model models/rf_model.pkl
#
# (Le paramètre --model est optionnel, mais s'il est fourni on affichera feature_importances_)

import argparse                                # parseur d'arguments
import os                                      # utilitaires système
import pandas as pd                            # pandas pour csv/dataframe
import numpy as np                             # numpy pour calculs
import matplotlib.pyplot as plt                # matplotlib pour graphiques
import textwrap                                 # utilitaire pour formatage texte

# sklearn: méthodes d'évaluation et calibration
from sklearn.metrics import (
    classification_report,                     # rapport précision/rappel/F1
    confusion_matrix,                           # matrice de confusion
    roc_auc_score                               # AUC ROC
)
from sklearn.calibration import calibration_curve # pour reliability diagram
import joblib                                   # pour charger le modèle s'il existe

def safe_read_csv(path):
    """Lit un CSV de façon robuste et retourne un DataFrame."""
    return pd.read_csv(path, dtype=str)         # lire tout en str pour éviter erreurs

def to_float_cols(df, cols):
    """Convertit en float les colonnes listées si présentes."""
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors='coerce')  # convert, NaN si erreur

def main():
    # parser d'arguments
    p = argparse.ArgumentParser(description="Analyse predictions CSV et diagnostique modèle")
    p.add_argument('--pred', required=True, help='Chemin vers predictions CSV (ex: data/predictions_test.csv)')
    p.add_argument('--model', required=False, help='(optionnel) chemin vers modèle RandomForest pour afficher importances')
    p.add_argument('--out', required=False, default='data/analysis_report.txt', help='Fichier texte résumé produit')
    args = p.parse_args()

    # vérifications d'existence
    if not os.path.exists(args.pred):
        raise FileNotFoundError(f"Fichier predictions introuvable: {args.pred}")

    # lecture du CSV predictions (colonnes attendues: qname, entropy, length, max_label..., proba_malicious, predicted_label)
    df = safe_read_csv(args.pred)                 # lire le CSV
    # nettoyer qname (retirer les points finaux et espaces)
    if 'qname' in df.columns:
        df['qname'] = df['qname'].astype(str).str.strip().str.rstrip('.')

    # convertir en float les colonnes numériques usuelles si présentes
    numeric_cols = ['entropy','length','max_label','avg_label_len','num_labels','alpha_ratio','digit_ratio','special_ratio','vowel_ratio','proba_malicious']
    to_float_cols(df, numeric_cols)               # conversion en float

    # convertir predicted_label en int si présent
    if 'predicted_label' in df.columns:
        df['predicted_label'] = pd.to_numeric(df['predicted_label'], errors='coerce').fillna(-1).astype(int)

    # résumé basique
    total = len(df)                               # nombre total de lignes
    nb_pred1 = int((df['predicted_label']==1).sum()) if 'predicted_label' in df.columns else None
    nb_pred0 = int((df['predicted_label']==0).sum()) if 'predicted_label' in df.columns else None

    # écrire un rapport texte synthétique
    lines = []
    lines.append(f"Analyse du fichier: {args.pred}")
    lines.append(f"Nombre total de lignes: {total}")
    if nb_pred1 is not None:
        lines.append(f"Prédits malicieux (predicted_label==1): {nb_pred1}")
        lines.append(f"Prédits normaux (predicted_label==0): {nb_pred0}")
    lines.append("")

    # distribution de la probabilité
    if 'proba_malicious' in df.columns:
        p_stats = df['proba_malicious'].describe().to_dict()   # stats descriptives
        lines.append("Statistiques sur proba_malicious:")
        for k,v in p_stats.items():
            lines.append(f"  {k}: {v}")
        # fraction exactement égale à 1.0 / 0.0 (RandomForest peut être "one-hot")
        frac_one = (df['proba_malicious'] >= 0.999999).mean()
        frac_zero = (df['proba_malicious'] <= 1e-6).mean()
        lines.append(f"  fraction probas == 1.0: {frac_one:.3f}, == 0.0: {frac_zero:.3f}")
        lines.append("")

    # si labels réels présents (colonne 'label'), évaluer métriques
    if 'label' in df.columns:
        # convertir label en int
        df['label'] = pd.to_numeric(df['label'], errors='coerce')
        valid = df[~df['label'].isna()]
        if len(valid) == 0:
            lines.append("[WARN] Colonne 'label' présente mais toutes valeurs NaN après conversion.")
        else:
            y_true = valid['label'].astype(int).values
            y_pred = valid['predicted_label'].astype(int).loc[valid.index].values
            lines.append("=== Classification report (sur lignes avec label réel) ===")
            lines.append(classification_report(y_true, y_pred, digits=4))
            cm = confusion_matrix(y_true, y_pred)
            lines.append("Matrice de confusion [[TN FP]; [FN TP]]:")
            lines.append(str(cm))
            # AUC si proba disponible
            if 'proba_malicious' in df.columns:
                try:
                    auc = roc_auc_score(y_true, df.loc[valid.index,'proba_malicious'].astype(float).values)
                    lines.append(f"AUC ROC: {auc:.4f}")
                except Exception as e:
                    lines.append(f"[WARN] AUC impossible à calculer: {e}")

    # agrégats features : moyenne/mediane des features pour prédits 1 vs 0
    lines.append("")
    lines.append("Moyennes des features par groupe predicted_label:")
    if 'predicted_label' in df.columns:
        grouped = df.groupby('predicted_label')[ ['entropy','length','max_label','avg_label_len','num_labels','alpha_ratio','digit_ratio'] ].mean()
        lines.append(str(grouped))
    else:
        lines.append("[WARN] 'predicted_label' absent; impossible d'agréger.")

    # Top domaines excessivement longs / entropie élevée (potentiels exfils)
    lines.append("")
    lines.append("Top 20 qnames par proba_malicious décroissante:")
    if 'proba_malicious' in df.columns:
        top = df.sort_values('proba_malicious', ascending=False).head(20)[['qname','proba_malicious','entropy','length','max_label']]
        for _, r in top.iterrows():
            lines.append(f"  {r['qname']}  p={r['proba_malicious']:.3f} ent={r['entropy']:.2f} len={int(r['length'])} maxl={int(r['max_label'])}")
    else:
        lines.append("[WARN] 'proba_malicious' absent.")

    # sauvegarde rapport texte
    with open(args.out, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

    print(f"[OK] Rapport texte écrit: {args.out}")

    # --- Graphiques (sauvegarde PNG dans data/) ---
    png_dir = os.path.dirname(args.out) or '.'
    try:
        # histogramme des probabilités
        if 'proba_malicious' in df.columns:
            plt.figure(figsize=(6,3))
            plt.hist(df['proba_malicious'].dropna(), bins=40)
            plt.title('Histogramme proba_malicious')
            plt.xlabel('probability'); plt.ylabel('count')
            plt.tight_layout()
            plt.savefig(os.path.join(png_dir, 'proba_hist.png'))
            plt.close()

        # boxplots entropy par predicted_label
        if 'predicted_label' in df.columns and 'entropy' in df.columns:
            plt.figure(figsize=(6,3))
            df.boxplot(column='entropy', by='predicted_label')
            plt.title('Entropy par predicted_label')
            plt.suptitle('')
            plt.xlabel('predicted_label'); plt.ylabel('entropy')
            plt.tight_layout()
            plt.savefig(os.path.join(png_dir, 'entropy_by_pred.png'))
            plt.close()

        # reliability diagram (calibration) si proba et labels réels
        if 'proba_malicious' in df.columns and 'label' in df.columns:
            # convertir y_true et y_prob pour les lignes où label présent
            df_lab = df[~df['label'].isna()]
            y_true = df_lab['label'].astype(int).values
            y_prob = df_lab['proba_malicious'].astype(float).values
            # calcul points calibration
            prob_true, prob_pred = calibration_curve(y_true, y_prob, n_bins=10)
            plt.figure(figsize=(4,4))
            plt.plot(prob_pred, prob_true, marker='o', label='calibration')
            plt.plot([0,1],[0,1],'--',color='gray',label='perfect')
            plt.xlabel('predicted prob'); plt.ylabel('empirical prob')
            plt.legend()
            plt.tight_layout()
            plt.savefig(os.path.join(png_dir, 'reliability.png'))
            plt.close()
    except Exception as e:
        print("[WARN] Erreur lors de la génération graphique:", e)

    # --- Feature importances si modèle RF donné ---
    if args.model and os.path.exists(args.model):
        try:
            model = joblib.load(args.model)               # charge modèle joblib
            # si RandomForest a attribute feature_importances_
            if hasattr(model, 'feature_importances_'):
                fi = model.feature_importances_
                # déterminer feature names dans l'ordre: on tente d'utiliser present_cols list ci-dessus
                present = [c for c in ['entropy','length','max_label','avg_label_len','num_labels','alpha_ratio','digit_ratio','special_ratio','vowel_ratio'] if c in df.columns]
                # afficher importances triées
                order = np.argsort(fi)[::-1]
                lines = ["", "Feature importances (modèle fourni):"]
                for idx in order:
                    name = present[idx] if idx < len(present) else f"f{idx}"
                    lines.append(f"  {name}: {fi[idx]:.4f}")
                # append to report file
                with open(args.out, 'a', encoding='utf-8') as f:
                    f.write("\n".join(lines))
                print("[INFO] Feature importances ajoutées au rapport.")
            else:
                print("[WARN] Le modèle chargé n'a pas d'attribut feature_importances_.")
        except Exception as e:
            print("[WARN] Erreur lors du chargement du modèle:", e)

if __name__ == '__main__':
    main()
