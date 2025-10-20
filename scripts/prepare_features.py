#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# prepare_features.py — Lit un CSV simple "label,qname" et calcule des features par qname.
# usage: python scripts/prepare_features.py --in data/raw_dns.csv --out data/features.csv

import argparse                                     # gestion des arguments CLI
import pandas as pd                                 # pandas pour la manipulation de tables
import math                                         # fonctions math (log2)
from collections import Counter                     # compter les caractères pour l'entropie
import os                                           # utilitaires système (chemins)
import sys                                          # utilitaires système (sortie d'erreur)

def shannon_entropy(s: str) -> float:               # fonction pour calculer l'entropie de Shannon
    """Renvoie l'entropie de Shannon de la chaîne s (base 2)."""
    if not s:                                       # si la chaîne est vide
        return 0.0                                  # entropie nulle pour chaîne vide
    c = Counter(s)                                  # compte les occurrences de chaque caractère
    n = len(s)                                      # longueur totale de la chaîne
    # somme p(x) * log2(p(x)) avec signe négatif
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in c.values())  # calcule l'entropie

def extract_features_from_qname(qname: str) -> dict:# construit un dictionnaire de features à partir d'un qname
    """Extrait des features simples et discriminantes à partir d'un qname."""
    q = '' if qname is None else str(qname).strip()  # nettoie l'entrée (None -> '')
    q = q.rstrip('.')                                # retire le point final s'il existe (ex: "example.com.")
    labels = [lab for lab in q.split('.') if lab != '']  # liste des labels non vides
    length = len(q)                                  # longueur totale du qname
    max_label = max((len(l) for l in labels), default=0)  # longueur du label le plus long
    num_labels = len(labels)                         # nombre de labels
    # entropie calculée sur la chaîne sans points (pour mesurer "aléa")
    entropy = shannon_entropy(q.replace('.', ''))    # entropie
    # ratio de caractères alphabétiques et numériques
    alpha_ratio = sum(ch.isalpha() for ch in q) / max(1, length)  # proportion lettres
    digit_ratio = sum(ch.isdigit() for ch in q) / max(1, length)  # proportion chiffres
    special_ratio = sum((not ch.isalnum() and ch != '.') for ch in q) / max(1, length)  # spéciaux hors '.'
    # moyenne des longueurs de labels (utile pour DGA vs domaines normaux)
    avg_label_len = (sum(len(l) for l in labels) / num_labels) if num_labels > 0 else 0.0
    # taux de voyelles (peut aider à différencier mots anglais vs chaînes aléatoires)
    vowel_ratio = sum(ch.lower() in 'aeiouy' for ch in q) / max(1, length)
    # retourne un dict avec toutes les features calculées
    return {
        'qname': q,                                  # nom de domaine nettoyé
        'entropy': float(entropy),                   # entropie totale
        'length': float(length),                     # longueur totale
        'max_label': float(max_label),               # longueur label max
        'num_labels': int(num_labels),               # nb de labels
        'avg_label_len': float(avg_label_len),       # longueur moyenne des labels
        'alpha_ratio': float(alpha_ratio),           # ratio alpha
        'digit_ratio': float(digit_ratio),           # ratio digits
        'special_ratio': float(special_ratio),       # ratio caractères spéciaux
        'vowel_ratio': float(vowel_ratio),           # ratio voyelles
    }

def main(argv=None):                                # fonction principale CLI
    ap = argparse.ArgumentParser(description="Prépare features depuis CSV 'label,qname'")  # parser
    ap.add_argument('--in', dest='in_path', required=True, help='Chemin vers le CSV brut (label,qname)')  # input
    ap.add_argument('--out', dest='out_path', default='data/features.csv', help='Chemin CSV de sortie des features')  # output
    args = ap.parse_args(argv)                       # parse args

    in_path = args.in_path                           # chemin input
    out_path = args.out_path                         # chemin output

    if not os.path.exists(in_path):                  # vérification existence fichier
        print(f"[ERROR] Le fichier d'entrée n'existe pas: {in_path}", file=sys.stderr)  # message erreur
        sys.exit(2)                                 # exit non nul

    # lecture robuste : fichier sans header avec deux colonnes "label,qname" ou fichier avec colonnes nommées
    try:
        # On essaye de lire en forçant deux colonnes si nécessaire
        df_raw = pd.read_csv(in_path, header=None, names=['label','qname'], dtype=str, na_filter=False)  # lecture basique
        # Si le fichier avait un header réel ("label,qname"), la lecture ci-dessus aura transformé la 1ère ligne en données.
        # On vérifie si la 1ère valeur ressemble à 'label' + 'qname' et dans ce cas on relit en header auto.
        first_label = str(df_raw.iloc[0]['label']).lower() if len(df_raw) > 0 else ''
        if first_label in ('label','lbl','class','is_malicious'):  # heuristique header
            df_raw = pd.read_csv(in_path, dtype=str)           # relire avec header
    except Exception as e:
        # si erreur, tenter lecture avec pandas par défaut
        df_raw = pd.read_csv(in_path, dtype=str)               # relire en force
    # si le CSV a plus d'une colonne par erreur (par ex qname contient des virgules), on combine toutes les colonnes sauf la 1ère en qname
    if df_raw.shape[1] > 2:                                   # plus de 2 colonnes trouvées
        cols = list(df_raw.columns)                           # noms colonnes
        # conserver 1ère colonne comme label, concatener le reste comme qname (séparateur virgule)
        df_raw['qname'] = df_raw[cols[1:]].astype(str).agg(','.join, axis=1)  # recomposition
        df_raw = df_raw[[cols[0],'qname']].rename(columns={cols[0]:'label'})  # garder label et qname

    # normaliser le label en entier 0/1 si possible
    # on accepte labels comme '0'/'1' ou 'normal'/'malicious'
    def normalize_label(x):                                   # helper pour label
        s = str(x).strip().lower()                            # normalise case
        if s in ('0','normal','benign','false','no','n'):     # si correspond à normal
            return 0
        if s in ('1','malicious','malware','true','yes','y'): # si correspond à malicieux
            return 1
        # fallback : essayer conversion numérique
        try:
            iv = int(float(s))
            return 1 if iv != 0 else 0
        except Exception:
            return None                                       # valeur non interprétable

    # appliquer la normalisation sur la colonne 'label'
    df_raw['label_norm'] = df_raw['label'].apply(normalize_label)  # colonne label normalisée
    # si aucune ligne n'a été interprétée : avertir
    if df_raw['label_norm'].isna().all():                       # si tout est NaN
        print("[WARN] Aucun label interprétable (attendu 0/1 ou 'normal'/'malicious'). Les labels seront NaN.", file=sys.stderr)

    # extraire features ligne par ligne
    features_list = []                                           # liste pour accumuler dicts de features
    for idx, row in df_raw.iterrows():                           # itération sur les lignes
        q = row.get('qname', '')                                 # récupérer qname
        feat = extract_features_from_qname(q)                    # extraire features
        feat['label'] = row.get('label_norm')                    # attacher label normalisé (peut être None)
        features_list.append(feat)                               # ajouter à la liste

    # construction DataFrame de features
    df_feat = pd.DataFrame(features_list)                         # dataframe final
    # colonne 'qname' en premier (lisibilité)
    cols_order = ['qname','entropy','length','max_label','avg_label_len','num_labels','alpha_ratio','digit_ratio','special_ratio','vowel_ratio','label']
    df_feat = df_feat[[c for c in cols_order if c in df_feat.columns]]  # réordonner si colonnes présentes

    # sauvegarde CSV
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)  # créer dossier si besoin
    df_feat.to_csv(out_path, index=False)                         # écrire CSV sans index
    print(f"[OK] Features écrites dans: {out_path} (lignes: {len(df_feat)})")  # message succès

if __name__ == '__main__':                                      # point d'entrée script
    main()                                                       # exécuter la fonction principale
