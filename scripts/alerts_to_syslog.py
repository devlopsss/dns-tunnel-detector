#!/usr/bin/env python3  # Exécuter avec Python 3
# -*- coding: utf-8 -*-  # Encodage UTF-8 pour caractères non ASCII

"""
alerts_to_syslog.py — Convertit un CSV de prédictions en alertes Syslog RFC5424 (UDP/TCP).

Spécificités :
- Mode 'simple' (par défaut) : message compact avec probabilité PUIS qname (dans cet ordre).
- Mode 'full' : message enrichi + features dans le Structured-Data (SD).
- Séparateur visuel configurable avec --separator (défaut : " || ").
- Ajoute un DOUBLE SAUT DE LIGNE (\n\n) à l’envoi pour séparer visuellement chaque alerte.

Exemples :
  python scripts/alerts_to_syslog.py --pred data/predictions.csv --host 127.0.0.1 --port 514
  python scripts/alerts_to_syslog.py --pred data/predictions.csv --host 127.0.0.1 --port 514 --mode full
"""

import argparse               # Parser d’arguments CLI
import os                     # Vérifier chemins / PID
import sys                    # Sorties d’erreur, exit codes
import socket                 # Sockets UDP/TCP pour Syslog
from datetime import datetime # Timestamps ISO 8601
import json                   # Sérialisation du SD en JSON
import pandas as pd           # Lecture du CSV de prédictions


def severity_from_proba(p: float, high: float, med: float) -> str:
    """Retourne 'low' / 'medium' / 'high' selon les seuils fournis."""
    if p >= high:             # Si p ≥ seuil haut
        return "high"         # → high
    if p >= med:              # Sinon si p ≥ seuil medium
        return "medium"       # → medium
    return "low"              # Sinon → low


def rfc5424_message(hostname: str, appname: str, procid: str, msgid: str,
                    structured_data: str, msg: str, facility: int, sev_code: int) -> str:
    """Construit une trame RFC5424 (PRI + version=1)."""
    pri = 8 * facility + sev_code            # PRI = 8*facility + severity
    ts = datetime.utcnow().isoformat() + "Z" # Timestamp UTC ISO 8601
    sd = structured_data if structured_data else '-'  # SD présent ou '-'
    # Retourne la trame complète RFC5424
    return f"<{pri}>1 {ts} {hostname} {appname} {procid} {msgid} {sd} {msg}"


def open_syslog_socket(host: str, port: int, tcp: bool):
    """Crée une socket Syslog : TCP si demandé, sinon UDP."""
    if tcp:                                      # Transport TCP
        return socket.create_connection((host, port), timeout=5)  # Socket connectée
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)       # UDP datagrammes


def main():                                      # Point d’entrée
    # Définition des arguments CLI
    parser = argparse.ArgumentParser(description="CSV prédictions -> alertes Syslog (simple/full)")
    parser.add_argument("--pred", required=True, help="CSV de prédictions (ex: data/predictions.csv)")     # Fichier CSV
    parser.add_argument("--host", required=True, help="Adresse du serveur Syslog (ex: 127.0.0.1)")         # Hôte SIEM
    parser.add_argument("--port", type=int, default=514, help="Port Syslog (défaut 514)")                  # Port SIEM
    parser.add_argument("--tcp", action="store_true", help="Utiliser TCP (sinon UDP)")                     # Flag TCP
    parser.add_argument("--facility", type=int, default=1, help="Facility RFC5424 (1=USER, 16=LOCAL0)")    # Facility
    parser.add_argument("--appname", default="dns-detector", help="APP-NAME RFC5424")                      # Appname
    parser.add_argument("--hostname", default="sensor-batch", help="HOSTNAME RFC5424")                     # Hostname
    parser.add_argument("--high", type=float, default=0.85, help="Seuil proba HIGH")                       # Seuil 'high'
    parser.add_argument("--medium", type=float, default=0.60, help="Seuil proba MEDIUM")                   # Seuil 'medium'
    parser.add_argument("--min-prob-emit", type=float, default=0.60, help="Proba minimale pour émettre")   # Filtre proba
    parser.add_argument("--min-severity", choices=["low","medium","high"], default="low",
                        help="Sévérité minimale à émettre")                                                # Filtre sévérité
    parser.add_argument("--mode", choices=["simple","full"], default="simple",
                        help="Mode 'simple' (proba+qname) ou 'full' (features)")                           # Mode
    parser.add_argument("--separator", default=" || ",
                        help="Séparateur visuel dans le MSG (défaut: ' || ')")                             # Séparateur
    args = parser.parse_args()                                                                             # Parse args

    if not os.path.exists(args.pred):                                 # Vérifie présence CSV
        print(f"[ERROR] Fichier introuvable: {args.pred}", file=sys.stderr); sys.exit(2)                   # Erreur claire

    try:
        df = pd.read_csv(args.pred)                                   # Lecture CSV
    except Exception as e:
        print(f"[ERROR] Lecture CSV: {e}", file=sys.stderr); sys.exit(3)                                   # Parsing error

    if "proba_malicious" not in df.columns:                           # Proba requise
        print("[ERROR] 'proba_malicious' manquant dans CSV.", file=sys.stderr); sys.exit(4)                # Erreur

    if "qname" in df.columns:                                         # qname optionnel mais utile
        df["qname"] = df["qname"].astype(str).str.strip().str.rstrip('.')                                  # Nettoyage
    else:
        df["qname"] = ""                                              # Valeur vide si colonne absente

    df["proba_malicious"] = pd.to_numeric(df["proba_malicious"], errors="coerce")                          # Force float
    if "predicted_label" in df.columns:                                                                     # Label prédit ?
        df["predicted_label"] = pd.to_numeric(df["predicted_label"], errors="coerce").fillna(-1).astype(int) # En int
    else:
        df["predicted_label"] = -1                                                                          # Défaut

    order = {"low": 0, "medium": 1, "high": 2}                        # Ordre des sévérités
    min_rank = order[args.min_severity]                                # Rang minimal demandé

    sock = open_syslog_socket(args.host, args.port, args.tcp)          # Ouvre socket syslog
    use_tcp = args.tcp                                                 # Mémorise si TCP

    sent = 0                                                           # Compteur
    try:
        for _, row in df.iterrows():                                   # Parcourt chaque prédiction
            p = float(row.get("proba_malicious", 0.0))                 # Récupère la proba
            if p < args.min_prob_emit:                                 # Filtre proba minimale
                continue                                               # Ignore si trop bas

            sev_txt = severity_from_proba(p, args.high, args.medium)   # Calcule sévérité textuelle
            if order[sev_txt] < min_rank:                              # Filtre sévérité minimale
                continue                                               # Ignore si trop faible

            sev_code = 1 if sev_txt == "high" else (4 if sev_txt == "medium" else 5)  # Code RFC5424 (1,4,5)

            sep = args.separator                                       # Séparateur visuel configurable

            if args.mode == "simple":                                  # MODE SIMPLE (proba puis qname)
                sd = f'[dns@9999 data="{json.dumps({"probability": round(p,6)}, ensure_ascii=False)}"]'     # SD minimal
                # >>> qname placé APRÈS la probabilité
                msg = f"DNS alert{sep}proba={p:.3f}{sep}qname={row.get('qname','')}"                        # MSG compact
            else:                                                      # MODE FULL (SD enrichi + MSG riche)
                sd_obj = {                                             # Objet SD avec champs utiles
                    "probability": round(p, 6),
                    "predicted_label": int(row.get("predicted_label", -1)),
                    "thresholds": {"high": args.high, "medium": args.medium},
                    "qname": row.get("qname","")
                }
                # Ajoute les features si elles existent dans le CSV
                for col in ["entropy","length","max_label","num_labels","alpha_ratio","digit_ratio","special_ratio","vowel_ratio"]:
                    if col in df.columns:
                        try: sd_obj[col] = float(row.get(col, 0.0))
                        except Exception: pass
                sd = f'[dns@9999 data="{json.dumps(sd_obj, ensure_ascii=False)}"]'                          # SD sérialisé
                base = ["DNS alert", f"qname={row.get('qname','')}", f"severity={sev_txt}", f"proba={p:.3f}"]  # Message
                msg = sep.join(base)                                                                        # Jointure

            frame = rfc5424_message(                                  # Construit la trame RFC5424
                hostname=args.hostname, appname=args.appname,
                procid=str(os.getpid()), msgid="dns-alert",
                structured_data=sd, msg=msg, facility=args.facility, sev_code=sev_code
            )

            data = frame.encode("utf-8")                               # Encode en UTF-8
            # >>> DOUBLE saut de ligne pour séparer les alertes (visuel clair)
            if use_tcp:
                sock.sendall(data + b"\n\n")                           # TCP : envoyer et séparer
            else:
                sock.sendto(data + b"\n\n", (args.host, args.port))    # UDP : idem

            sent += 1                                                  # Incrémente compteur
    finally:
        try: sock.close()                                              # Ferme la socket proprement
        except Exception: pass

    print(f"[OK] {sent} alertes envoyées à {args.host}:{args.port} ({'TCP' if use_tcp else 'UDP'})")  # Résumé


if __name__ == "__main__":  # Standard Python entrypoint
    main()                   # Lance le script
