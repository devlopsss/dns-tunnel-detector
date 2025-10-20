#!/usr/bin/env python3  # Utiliser Python 3
# -*- coding: utf-8 -*-  # Encodage UTF-8

"""
realtime_syslog_detector.py — Sniff DNS en live, score via modèle supervisé, envoie alertes Syslog.

Spécificités :
- Mode 'simple' (défaut) : message compact avec probabilité PUIS qname (dans cet ordre).
- Mode 'full' : message enrichi + features dans le Structured-Data (SD).
- Séparateur visuel configurable (défaut " || ").
- Ajoute un DOUBLE SAUT DE LIGNE (\n\n) à chaque envoi (UDP et TCP) pour une séparation claire entre alertes.
"""

import argparse, os, sys, socket, json                      # Gestion CLI / OS / sockets / JSON
from datetime import datetime                               # Timestamp
from collections import Counter                             # Comptage pour entropie
import math, joblib, numpy as np                            # Math, chargement modèles, vecteurs
from scapy.all import sniff, DNS, DNSQR                     # Scapy pour sniff DNS (requiert droits)

# ---------- Utilitaires de features ----------

def shannon_entropy(s: str) -> float:
    """Entropie de Shannon (base 2) de la chaîne s."""
    if not s: return 0.0                                    # Chaîne vide → 0
    c = Counter(s)                                          # Compte caractères
    n = len(s)                                              # Longueur
    return -sum((cnt/n) * math.log2(cnt/n) for cnt in c.values())  # Formule

def extract_features(qname: str) -> dict:
    """Extrait les features nécessaires au modèle (mêmes que training)."""
    q = '' if qname is None else str(qname).strip()         # Normalisation qname
    q = q.rstrip('.')                                       # Retire '.' final
    labels = [lab for lab in q.split('.') if lab]           # Découpe labels
    length = len(q)                                         # Longueur totale
    max_label = max((len(l) for l in labels), default=0)    # Max label length
    num_labels = len(labels)                                 # Nombre de labels
    entropy = shannon_entropy(q.replace('.', ''))           # Entropie sans '.'
    alpha_ratio = sum(ch.isalpha() for ch in q)/max(1, length)   # % lettres
    digit_ratio = sum(ch.isdigit() for ch in q)/max(1, length)   # % chiffres
    special_ratio = sum((not ch.isalnum() and ch != '.') for ch in q)/max(1, length)  # % spéciaux
    avg_label_len = (sum(len(l) for l in labels)/num_labels) if num_labels>0 else 0.0 # Moy. long. label
    vowel_ratio = sum(ch.lower() in 'aeiouy' for ch in q)/max(1, length)              # % voyelles
    return {
        'qname': q, 'entropy': float(entropy), 'length': float(length), 'max_label': float(max_label),
        'avg_label_len': float(avg_label_len), 'num_labels': float(num_labels),
        'alpha_ratio': float(alpha_ratio), 'digit_ratio': float(digit_ratio),
        'special_ratio': float(special_ratio), 'vowel_ratio': float(vowel_ratio),
    }

# ---------- Mapping sévérité ----------

def severity_from_proba(p: float, high: float, med: float) -> str:
    """Mappe p en 'low'/'medium'/'high' selon (high, medium)."""
    if p >= high: return "high"                             # p ≥ high → high
    if p >= med: return "medium"                            # p ≥ medium → medium
    return "low"                                            # sinon → low

# ---------- Construction RFC5424 ----------

def rfc5424_message(hostname: str, appname: str, procid: str, msgid: str,
                    structured_data: str, msg: str, facility: int, sev_code: int) -> str:
    """Construit une trame Syslog RFC5424 complète."""
    pri = 8*facility + sev_code                             # PRI
    ts = datetime.utcnow().isoformat() + "Z"                # Timestamp UTC
    sd = structured_data if structured_data else '-'        # SD ou '-'
    return f"<{pri}>1 {ts} {hostname} {appname} {procid} {msgid} {sd} {msg}"  # Trame finale

# ---------- Émetteur Syslog ----------

class SyslogSender:
    """Émetteur Syslog réutilisable (UDP par défaut, TCP si --tcp)."""
    def __init__(self, host: str, port: int, tcp: bool):
        self.host, self.port, self.tcp = host, port, tcp                   # Stocke params
        if tcp: self.sock = socket.create_connection((host, port), timeout=5)  # TCP
        else:   self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # UDP
    def send(self, frame: str):
        data = frame.encode("utf-8")                                       # Encode UTF-8
        # DOUBLE saut de ligne pour séparer visuellement chaque alerte
        if self.tcp: self.sock.sendall(data + b"\n\n")                     # TCP : \n\n
        else:       self.sock.sendto(data + b"\n\n", (self.host, self.port))   # UDP : \n\n
    def close(self):
        try: self.sock.close()                                             # Ferme socket
        except Exception: pass

# ---------- Scorer (modèle + scaler) ----------

class LiveScorer:
    """Charge modèle/scaler, applique scaling, renvoie proba classe 1."""
    def __init__(self, model_path: str, scaler_path: str):
        self.model = joblib.load(model_path)                               # Modèle sklearn
        self.scaler = joblib.load(scaler_path)                             # Scaler sklearn
        self.feature_cols = [                                              # Ordre EXACT du training
            'entropy','length','max_label','avg_label_len',
            'num_labels','alpha_ratio','digit_ratio','special_ratio','vowel_ratio'
        ]
    def predict_proba(self, feat: dict) -> float:
        x = np.array([[float(feat.get(c,0.0)) for c in self.feature_cols]], dtype=float)  # Vecteur 1xN
        xs = self.scaler.transform(x)                                      # Scaling
        if hasattr(self.model, "predict_proba"):                           # Modèle probabiliste ?
            return float(self.model.predict_proba(xs)[:,1][0])             # p(classe=1)
        return float(self.model.decision_function(xs))                     # Fallback (score)

# ---------- Callback Scapy ----------

def make_packet_handler(scorer: LiveScorer, syslog: SyslogSender,
                        hostname: str, appname: str, facility: int,
                        high: float, med: float,
                        min_prob_emit: float, emit_all: bool,
                        mode: str, separator: str):
    """Fabrique la fonction appelée à chaque paquet DNS capturé."""
    def _handler(pkt):
        try:
            if not pkt.haslayer(DNS): return                               # Ignore si pas DNS
            dns = pkt[DNS]                                                 # Couche DNS
            if dns.qr != 0: return                                         # On ne traite que les requêtes (qr==0)
            qd = dns.qd                                                    # Section question
            if qd is None: return                                          # Aucune question
            if isinstance(qd, DNSQR):                                      # DNSQR attendu
                qname = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)  # qname
            else:
                qname = str(qd[0].qname)                                   # Fallback si liste

            feat = extract_features(qname)                                 # Calcule features
            proba = scorer.predict_proba(feat)                             # Proba malicieux
            sev_txt = severity_from_proba(proba, high, med)                # Sévérité texte
            sev_code = 1 if sev_txt=="high" else (4 if sev_txt=="medium" else 5)  # Code RFC5424

            if (not emit_all) and (proba < min_prob_emit):                 # Filtre émission
                return                                                     # Ignore si proba faible

            sep = separator                                                # Séparateur visuel
            if mode == "simple":                                           # MODE SIMPLE : proba puis qname
                sd = f'[dns@9999 data="{json.dumps({"probability": round(proba,6)}, ensure_ascii=False)}"]'  # SD minimal
                # >>> qname placé APRÈS la probabilité dans le message
                msg = f"DNS alert{sep}proba={proba:.3f}{sep}qname={feat['qname']}"                           # MSG compact
            else:                                                          # MODE FULL : SD complet + MSG enrichi
                sd_obj = {
                    "qname": feat['qname'], "probability": round(proba,6),
                    "entropy": feat['entropy'], "length": feat['length'], "max_label": feat['max_label'],
                    "num_labels": feat['num_labels'], "alpha_ratio": feat['alpha_ratio'],
                    "digit_ratio": feat['digit_ratio'], "special_ratio": feat['special_ratio'], "vowel_ratio": feat['vowel_ratio'],
                    "rule": {"name": "dns_supervised_classifier", "version": 1,
                             "thresholds": {"high": high, "medium": med}}
                }
                sd = f'[dns@9999 data="{json.dumps(sd_obj, ensure_ascii=False)}"]'                           # SD JSON
                msg = sep.join(["DNS alert", f"qname={feat['qname']}", f"severity={sev_txt}", f"proba={proba:.3f}"])  # MSG enrichi

            frame = rfc5424_message(                                      # Construit trame RFC5424
                hostname=hostname, appname=appname, procid=str(os.getpid()), msgid="dns-alert",
                structured_data=sd, msg=msg, facility=facility, sev_code=sev_code
            )
            syslog.send(frame)                                            # Envoie la trame au SIEM
        except Exception as e:
            print(f"[WARN] Handler error: {e}", file=sys.stderr)          # Log l’erreur et continue
            return
    return _handler                                                        # Retourne le callback

# ---------- CLI / Main ----------

def main():
    p = argparse.ArgumentParser(description="DNS temps réel -> Syslog (simple/full + séparateur visuel)")
    p.add_argument("--iface", required=True, help="Interface réseau (ex: eth0, ens33, wlan0)")            # Interface sniff
    p.add_argument("--bpf", default="udp port 53", help="Filtre BPF (défaut: 'udp port 53')")              # Filtre BPF
    p.add_argument("--model", required=True, help="Chemin du modèle .pkl")                                 # Modèle sklearn
    p.add_argument("--scaler", required=True, help="Chemin du scaler .pkl")                                # Scaler sklearn
    p.add_argument("--syslog-host", required=True, help="Adresse du serveur Syslog")                       # Hôte SIEM
    p.add_argument("--syslog-port", type=int, default=514, help="Port Syslog (514)")                       # Port SIEM
    p.add_argument("--tcp", action="store_true", help="Utiliser TCP (sinon UDP)")                          # Transport TCP
    p.add_argument("--facility", type=int, default=1, help="Facility RFC5424 (1=USER, 16=LOCAL0...)")      # Facility
    p.add_argument("--high", type=float, default=0.85, help="Seuil HIGH")                                  # Seuil 'high'
    p.add_argument("--medium", type=float, default=0.60, help="Seuil MEDIUM")                              # Seuil 'medium'
    p.add_argument("--min-prob-emit", type=float, default=0.60, help="Proba minimale pour émettre")        # Seuil émission
    p.add_argument("--emit-all", action="store_true", help="Émettre toutes les requêtes (debug)")          # Tout émettre
    p.add_argument("--hostname", default="sensor-local", help="Hostname RFC5424")                           # Hostname
    p.add_argument("--appname", default="dns-detector", help="Appname RFC5424")                             # Appname
    p.add_argument("--mode", choices=["simple","full"], default="simple", help="Mode simple ou full")       # Mode
    p.add_argument("--separator", default=" || ", help="Séparateur visuel dans le MSG")                     # Séparateur
    args = p.parse_args()                                                                                    # Parse

    scorer = LiveScorer(args.model, args.scaler)                        # Charge modèle + scaler
    syslog_sender = SyslogSender(args.syslog_host, args.syslog_port, args.tcp)  # Socket syslog
    handler = make_packet_handler(                                      # Callback pour Scapy
        scorer, syslog_sender, args.hostname, args.appname, args.facility,
        args.high, args.medium, args.min_prob_emit, args.emit_all, args.mode, args.separator
    )

    print(f"[INFO] Sniff iface={args.iface} bpf='{args.bpf}' → Syslog {args.syslog_host}:{args.syslog_port} ({'TCP' if args.tcp else 'UDP'})")
    print(f"[INFO] Mode={args.mode}  sep='{args.separator}'  Seuils: high>={args.high}  medium>={args.medium}  min_prob_emit={args.min_prob_emit} emit_all={args.emit_all}")

    try:
        sniff(iface=args.iface, filter=args.bpf, prn=handler, store=False)  # Lance la capture (sans stocker en RAM)
    finally:
        syslog_sender.close()                                               # Ferme la socket proprement

if __name__ == "__main__":  # Entrée standard
    main()                   # Exécuter le main
