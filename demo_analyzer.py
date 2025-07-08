#!/usr/bin/env python3
"""
S1AP Protocol Analyzer - Demonstration Script
==============================================

Script de démonstration des capacités de l'analyseur S1AP.
Affiche les résultats d'une analyse précédente et montre les fonctionnalités.

Usage:
    python demo_analyzer.py
"""

import json
import sys
from pathlib import Path
from datetime import datetime


def load_analysis_results():
    """Charge les résultats d'analyse existants."""
    results_file = Path("s1ap_analysis_final.json")
    
    if not results_file.exists():
        print("❌ Fichier de résultats d'analyse non trouvé : s1ap_analysis_final.json")
        return None
    
    try:
        with open(results_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Erreur lors du chargement : {e}")
        return None


def print_header():
    """Affiche l'en-tête de démonstration."""
    print("\n" + "="*80)
    print("🔍 S1AP PROTOCOL ANALYZER - DEMONSTRATION")
    print("="*80)
    print("Analyseur professionnel pour le protocole S1AP")
    print("Conforme 3GPP TS 36.413 - Décodage ASN.1/PER correct")
    print("="*80)


def print_metadata(metadata):
    """Affiche les métadonnées de l'analyse."""
    print("\n📋 MÉTADONNÉES DE L'ANALYSE")
    print("-" * 40)
    print(f"🔧 Version analyseur: {metadata.get('analyzer_version', 'N/A')}")
    print(f"📚 Standard 3GPP: {metadata.get('3gpp_standard', 'N/A')}")
    print(f"🔒 Conformité ASN.1: {metadata.get('asn1_compliance', 'N/A')}")
    print(f"🧩 Compatible Wireshark: {'✅ Oui' if metadata.get('wireshark_compatible') else '❌ Non'}")
    print(f"⏰ Analyse effectuée: {metadata.get('analysis_timestamp', 'N/A')}")
    print(f"📁 Fichier source: {metadata.get('pcap_file', 'N/A')}")


def print_summary(summary):
    """Affiche le résumé statistique."""
    print("\n📊 RÉSUMÉ STATISTIQUE")
    print("-" * 40)
    print(f"📦 Paquets totaux analysés: {summary.get('total_packets', 0)}")
    print(f"📨 Messages S1AP décodés: {summary.get('s1ap_messages', 0)}")
    print(f"🔄 Procédures uniques: {summary.get('unique_procedures', 0)}")
    print(f"👥 Sessions UE distinctes: {summary.get('unique_sessions', 0)}")
    
    duration = summary.get('analysis_duration', 0)
    print(f"⚡ Durée d'analyse: {duration:.3f} secondes")
    
    # Calcul de la vitesse
    if duration > 0:
        msg_per_sec = summary.get('s1ap_messages', 0) / duration
        print(f"🚀 Vitesse de traitement: {msg_per_sec:.1f} messages/seconde")


def print_procedures(procedures):
    """Affiche la distribution des procédures."""
    print("\n🔄 DISTRIBUTION DES PROCÉDURES S1AP")
    print("-" * 50)
    
    # Trier par pourcentage décroissant
    sorted_procedures = sorted(
        procedures.items(), 
        key=lambda x: x[1].get('percentage', 0), 
        reverse=True
    )
    
    for proc_name, info in sorted_procedures:
        count = info.get('count', 0)
        percentage = info.get('percentage', 0)
        description = info.get('description', 'N/A')
        
        # Barre de progression simple
        bar_length = int(percentage / 100 * 30)
        bar = "█" * bar_length + "░" * (30 - bar_length)
        
        print(f"📋 {proc_name:<25} │ {bar} │ {count:>3} msg ({percentage:5.1f}%)")
        print(f"   └─ {description}")


def print_sessions_summary(sessions):
    """Affiche un résumé des sessions UE."""
    print("\n👥 SESSIONS UE DÉTECTÉES")
    print("-" * 50)
    print(f"Nombre total de sessions: {len(sessions)}")
    
    if not sessions:
        print("Aucune session détectée.")
        return
    
    print("\nTop 5 des sessions par activité:")
    # Trier par nombre de messages
    sorted_sessions = sorted(
        sessions.items(),
        key=lambda x: x[1].get('message_count', 0),
        reverse=True
    )
    
    for i, (session_id, info) in enumerate(sorted_sessions[:5], 1):
        mme_id = info.get('mme_ue_s1ap_id', 'N/A')
        enb_id = info.get('enb_ue_s1ap_id', 'N/A')
        msg_count = info.get('message_count', 0)
        procedures = info.get('procedures', [])
        
        print(f"{i}. Session MME-ID: {mme_id} / eNB-ID: {enb_id}")
        print(f"   └─ {msg_count} messages, Procédures: {', '.join(procedures)}")


def print_sample_message(messages):
    """Affiche un exemple de message décodé."""
    if not messages:
        return
        
    print("\n📨 EXEMPLE DE MESSAGE DÉCODÉ")
    print("-" * 50)
    
    # Prendre le premier message avec des IEs enrichis
    sample_msg = None
    for msg in messages:
        if msg.get('ies') and len(msg['ies']) > 0:
            sample_msg = msg
            break
    
    if not sample_msg:
        print("Aucun message avec IEs trouvé.")
        return
    
    print(f"🔢 Paquet #{sample_msg.get('packet_number', 'N/A')}")
    print(f"⏰ Timestamp: {sample_msg.get('timestamp_human', 'N/A')}")
    print(f"🔄 Procédure: {sample_msg['procedure']['name']}")
    print(f"📏 Taille: {sample_msg['size']['raw_bytes']} octets")
    print(f"📊 Nombre d'IEs: {sample_msg['size']['ies_count']}")
    
    print("\n🧩 Information Elements (IEs):")
    for i, ie in enumerate(sample_msg['ies'][:3], 1):  # Top 3 IEs
        print(f"  {i}. {ie['name']} (ID: {ie['id']})")
        print(f"     └─ Longueur: {ie['length']} octets, Criticité: {ie['criticality']}")
        
        # Afficher le contenu analysé si disponible
        analyzed = ie.get('analyzed_content')
        if analyzed and isinstance(analyzed, dict):
            if 'structured_data' in analyzed:
                structured = analyzed['structured_data']
                for key, value in list(structured.items())[:2]:  # Top 2 fields
                    print(f"     └─ {key}: {value}")


def print_advanced_features():
    """Affiche les fonctionnalités avancées du décodeur."""
    print("\n🎯 FONCTIONNALITÉS AVANCÉES")
    print("-" * 50)
    
    features = [
        "✅ Décodage ASN.1/PER conforme aux standards 3GPP",
        "✅ Analyse structurée des Information Elements composés",
        "✅ Enrichissement automatique avec table MCC-MNC",
        "✅ Tracking des sessions UE avec MME-UE-S1AP-ID et eNB-UE-S1AP-ID",
        "✅ Validation croisée avec les résultats Wireshark",
        "✅ Support des procédures : CellTrafficTrace, Paging, downlinkNASTransport",
        "✅ Décodage correct des types composés : TAIList, EUTRAN-CGI",
        "✅ Export JSON structuré pour intégration",
        "✅ Statistiques détaillées et insights métier",
        "✅ Interface en ligne de commande intuitive"
    ]
    
    for feature in features:
        print(f"  {feature}")


def print_usage_example():
    """Affiche des exemples d'utilisation."""
    print("\n💡 EXEMPLES D'UTILISATION")
    print("-" * 50)
    
    examples = [
        "# Analyse complète d'un fichier PCAP",
        "python s1ap_analyzer.py s1CP.pcap",
        "",
        "# Limitation aux 10 premiers paquets",
        "python s1ap_analyzer.py s1CP.pcap --limit 10",
        "",
        "# Export vers fichier JSON",
        "python s1ap_analyzer.py s1CP.pcap --output analysis.json",
        "",
        "# Mode verbose avec détails complets",
        "python s1ap_analyzer.py s1CP.pcap --verbose",
        "",
        "# Analyse avec limitation et export",
        "python s1ap_analyzer.py s1CP.pcap --limit 50 --output detailed.json"
    ]
    
    for example in examples:
        if example.startswith("#"):
            print(f"\n{example}")
        elif example == "":
            continue
        else:
            print(f"  {example}")


def main():
    """Fonction principale de démonstration."""
    print_header()
    
    # Charger les résultats d'analyse
    results = load_analysis_results()
    if not results:
        print("\n❌ Impossible de charger les résultats d'analyse.")
        print("Assurez-vous que le fichier 's1ap_analysis_final.json' existe.")
        return 1
    
    # Afficher les différentes sections
    print_metadata(results.get('metadata', {}))
    print_summary(results.get('summary', {}))
    print_procedures(results.get('procedures', {}))
    print_sessions_summary(results.get('sessions', {}))
    print_sample_message(results.get('messages', []))
    print_advanced_features()
    print_usage_example()
    
    print("\n" + "="*80)
    print("🎉 DÉMONSTRATION TERMINÉE")
    print("="*80)
    print("Pour une analyse complète de vos propres fichiers PCAP :")
    print("  python s1ap_analyzer.py votre_fichier.pcap")
    print("\nPour plus d'informations, consultez le README.md")
    print("="*80)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
