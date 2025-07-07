#!/usr/bin/env python3
"""
S1AP Protocol Analyzer - Main Entry Point
==========================================

Analyseur professionnel pour le protocole S1AP (S1 Application Protocol)
conforme aux standards 3GPP TS 36.413 avec décodage ASN.1/PER correct.

Usage:
    python s1ap_analyzer.py <pcap_file> [--limit N] [--output output.json]

Exemples:
    python s1ap_analyzer.py s1CP.pcap
    python s1ap_analyzer.py s1CP.pcap --limit 10 --output results.json
"""

import sys
import argparse
import json
from pathlib import Path

# Import des modules du décodeur S1AP
sys.path.append(str(Path(__file__).parent / "src"))
from s1ap_decoder.core import S1APDecoder


def main():
    """Point d'entrée principal de l'analyseur S1AP."""
    
    parser = argparse.ArgumentParser(
        description="Analyseur S1AP professionnel - Conforme 3GPP TS 36.413",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python s1ap_analyzer.py s1CP.pcap
  python s1ap_analyzer.py s1CP.pcap --limit 10
  python s1ap_analyzer.py s1CP.pcap --output analysis_results.json
  python s1ap_analyzer.py s1CP.pcap --limit 50 --output detailed_analysis.json

Le décodeur supporte:
  ✓ Décodage ASN.1/PER conforme
  ✓ Tracking des sessions UE
  ✓ Analyse des procédures S1AP
  ✓ Validation croisée avec Wireshark
  ✓ Statistiques détaillées
        """
    )
    
    parser.add_argument(
        "pcap_file",
        help="Fichier PCAP contenant les messages S1AP à analyser"
    )
    
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limiter l'analyse aux N premiers paquets S1AP (par défaut: tous)"
    )
    
    parser.add_argument(
        "--output",
        "-o",
        help="Fichier de sortie JSON (par défaut: affichage console)"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Affichage détaillé des informations de décodage"
    )
    
    args = parser.parse_args()
    
    # Vérification de l'existence du fichier PCAP
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        print(f"❌ Erreur: Le fichier PCAP '{args.pcap_file}' n'existe pas.")
        return 1
    
    print(f"🔍 Analyse S1AP du fichier: {args.pcap_file}")
    if args.limit:
        print(f"📊 Limitation: {args.limit} premiers paquets S1AP")
    
    try:
        # Initialisation de l'analyseur
        analyzer = S1APDecoder()
        
        # Analyse du fichier PCAP
        results = analyzer.analyze_pcap(
            str(pcap_path),
            limit_packets=args.limit
        )
        
        # Affichage des résultats
        if args.output:
            # Sauvegarde dans un fichier JSON
            output_path = Path(args.output)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"✅ Résultats sauvegardés dans: {args.output}")
            
            # Affichage du résumé
            summary = results.get('summary', {})
            print(f"\n📊 Résumé de l'analyse:")
            print(f"   • Messages S1AP: {summary.get('s1ap_messages', 0)}")
            print(f"   • Procédures uniques: {summary.get('unique_procedures', 0)}")
            print(f"   • Sessions UE: {summary.get('unique_sessions', 0)}")
            print(f"   • Durée d'analyse: {summary.get('analysis_duration', 0):.3f}s")
        else:
            # Affichage console détaillé
            if args.verbose:
                print(json.dumps(results, indent=2, ensure_ascii=False))
            else:
                print_summary(results)
                
    except Exception as e:
        print(f"❌ Erreur lors de l'analyse: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


def print_summary(results):
    """Affiche un résumé formaté des résultats d'analyse."""
    
    print("\n" + "="*60)
    print("📊 RÉSUMÉ DE L'ANALYSE S1AP")
    print("="*60)
    
    # Métadonnées
    metadata = results.get('metadata', {})
    print(f"🔧 Version analyseur: {metadata.get('analyzer_version', 'N/A')}")
    print(f"📋 Standard 3GPP: {metadata.get('3gpp_standard', 'N/A')}")
    print(f"🔒 Conformité ASN.1: {metadata.get('asn1_compliance', 'N/A')}")
    
    # Résumé global
    summary = results.get('summary', {})
    print(f"\n📈 Statistiques globales:")
    print(f"   • Messages S1AP analysés: {summary.get('s1ap_messages', 0)}")
    print(f"   • Procédures uniques: {summary.get('unique_procedures', 0)}")
    print(f"   • Sessions UE distinctes: {summary.get('unique_sessions', 0)}")
    print(f"   • Durée d'analyse: {summary.get('analysis_duration', 0):.3f} secondes")
    
    # Distribution des procédures
    procedures = results.get('procedures', {})
    if procedures:
        print(f"\n🔄 Distribution des procédures:")
        for proc_name, info in procedures.items():
            count = info.get('count', 0)
            pct = info.get('percentage', 0)
            print(f"   • {proc_name}: {count} messages ({pct:.1f}%)")
    
    # Sessions UE
    sessions = results.get('sessions', {})
    if sessions:
        print(f"\n👥 Sessions UE détectées: {len(sessions)}")
        for session_id, session_info in list(sessions.items())[:5]:  # Top 5
            mme_id = session_info.get('mme_ue_s1ap_id')
            enb_id = session_info.get('enb_ue_s1ap_id')
            msg_count = session_info.get('message_count', 0)
            procedures = ', '.join(session_info.get('procedures', []))
            print(f"   • MME-ID: {mme_id}, eNB-ID: {enb_id} ({msg_count} msg)")
    
    # Insights métier
    insights = results.get('statistics', {}).get('business_insights', {})
    if insights:
        call_patterns = insights.get('call_patterns', {})
        print(f"\n💼 Insights métier:")
        print(f"   • Procédure la plus fréquente: {call_patterns.get('most_common_procedure', 'N/A')}")
        print(f"   • Demandes de paging: {call_patterns.get('paging_requests', 0)}")
        print(f"   • Tentatives d'attach: {call_patterns.get('attach_attempts', 0)}")
        print(f"   • Handovers: {call_patterns.get('handover_attempts', 0)}")
    
    # Validation Wireshark
    validation = results.get('validation', {})
    conformance = validation.get('conformance_check', {})
    print(f"\n✅ Validation:")
    print(f"   • Conformité ASN.1/PER: {'✓' if conformance.get('asn1_per_compliant') else '✗'}")
    print(f"   • Compatible Wireshark: {'✓' if metadata.get('wireshark_compatible') else '✗'}")
    
    print("\n" + "="*60)
    print("🎯 Analyse terminée avec succès!")
    print("="*60)


if __name__ == "__main__":
    sys.exit(main())
