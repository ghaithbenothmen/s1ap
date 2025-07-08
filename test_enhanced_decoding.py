#!/usr/bin/env python3
"""
Test Enhanced S1AP IE Decoding
===============================

Script de test pour valider le décodage amélioré des IEs S1AP complexes,
en particulier TAIList et autres types composés.
"""

import sys
import json
from pathlib import Path

# Import du décodeur S1AP
sys.path.append(str(Path(__file__).parent / "src"))
from s1ap_decoder.core import S1APDecoder

def test_enhanced_decoding():
    """Test du décodage amélioré des IEs composés"""
    
    print("="*70)
    print("🧪 TEST DU DÉCODAGE AMÉLIORÉ DES IEs S1AP COMPOSÉS")
    print("="*70)
    
    # Initialiser l'analyseur
    analyzer = S1APDecoder()
    
    # Analyser le fichier PCAP
    pcap_file = "s1CP.pcap"
    if not Path(pcap_file).exists():
        print(f"❌ Fichier PCAP '{pcap_file}' non trouvé")
        return
    
    print(f"📁 Analyse du fichier : {pcap_file}")
    
    # Effectuer l'analyse complète
    results = analyzer.analyze_pcap(pcap_file, limit_packets=10)
    
    print(f"\n📊 Messages S1AP analysés : {results['summary']['s1ap_messages']}")
    print(f"🔧 Procédures uniques : {results['summary']['unique_procedures']}")
    
    # Rechercher et analyser les IEs composés
    composite_ies_found = {}
    
    for message in results.get('messages', []):
        for ie in message.get('ies', []):
            ie_name = ie.get('name', 'Unknown')
            analyzed = ie.get('analyzed_content', {})
            
            # Identifier les IEs composés
            if analyzed.get('type') in ['sequence', 'sequence_of']:
                if ie_name not in composite_ies_found:
                    composite_ies_found[ie_name] = []
                composite_ies_found[ie_name].append({
                    'packet': message['packet_number'],
                    'procedure': message['procedure']['name'],
                    'analysis': analyzed
                })
    
    # Afficher les résultats des IEs composés
    print(f"\n🧬 IEs COMPOSÉS TROUVÉS :")
    print("-" * 50)
    
    for ie_name, instances in composite_ies_found.items():
        print(f"\n📋 {ie_name} ({len(instances)} instance(s))")
        
        for i, instance in enumerate(instances, 1):
            print(f"  └─ Instance {i} - Paquet {instance['packet']} ({instance['procedure']})")
            analysis = instance['analysis']
            
            if ie_name == "TAIList":
                print_tai_list_analysis(analysis)
            elif ie_name == "EUTRAN-CGI":
                print_eutran_cgi_analysis(analysis)
            else:
                print_generic_analysis(analysis)
    
    # Statistiques de décodage
    print(f"\n📈 STATISTIQUES DE DÉCODAGE :")
    print("-" * 40)
    total_composites = sum(len(instances) for instances in composite_ies_found.values())
    print(f"• Total IEs composés : {total_composites}")
    print(f"• Types uniques : {len(composite_ies_found)}")
    
    # Validation Wireshark
    print(f"\n✅ VALIDATION WIRESHARK :")
    print("-" * 30)
    validation = results.get('validation', {})
    conformance = validation.get('conformance_check', {})
    print(f"• Conformité ASN.1/PER : {'✓' if conformance.get('asn1_per_compliant') else '✗'}")
    print(f"• Compatible Wireshark : {'✓' if results['metadata'].get('wireshark_compatible') else '✗'}")
    
    print(f"\n🎯 Test terminé avec succès !")


def print_tai_list_analysis(analysis):
    """Affiche l'analyse détaillée d'un TAIList"""
    tai_items = analysis.get('tai_items', [])
    
    for j, tai in enumerate(tai_items, 1):
        plmn = tai.get('plmn_identity', {})
        network = tai.get('network_info', {})
        
        print(f"    🌍 TAI {j}:")
        if not plmn.get('error'):
            print(f"      • PLMN : {plmn.get('readable', 'N/A')} (MCC={plmn.get('mcc')}, MNC={plmn.get('mnc')})")
            print(f"      • Pays : {network.get('country', 'Inconnu')}")
            print(f"      • Opérateur : {network.get('operator', 'Inconnu')}")
            print(f"      • TAC : {tai.get('tracking_area_code')} (0x{tai.get('tac_hex', '')})")
        else:
            print(f"      • Erreur : {plmn.get('error')}")


def print_eutran_cgi_analysis(analysis):
    """Affiche l'analyse détaillée d'un E-UTRAN CGI"""
    if analysis.get('type') == 'sequence':
        print(f"    📡 E-UTRAN CGI : {analysis.get('hex_value', 'N/A')}")
    else:
        plmn = analysis.get('plmn_identity', {})
        if not plmn.get('error'):
            print(f"    📡 PLMN : {plmn.get('readable', 'N/A')}")
            print(f"    📡 eNB ID : {analysis.get('enb_id', 'N/A')}")
            print(f"    📡 Cell ID : {analysis.get('cell_id', 'N/A')}")


def print_generic_analysis(analysis):
    """Affiche l'analyse générique d'un IE composé"""
    print(f"    🔍 Type : {analysis.get('type', 'N/A')}")
    print(f"    🔍 Taille : {analysis.get('length', 0)} octets")
    if analysis.get('analysis_note'):
        print(f"    🔍 Note : {analysis.get('analysis_note')}")


if __name__ == "__main__":
    test_enhanced_decoding()
