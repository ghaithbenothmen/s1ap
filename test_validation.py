#!/usr/bin/env python3
"""
Test rapide du S1AP Analyzer
=============================

Script de démonstration pour tester rapidement le décodeur S1AP.
"""

import sys
import json
from pathlib import Path

# Ajouter le chemin vers le décodeur
sys.path.append(str(Path(__file__).parent / "src"))

def test_quick_analysis():
    """Test rapide d'analyse S1AP"""
    from s1ap_decoder.core import S1APDecoder
    
    print("🧪 Test du S1AP Analyzer")
    print("=" * 50)
    
    # Vérifier que le fichier PCAP existe
    pcap_file = "s1CP.pcap"
    if not Path(pcap_file).exists():
        print(f"❌ Fichier PCAP manquant: {pcap_file}")
        return False
    
    try:
        # Initialiser l'analyseur
        decoder = S1APDecoder()
        
        # Analyser les 3 premiers messages S1AP
        print(f"🔍 Analyse des 3 premiers messages S1AP de {pcap_file}")
        results = decoder.analyze_pcap(pcap_file, limit_packets=3)
        
        # Afficher les résultats
        summary = results['summary']
        print(f"\n📊 Résultats:")
        print(f"   • Messages S1AP trouvés: {summary['s1ap_messages']}")
        print(f"   • Procédures uniques: {summary['unique_procedures']}")
        print(f"   • Sessions UE: {summary['unique_sessions']}")
        print(f"   • Durée d'analyse: {summary['analysis_duration']:.3f}s")
        
        # Afficher les procédures
        print(f"\n🔄 Procédures détectées:")
        for proc_name, info in results['procedures'].items():
            print(f"   • {proc_name}: {info['count']} messages")
        
        # Afficher les sessions UE
        print(f"\n👥 Sessions UE:")
        for session_id, session in results['sessions'].items():
            mme_id = session['mme_ue_s1ap_id']
            enb_id = session['enb_ue_s1ap_id']
            msg_count = session['message_count']
            print(f"   • MME-ID: {mme_id}, eNB-ID: {enb_id} ({msg_count} msg)")
        
        # Validation Wireshark
        conformance = results['validation']['conformance_check']
        print(f"\n✅ Validation:")
        print(f"   • Conformité ASN.1/PER: {'✓' if conformance['asn1_per_compliant'] else '✗'}")
        print(f"   • Compatible Wireshark: {'✓' if results['metadata']['wireshark_compatible'] else '✗'}")
        
        print(f"\n🎉 Test réussi ! Le décodeur fonctionne correctement.")
        return True
        
    except Exception as e:
        print(f"❌ Erreur pendant le test: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_specific_values():
    """Test les valeurs spécifiques par rapport à Wireshark"""
    print(f"\n🔬 Validation des valeurs critiques (comparaison Wireshark)")
    print("=" * 60)
    
    # Valeurs attendues d'après Wireshark pour le paquet 2
    expected_values = {
        "packet_2": {
            "mme_ue_s1ap_id": 147254901,
            "enb_ue_s1ap_id": 673401,
            "procedure": "CellTrafficTrace"
        }
    }
    
    try:
        from s1ap_decoder.core import S1APDecoder
        decoder = S1APDecoder()
        results = decoder.analyze_pcap("s1CP.pcap", limit_packets=5)
        
        # Vérifier les valeurs du premier message (paquet 2 dans le PCAP)
        if results['messages']:
            first_msg = results['messages'][0]
            
            # Extraire les IDs de session
            mme_id = None
            enb_id = None
            for ie in first_msg['ies']:
                if ie['id'] == 0:  # MME-UE-S1AP-ID
                    mme_id = ie['analyzed_content']['value']
                elif ie['id'] == 8:  # eNB-UE-S1AP-ID
                    enb_id = ie['analyzed_content']['value']
            
            # Comparer avec les valeurs attendues
            expected = expected_values["packet_2"]
            print(f"📋 Comparaison Paquet 2 (CellTrafficTrace):")
            
            # MME-UE-S1AP-ID
            mme_status = "✓" if mme_id == expected["mme_ue_s1ap_id"] else "✗"
            print(f"   • MME-UE-S1AP-ID: {mme_id} (attendu: {expected['mme_ue_s1ap_id']}) {mme_status}")
            
            # eNB-UE-S1AP-ID  
            enb_status = "✓" if enb_id == expected["enb_ue_s1ap_id"] else "✗"
            print(f"   • eNB-UE-S1AP-ID: {enb_id} (attendu: {expected['enb_ue_s1ap_id']}) {enb_status}")
            
            # Procédure
            proc_status = "✓" if first_msg['procedure']['name'] == expected["procedure"] else "✗"
            print(f"   • Procédure: {first_msg['procedure']['name']} (attendu: {expected['procedure']}) {proc_status}")
            
            # Résultat global
            all_good = (mme_id == expected["mme_ue_s1ap_id"] and 
                       enb_id == expected["enb_ue_s1ap_id"] and 
                       first_msg['procedure']['name'] == expected["procedure"])
            
            if all_good:
                print(f"\n🎯 Validation Wireshark: PARFAITE CONFORMITÉ ✅")
                print(f"   Les valeurs décodées correspondent exactement à Wireshark!")
            else:
                print(f"\n❌ Validation Wireshark: ÉCHEC")
                print(f"   Des différences détectées avec les valeurs Wireshark")
                
            return all_good
        else:
            print("❌ Aucun message trouvé")
            return False
            
    except Exception as e:
        print(f"❌ Erreur de validation: {e}")
        return False

if __name__ == "__main__":
    print("🚀 S1AP Analyzer - Test de Validation")
    print("=" * 60)
    
    # Test général
    success1 = test_quick_analysis()
    
    # Test de validation Wireshark
    success2 = test_specific_values()
    
    print("\n" + "=" * 60)
    if success1 and success2:
        print("🎉 TOUS LES TESTS RÉUSSIS!")
        print("   Le décodeur S1AP est prêt à l'emploi!")
        print("\n💡 Utilisez maintenant:")
        print("   python s1ap_analyzer.py s1CP.pcap --limit 10")
    else:
        print("❌ CERTAINS TESTS ONT ÉCHOUÉ")
        print("   Vérifiez la configuration du décodeur")
    print("=" * 60)
