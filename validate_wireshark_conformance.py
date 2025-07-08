#!/usr/bin/env python3
"""
Validation du Décodage Amélioré - Conformité Wireshark
======================================================

Script de validation finale pour vérifier la conformité 100% avec Wireshark
pour le décodage des IEs composés TAIList et EUTRAN-CGI.
"""

import sys
import json
from pathlib import Path

# Import du décodeur S1AP
sys.path.append(str(Path(__file__).parent / "src"))
from s1ap_decoder.core import S1APDecoder

def validate_wireshark_conformance():
    """Validation de la conformité avec Wireshark"""
    
    print("="*80)
    print("🔍 VALIDATION CONFORMITÉ WIRESHARK - DÉCODAGE IEs COMPOSÉS")
    print("="*80)
    
    # Analyser le fichier PCAP
    analyzer = S1APDecoder()
    results = analyzer.analyze_pcap("s1CP.pcap", limit_packets=5)
    
    # Extraire les données du paquet 2 (EUTRAN-CGI) et paquet 4 (TAIList)
    validation_results = {"passed": 0, "failed": 0, "tests": []}
    
    for message in results.get('messages', []):
        packet_num = message['packet_number']
        
        for ie in message.get('ies', []):
            ie_name = ie.get('name')
            analyzed = ie.get('analyzed_content', {})
            
            # Test EUTRAN-CGI (Paquet 2)
            if packet_num == 2 and ie_name == "EUTRAN-CGI":
                test_eutran_cgi(ie, analyzed, validation_results)
                
            # Test TAIList (Paquet 4)  
            elif packet_num == 4 and ie_name == "TAIList":
                test_tai_list(ie, analyzed, validation_results)
    
    # Afficher les résultats
    print(f"\n📊 RÉSULTATS DE VALIDATION :")
    print(f"✅ Tests réussis : {validation_results['passed']}")
    print(f"❌ Tests échoués : {validation_results['failed']}")
    print(f"🎯 Taux de réussite : {validation_results['passed']/(validation_results['passed']+validation_results['failed'])*100:.1f}%")
    
    # Détail des tests
    print(f"\n📋 DÉTAIL DES TESTS :")
    for test in validation_results['tests']:
        status = "✅" if test['passed'] else "❌"
        print(f"{status} {test['name']}: {test['result']}")
    
    return validation_results['failed'] == 0


def test_eutran_cgi(ie, analyzed, validation_results):
    """Test EUTRAN-CGI conformité Wireshark"""
    
    tests = [
        {
            'name': 'EUTRAN-CGI Hex Value',
            'expected': "0006f510003a3040",
            'actual': ie.get('value_hex'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'PLMN Identity Hex', 
            'expected': "06f510",
            'actual': analyzed.get('plmn_identity', {}).get('plmn_hex'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'MCC (Tunisia)',
            'expected': 605,
            'actual': analyzed.get('plmn_identity', {}).get('mcc'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'MNC (Orange)',
            'expected': 1,
            'actual': analyzed.get('plmn_identity', {}).get('mnc'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'Network Country',
            'expected': "Tunisia",
            'actual': analyzed.get('network_info', {}).get('country'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'Network Operator',
            'expected': "Orange",
            'actual': analyzed.get('network_info', {}).get('operator'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'Cell Identity',
            'expected': 3813440,
            'actual': analyzed.get('cell_identity'),
            'test': lambda e, a: e == a
        }
    ]
    
    for test in tests:
        passed = test['test'](test['expected'], test['actual'])
        validation_results['tests'].append({
            'name': f"EUTRAN-CGI - {test['name']}",
            'passed': passed,
            'result': f"{test['actual']} (attendu: {test['expected']})" if passed else f"❌ {test['actual']} ≠ {test['expected']}"
        })
        
        if passed:
            validation_results['passed'] += 1
        else:
            validation_results['failed'] += 1


def test_tai_list(ie, analyzed, validation_results):
    """Test TAIList conformité Wireshark"""
    
    tai_items = analyzed.get('tai_items', [])
    if not tai_items:
        validation_results['tests'].append({
            'name': 'TAIList - Items Present',
            'passed': False,
            'result': "❌ Aucun TAI trouvé"
        })
        validation_results['failed'] += 1
        return
    
    tai = tai_items[0]
    plmn = tai.get('plmn_identity', {})
    
    tests = [
        {
            'name': 'TAIList Hex Value',
            'expected': "00002f40060006f510d932",
            'actual': ie.get('value_hex'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'TAI PLMN Hex',
            'expected': "06f510", 
            'actual': plmn.get('plmn_hex'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'TAI MCC (Tunisia)',
            'expected': 605,
            'actual': plmn.get('mcc'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'TAI MNC (Orange)',
            'expected': 1,
            'actual': plmn.get('mnc'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'TAC Value',
            'expected': 55602,
            'actual': tai.get('tracking_area_code'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'TAC Hex',
            'expected': "d932",
            'actual': tai.get('tac_hex'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'Network Country',
            'expected': "Tunisia",
            'actual': tai.get('network_info', {}).get('country'),
            'test': lambda e, a: e == a
        },
        {
            'name': 'Network Operator',
            'expected': "Orange",
            'actual': tai.get('network_info', {}).get('operator'),
            'test': lambda e, a: e == a
        }
    ]
    
    for test in tests:
        passed = test['test'](test['expected'], test['actual'])
        validation_results['tests'].append({
            'name': f"TAIList - {test['name']}",
            'passed': passed,
            'result': f"{test['actual']} (attendu: {test['expected']})" if passed else f"❌ {test['actual']} ≠ {test['expected']}"
        })
        
        if passed:
            validation_results['passed'] += 1
        else:
            validation_results['failed'] += 1


if __name__ == "__main__":
    success = validate_wireshark_conformance()
    
    if success:
        print(f"\n🎉 VALIDATION RÉUSSIE - Conformité 100% avec Wireshark !")
        print(f"✅ Tous les décodages sont corrects et conformes")
    else:
        print(f"\n⚠️ Des différences ont été détectées")
        print(f"❌ Vérifier les tests échoués ci-dessus")
    
    sys.exit(0 if success else 1)
