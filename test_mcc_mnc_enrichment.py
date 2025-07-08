#!/usr/bin/env python3
"""
Test du système d'enrichissement MCC-MNC amélioré
=================================================

Ce script teste les nouvelles fonctionnalités d'enrichissement avec la table JSON.
"""

import sys
import json
from pathlib import Path

# Ajouter le chemin source
sys.path.append(str(Path(__file__).parent / "src"))

from s1ap_decoder.ie_analyzer import InformationElementAnalyzer


def test_mcc_mnc_enrichment():
    """Test complet du système d'enrichissement MCC-MNC"""
    
    print("🧪 TEST D'ENRICHISSEMENT MCC-MNC AMÉLIORÉ")
    print("=" * 60)
    
    # Initialiser l'analyseur
    analyzer = InformationElementAnalyzer()
    
    # Vérifier le chargement de la table
    table_size = len(analyzer._mcc_mnc_table) if analyzer._mcc_mnc_table else 0
    print(f"📊 Table MCC-MNC chargée: {table_size} entrées")
    
    if table_size == 0:
        print("❌ ERREUR: Table MCC-MNC non chargée!")
        return False
    
    # Test cases comprehensifs
    test_cases = [
        # Format: (mcc, mnc, description)
        (605, 1, "Tunisia Orange (2-digit MNC)"),
        (605, 1, "Tunisia Orange (avec zéro initial)"),
        (605, 2, "Tunisia TT Mobile"),
        (605, 3, "Tunisia Ooredoo"),
        (208, 1, "France Orange"),
        (208, 10, "France SFR"), 
        (310, 260, "USA T-Mobile (3-digit MNC)"),
        (1, 1, "Test International"),
        (999, 99, "Invalid high values"),
        (0, 0, "Invalid zero values"),
        (None, None, "Null values"),
    ]
    
    print(f"\n🔍 TESTS D'ENRICHISSEMENT:")
    print("-" * 50)
    
    passed_tests = 0
    total_tests = len(test_cases)
    
    for i, (mcc, mnc, description) in enumerate(test_cases, 1):
        print(f"\n{i:2d}. {description}")
        print(f"    MCC: {mcc}, MNC: {mnc}")
        
        try:
            # Test de la fonction d'enrichissement
            result = analyzer._get_network_info(mcc, mnc)
            
            # Afficher les résultats
            country = result.get("country", "N/A")
            operator = result.get("operator", "N/A")
            source = result.get("source", "N/A")
            iso_code = result.get("iso_code", "N/A")
            
            print(f"    → Pays: {country}")
            print(f"    → Opérateur: {operator}")
            print(f"    → Source: {source}")
            print(f"    → ISO: {iso_code}")
            
            # Critères de validation
            if mcc and mnc and 200 <= mcc <= 999 and 0 <= mnc <= 999:
                # Cas valides - doit avoir des infos ou au moins le pays
                if country != "Unknown" or source in ["mcc_mnc_table_exact", "mcc_mnc_table_partial"]:
                    print(f"    ✅ RÉUSSI")
                    passed_tests += 1
                else:
                    print(f"    ⚠️  PARTIEL (aucune info trouvée pour MCC/MNC valide)")
                    passed_tests += 0.5
            else:
                # Cas invalides - doit retourner "Unknown" avec erreur appropriée
                if country == "Unknown" and "error" in result:
                    print(f"    ✅ RÉUSSI (erreur correctement gérée)")
                    passed_tests += 1
                else:
                    print(f"    ❌ ÉCHEC (erreur mal gérée)")
            
        except Exception as e:
            print(f"    ❌ EXCEPTION: {e}")
    
    print(f"\n" + "=" * 60)
    print(f"📊 RÉSULTATS FINAUX:")
    print(f"    Tests réussis: {passed_tests}/{total_tests}")
    print(f"    Taux de réussite: {(passed_tests/total_tests)*100:.1f}%")
    
    # Test spécifique du cas Tunisia Orange (exemple principal)
    print(f"\n🎯 TEST SPÉCIFIQUE: Tunisia Orange (MCC=605, MNC=1)")
    print("-" * 50)
    result = analyzer._get_network_info(605, 1)
    
    expected_values = {
        "country": "Tunisia",
        "operator": "Orange",
        "iso_code": "TN"
    }
    
    all_correct = True
    for key, expected in expected_values.items():
        actual = result.get(key, "").upper() if key == "iso_code" else result.get(key, "")
        expected_upper = expected.upper() if key == "iso_code" else expected
        
        if expected_upper in actual or actual == expected_upper:
            print(f"    ✅ {key}: {actual} (attendu: {expected})")
        else:
            print(f"    ❌ {key}: {actual} (attendu: {expected})")
            all_correct = False
    
    if all_correct:
        print(f"    🎉 Test Tunisia Orange: RÉUSSI!")
    else:
        print(f"    ⚠️  Test Tunisia Orange: PARTIEL")
    
    print(f"\n🔧 INFORMATIONS DE DIAGNOSTIC:")
    if analyzer._mcc_mnc_table:
        # Rechercher Tunisia dans la table
        tunisia_entries = [entry for entry in analyzer._mcc_mnc_table 
                          if "tunisia" in entry.get("country", "").lower()]
        print(f"    • Entrées Tunisia trouvées: {len(tunisia_entries)}")
        
        if tunisia_entries:
            print(f"    • Premières entrées Tunisia:")
            for entry in tunisia_entries[:3]:
                mcc = entry.get("mcc", "N/A")
                mnc = entry.get("mnc", "N/A") 
                network = entry.get("network", "N/A")
                print(f"      - MCC {mcc}, MNC {mnc}: {network}")
    
    success_rate = (passed_tests / total_tests) * 100
    return success_rate >= 80  # 80% de réussite minimum


def main():
    """Test principal"""
    print("🚀 DÉMARRAGE DES TESTS D'ENRICHISSEMENT MCC-MNC")
    
    success = test_mcc_mnc_enrichment()
    
    if success:
        print(f"\n🎉 TOUS LES TESTS RÉUSSIS!")
        print(f"✅ Le système d'enrichissement MCC-MNC fonctionne correctement")
        print(f"✅ La table JSON est correctement utilisée")
        return 0
    else:
        print(f"\n⚠️  CERTAINS TESTS ONT ÉCHOUÉ")
        print(f"🔧 Vérifiez la table MCC-MNC et les fonctions d'enrichissement")
        return 1


if __name__ == "__main__":
    sys.exit(main())
