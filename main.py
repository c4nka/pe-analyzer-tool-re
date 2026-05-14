import argparse
import sys
import os
from analyzer.pe_parser import PEAnalyzer
from analyzer.utils import (
    print_banner, 
    print_section_results, 
    print_imports, 
    check_suspicious_apis, 
    calculate_hashes, 
    print_hashes, 
    export_report,
    print_ip_audit,
    check_virustotal  # <-- YENİ EKLENDİ
)

def main():
    parser = argparse.ArgumentParser(description="Gelişmiş PE Analiz ve Tehdit İstihbarat Aracı")
    parser.add_argument("file", help="Analiz edilecek .exe veya .dll dosyasının yolu")
    parser.add_argument("--export", "-o", help="Sonuçları dosyaya kaydet (Örn: rapor.json)")
    parser.add_argument("--vt", help="Canlı tehdit istihbaratı için VirusTotal API Anahtarı") # <-- YENİ EKLENDİ
    
    args = parser.parse_args()
    target_file = args.file

    if not os.path.exists(target_file):
        print(f"[!] HATA: Belirtilen dosya bulunamadı -> {target_file}")
        sys.exit(1)

    print_banner(target_file)
    report_data = {"dosya_yolu": target_file}
    
    try:
        analyzer = PEAnalyzer(target_file)
        
        # 0. Dosya Hash Değerleri (Malware Kimliği)
        hashes = calculate_hashes(target_file)
        print_hashes(hashes)
        report_data["hash_degerleri"] = hashes
        
        # [YENİ] 0.5 VirusTotal Canlı İstihbarat
        if args.vt:
            # SHA-256 kullanarak VT veri tabanını sorgula
            vt_results = check_virustotal(hashes.get('SHA-256'), args.vt)
            report_data["virustotal_raporu"] = vt_results
        
        # 1. Temel Bilgiler
        basic_info = analyzer.get_basic_info()
        print("[+] TEMEL BİLGİLER")
        for key, value in basic_info.items():
            print(f"    {key:<15}: {value}")
        report_data["temel_bilgiler"] = basic_info
        print("\n")
        
        # 1.5 Fikri Mülkiyet ve Lisans Denetimi (IP Audit)
        ip_metadata = analyzer.get_ip_metadata()
        print_ip_audit(ip_metadata)
        report_data["fikri_mulkiyet_denetimi"] = ip_metadata
        
        # 2. Bölümler ve Entropi
        sections = analyzer.analyze_sections()
        print_section_results(sections)
        report_data["bolumler"] = sections
        
        # 3. İçe Aktarmalar (Imports)
        imports = analyzer.get_imports()
        print_imports(imports)
        report_data["kullanilan_kutuphaneler"] = list(imports.keys())
        
        # 4. Şüpheli API (Güvenlik) Kontrolü
        check_suspicious_apis(imports)
        
        # 5. Rapor Dışa Aktarma
        if args.export:
            export_report(report_data, args.export)
        
    except ValueError as ve:
        print(f"[!] FORMAT HATASI: {ve}")
    except Exception as e:
        print(f"[!] BEKLENMEYEN HATA: Analiz sırasında bir sorun oluştu: {e}")

if __name__ == "__main__":
    main()
