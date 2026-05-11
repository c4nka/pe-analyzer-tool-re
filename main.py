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
    print_ip_audit
)

def main():
    # Argüman ayrıştırıcı (Daha profesyonel kullanıcı arayüzü ve hata yönetimi)
    parser = argparse.ArgumentParser(description="Gelişmiş PE (Portable Executable) Analiz Aracı")
    parser.add_argument("file", help="Analiz edilecek .exe veya .dll dosyasının yolu")
    parser.add_argument("--export", "-o", help="Sonuçları dosyaya kaydet (Örn: rapor.json veya rapor.txt)")
    
    # Kullanıcı eksik komut girerse argparse otomatik şık bir hata mesajı üretir
    args = parser.parse_args()
    target_file = args.file

    if not os.path.exists(target_file):
        print(f"[!] HATA: Belirtilen dosya bulunamadı -> {target_file}")
        sys.exit(1)

    print_banner(target_file)
    
    # Raporlama için tüm analiz verilerini toplayacağımız ana sözlük
    report_data = {"dosya_yolu": target_file}
    
    try:
        analyzer = PEAnalyzer(target_file)
        
        # 0. Dosya Hash Değerleri (Malware Kimliği)
        hashes = calculate_hashes(target_file)
        print_hashes(hashes)
        report_data["hash_değerleri"] = hashes
        
        # 1. Temel Bilgiler
        basic_info = analyzer.get_basic_info()
        print("[+] TEMEL BİLGİLER")
        for key, value in basic_info.items():
            print(f"    {key:<15}: {value}")
        report_data["temel_bilgiler"] = basic_info
        print("\n")
        
        # 1.5 Fikri Mülkiyet ve Lisans Denetimi (IP Audit)
        # Hukuki süreçlerde kritik olan Telif Hakkı ve Şirket bilgilerini çıkarır
        ip_metadata = analyzer.get_ip_metadata()
        print_ip_audit(ip_metadata)
        report_data["fikri_mülkiyet_denetimi"] = ip_metadata
        
        # 2. Bölümler ve Entropi
        sections = analyzer.analyze_sections()
        print_section_results(sections)
        report_data["bölümler"] = sections
        
        # 3. İçe Aktarmalar (Imports)
        imports = analyzer.get_imports()
        print_imports(imports)
        report_data["kullanılan_kütüphaneler"] = list(imports.keys())
        
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
