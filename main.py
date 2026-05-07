import argparse
import sys
import os
from analyzer.pe_parser import PEAnalyzer
from analyzer.utils import (
    print_banner, print_section_results, print_imports, 
    check_suspicious_apis, calculate_hashes, print_hashes, export_report
)

def main():
    parser = argparse.ArgumentParser(description="Gelişmiş PE Analiz Aracı")
    parser.add_argument("file", help="Analiz edilecek dosya yolu")
    parser.add_argument("--export", "-o", help="Sonuçları dosyaya kaydet (örn: rapor.json veya rapor.txt)")
    
    args = parser.parse_args()
    target_file = args.file

    if not os.path.exists(target_file):
        print(f"[!] HATA: Dosya bulunamadı -> {target_file}")
        sys.exit(1)

    print_banner(target_file)
    
    # Raporlama için tüm verileri toplayacağımız sözlük
    report_data = {"dosya_yolu": target_file}
    
    try:
        analyzer = PEAnalyzer(target_file)
        
        # 0. Hash Değerleri
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
        
        # 2. Bölümler ve Entropi
        sections = analyzer.analyze_sections()
        print_section_results(sections)
        report_data["bölümler"] = sections
        
        # 3. İçe Aktarmalar (Imports)
        imports = analyzer.get_imports()
        print_imports(imports)
        report_data["kütüphaneler"] = list(imports.keys())
        
        # 4. Güvenlik Analizi
        # Bu fonksiyonu çıktıları da döndürecek şekilde düzenleyebiliriz ama şimdilik konsola basıyor
        check_suspicious_apis(imports)
        
        # 5. Rapor Dışa Aktarma
        if args.export:
            export_report(report_data, args.export)
            
    except Exception as e:
        print(f"[!] HATA: {e}")

if __name__ == "__main__":
    main()
