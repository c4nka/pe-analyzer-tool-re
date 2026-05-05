import argparse
import sys
import os
from analyzer.pe_parser import PEAnalyzer
from analyzer.utils import print_banner, print_section_results, print_imports, check_suspicious_apis

def main():
    # Argüman ayrıştırıcı (Daha profesyonel kullanıcı arayüzü ve hata yönetimi)
    parser = argparse.ArgumentParser(description="Gelişmiş PE (Portable Executable) Analiz Aracı")
    parser.add_argument("file", help="Analiz edilecek .exe veya .dll dosyasının yolu")
    
    # Kullanıcı eksik komut girerse argparse otomatik şık bir hata mesajı üretir
    args = parser.parse_args()
    target_file = args.file

    if not os.path.exists(target_file):
        print(f"[!] HATA: Belirtilen dosya bulunamadı -> {target_file}")
        sys.exit(1)

    print_banner(target_file)
    
    try:
        analyzer = PEAnalyzer(target_file)
        
        # 1. Temel Bilgiler
        basic_info = analyzer.get_basic_info()
        print("[+] TEMEL BİLGİLER")
        for key, value in basic_info.items():
            print(f"    {key:<15}: {value}")
        print("\n")
        
        # 2. Bölümler ve Entropi
        sections = analyzer.analyze_sections()
        print_section_results(sections)
        
        # 3. İçe Aktarmalar (Imports)
        imports = analyzer.get_imports()
        print_imports(imports)
        
        # 4. Şüpheli API (Güvenlik) Kontrolü
        check_suspicious_apis(imports)
        
    except ValueError as ve:
        print(f"[!] FORMAT HATASI: {ve}")
    except Exception as e:
        print(f"[!] BEKLENMEYEN HATA: Analiz sırasında bir sorun oluştu: {e}")

if __name__ == "__main__":
    main()
