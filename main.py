import sys
from analyzer.pe_parser import PEAnalyzer
from analyzer.utils import print_banner, print_section_results

def main():
    # Komut satırı argümanı kontrolü
    if len(sys.argv) < 2:
        print("Kullanım: python main.py <analiz_edilecek_dosya.exe>")
        sys.exit(1)
        
    target_file = sys.argv[1]
    print_banner(target_file)
    
    try:
        # Modüler mimariyi kullanarak nesne oluşturma
        analyzer = PEAnalyzer(target_file)
        
        # Temel bilgileri al ve yazdır
        basic_info = analyzer.get_basic_info()
        print("[+] TEMEL BİLGİLER")
        for key, value in basic_info.items():
            print(f"    {key:<15}: {value}")
        print("\n")
        
        # Bölümleri analiz et ve yazdır
        sections = analyzer.analyze_sections()
        print_section_results(sections)
        
    except ValueError as ve:
        print(f"[!] HATA: {ve}")
    except Exception as e:
        print(f"[!] Beklenmeyen bir hata oluştu: {e}")

if __name__ == "__main__":
    main()
