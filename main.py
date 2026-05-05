import sys
from analyzer.pe_parser import PEAnalyzer
from analyzer.utils import print_banner, print_section_results, print_imports

def main():
    if len(sys.argv) < 2:
        print("Kullanım: python main.py <analiz_edilecek_dosya.exe>")
        sys.exit(1)
        
    target_file = sys.argv[1]
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
        
    except ValueError as ve:
        print(f"[!] HATA: {ve}")
    except Exception as e:
        print(f"[!] Beklenmeyen bir hata oluştu: {e}")

if __name__ == "__main__":
    main()
