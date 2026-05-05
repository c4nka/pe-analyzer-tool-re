def print_banner(file_name: str):
    """Terminalde analizin başladığını gösteren şık bir karşılama basar."""
    print("\n" + "="*60)
    print(f"[*] STATİK PE ANALİZİ BAŞLATILIYOR: {file_name}")
    print("="*60 + "\n")

def print_section_results(sections: list):
    """Bölüm analiz sonuçlarını tablo formatında terminale yazdırır."""
    print("[+] BÖLÜMLER VE ENTROPİ DEĞERLERİ")
    print(f"{'İsim':<10} | {'Sanal Boyut':<12} | {'Entropi':<10} | {'Durum'}")
    print("-" * 60)
    for sec in sections:
        print(f"{sec['İsim']:<10} | {sec['Sanal Boyut']:<12} | {sec['Entropi']:<10} | {sec['Durum']}")
    print("-" * 60 + "\n")
