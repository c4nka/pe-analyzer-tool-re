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

def print_imports(imports_data: dict):
    """İçe aktarılan DLL ve fonksiyonları okunabilir formatta yazdırır."""
    print("[+] KULLANILAN KÜTÜPHANELER VE FONKSİYONLAR (IMPORTS)")
    if not imports_data:
        print("    [!] İçe aktarılan fonksiyon bulunamadı (Dosya gizlenmiş olabilir).")
        print("-" * 60 + "\n")
        return
        
    for dll, funcs in imports_data.items():
        print(f"    -> {dll}")
        # Ekranı boğmamak için her DLL'in sadece ilk 3 fonksiyonunu gösterelim
        for i, func in enumerate(funcs):
            if i < 3:
                print(f"         - {func}")
        if len(funcs) > 3:
            print(f"         - ... (+ {len(funcs) - 3} fonksiyon daha)")
            
    print("-" * 60 + "\n")
