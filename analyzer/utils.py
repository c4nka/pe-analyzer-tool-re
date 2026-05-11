import hashlib
import json

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
    
def check_suspicious_apis(imports_data: dict):
    """İçe aktarılan fonksiyonlar arasında bilinen zararlı/şüpheli API'leri arar."""
    # Zararlı yazılımların sık kullandığı (Anti-Debug, Injection, Keylogging) API listesi
    suspicious_apis = [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", # Anti-Debugging
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", # Process Injection
        "SetWindowsHookEx", "GetAsyncKeyState", # Keylogging
        "HttpSendRequestA", "InternetOpenA", "InternetConnectA" # C2 Bağlantısı / İndirme
    ]
    
    found_suspicious = []
    
    for dll, funcs in imports_data.items():
        for func in funcs:
            if func in suspicious_apis:
                found_suspicious.append(f"{func} (Kaynak: {dll})")
                
    print("[!] GÜVENLİK ANALİZİ: ŞÜPHELİ API TESPİTİ")
    if found_suspicious:
        print("    [UYARI] Dosya içerisinde zararlı yazılım davranışı gösterebilecek API'ler bulundu:")
        for alert in found_suspicious:
            print(f"      - {alert}")
    else:
        print("    [+] Bilinen kritik/şüpheli bir API çağrısı tespit edilmedi.")
    print("-" * 60 + "\n")

def calculate_hashes(file_path: str) -> dict:
    """Dosyanın MD5 ve SHA-256 özet (hash) değerlerini hesaplar."""
    hashes = {'MD5': hashlib.md5(), 'SHA-256': hashlib.sha256()}
    
    try:
        # Dosyayı chunk'lar halinde oku (Büyük dosyalar için RAM dostu yaklaşım)
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hashes['MD5'].update(chunk)
                hashes['SHA-256'].update(chunk)
                
        return {
            'MD5': hashes['MD5'].hexdigest(),
            'SHA-256': hashes['SHA-256'].hexdigest()
        }
    except Exception as e:
        return {'Hata': str(e)}

def print_hashes(hashes_data: dict):
    """Hesaplanan Hash değerlerini terminale şık bir şekilde basar."""
    print("[+] DOSYA KİMLİĞİ (HASH DEĞERLERİ)")
    for algo, h_val in hashes_data.items():
        print(f"    {algo:<10}: {h_val}")
    print("-" * 60 + "\n")

def export_report(data: dict, output_file: str):
    """Analiz sonuçlarını JSON veya TXT formatında dışa aktarır."""
    file_ext = output_file.split('.')[-1].lower()
    
    try:
        if file_ext == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
        else:
            # Varsayılan olarak TXT formatında şık bir rapor oluşturur
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"PE ANALİZ RAPORU\n{'='*20}\n")
                for key, value in data.items():
                    if isinstance(value, list):
                        f.write(f"\n[+] {key.upper()}\n")
                        for item in value:
                            f.write(f"  - {item}\n")
                    elif isinstance(value, dict):
                        f.write(f"\n[+] {key.upper()}\n")
                        for k, v in value.items():
                            f.write(f"  {k}: {v}\n")
                    else:
                        f.write(f"{key}: {value}\n")

        def print_ip_audit(metadata: dict):
    """Fikri Mülkiyet ve Lisans (IP Audit) verilerini terminale basar."""
    print("[+] FİKRİ MÜLKİYET VE LİSANS DENETİMİ (IP AUDIT)")
    
    if not metadata:
        print("    [!] Dosya içinde yasal meta veri bulunamadı.")
        print("    [?] Not: Korsan, manipüle edilmiş veya amatör yazılımlarda bu alan genellikle boştur.")
        print("-" * 60 + "\n")
        return
        
    # Hukuki uyuşmazlıklarda incelenen kritik alanlar
    legal_keys = [
        'CompanyName', 
        'LegalCopyright', 
        'LegalTrademarks', 
        'OriginalFilename', 
        'ProductName',
        'FileVersion'
    ]
    
    found_any = False
    for key in legal_keys:
        if key in metadata and metadata[key].strip():
            print(f"    {key:<18}: {metadata[key]}")
            found_any = True
            
    if not found_any:
        print("    [!] Yasal bağlayıcılığı olan standart anahtarlar (Telif/Marka vb.) bulunamadı.")
        
    print("-" * 60 + "\n")
        
        print(f"\n[OK] Rapor başarıyla kaydedildi: {output_file}")
    except Exception as e:
        print(f"\n[!] Rapor oluşturulurken hata: {e}")
