import os
import hashlib
import json
import requests

def print_banner(target_file):
    print("=" * 60)
    print(f"[*] PE ANALİZ BAŞLATILIYOR: {target_file}")
    print("=" * 60 + "\n")

def print_section_results(sections):
    print("[+] BÖLÜMLER (SECTIONS) VE ENTROPİ")
    for sec in sections:
        name = sec.get('Name', 'Bilinmiyor')
        v_addr = sec.get('VirtualAddress', '')
        v_size = sec.get('VirtualSize', '')
        entropy = sec.get('Entropy', 0.0)
        
        # Yüksek entropi paketlenmiş (packed) veya şifrelenmiş kodu işaret edebilir
        entropy_alert = " (DİKKAT: Yüksek Entropi - Paketlenmiş Olabilir!)" if entropy > 7.0 else ""
        
        print(f"    - {name:<8} | Adres: {v_addr:<10} | Boyut: {v_size:<10} | Entropi: {entropy:.4f}{entropy_alert}")
    print("\n")

def print_imports(imports):
    print("[+] KULLANILAN KÜTÜPHANELER (IMPORTS)")
    if not imports:
        print("    [!] İçe aktarılan kütüphane bulunamadı.")
    for dll, apis in imports.items():
        print(f"    - {dll}: {len(apis)} API kullanılıyor")
    print("\n")

def check_suspicious_apis(imports):
    print("[+] ŞÜPHELİ API KONTROLÜ (GÜVENLİK)")
    
    # Zararlı yazılımların sık kullandığı riskli fonksiyonlar
    suspicious_list = [
        'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 
        'ReadProcessMemory', 'LoadLibraryA', 'GetProcAddress', 
        'SetWindowsHookEx', 'RegSetValueEx', 'WinExec', 'ShellExecute',
        'IsDebuggerPresent', 'CryptAcquireContext'
    ]
    
    found_suspicious = []
    
    for dll, apis in imports.items():
        for api in apis:
            if api in suspicious_list:
                found_suspicious.append(f"{api} (Kaynak: {dll})")
                
    if found_suspicious:
        print("    [!] DİKKAT! Şüpheli fonksiyonlar tespit edildi:")
        for item in found_suspicious:
            print(f"        - {item}")
    else:
        print("    [OK] Bilinen şüpheli API çağrısı tespit edilmedi.")
    print("-" * 60 + "\n")

def calculate_hashes(file_path: str) -> dict:
    """Dosyanın MD5 ve SHA-256 özet (hash) değerlerini hesaplar."""
    hashes = {'MD5': hashlib.md5(), 'SHA-256': hashlib.sha256()}
    
    try:
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
        
        print(f"\n[OK] Rapor başarıyla kaydedildi: {output_file}")
    except Exception as e:
        print(f"\n[!] Rapor oluşturulurken hata: {e}")

def print_ip_audit(metadata: dict):
    """Fikri Mülkiyet ve Lisans (IP Audit) verilerini terminale basar."""
    print("[+] FİKRİ MÜLKİYET VE LİSANS DENETİMİ (IP AUDIT)")
    
    if not metadata:
        print("    [!] Dosya içinde yasal meta veri bulunamadı.")
        print("    [?] Not: Korsan, manipüle edilmiş veya amatör yazılımlarda bu alan genellikle boştur.")
        print("-" * 60 + "\n")
        return
        
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

def check_virustotal(file_hash: str, api_key: str) -> dict:
    """VirusTotal API v3 kullanarak dosyanın tehdit istihbaratını çeker."""
    print("[+] VIRUSTOTAL TEHDİT İSTİHBARATI (CANLI OSINT)")
    
    if not api_key:
        print("    [!] VirusTotal API anahtarı bulunamadı.")
        print("    [?] Bilgi: Canlı tarama için komut satırında --vt <API_KEY> parametresini kullanın.")
        print("-" * 60 + "\n")
        return {"Durum": "API Anahtarı Eksik"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        print("    [*] VirusTotal veri tabanı sorgulanıyor... Lütfen bekleyin.")
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            undetected = stats.get('undetected', 0)
            total = malicious + undetected + stats.get('harmless', 0) + stats.get('suspicious', 0)

            print(f"    [!] Küresel Tespit Oranı: {total} güvenlik motorundan {malicious} tanesi ZARARLI buldu!")

            if malicious > 0:
                print("    [!] DİKKAT: Bu dosya yüksek ihtimalle ZARARLI (Malware)!")
            else:
                print("    [OK] Dosya temiz görünüyor (Bilinen bir tehdit bulunamadı).")
            
            print("-" * 60 + "\n")
            return {"tespit_edilen": malicious, "toplam_tarama": total, "durum": "Basarili"}

        elif response.status_code == 404:
            print("    [?] Bu dosya daha önce VirusTotal'de hiç taranmamış.")
            print("    [!] DİKKAT: Bu bir Zero-Day (Sıfırıncı Gün) zararlısı veya tamamen yeni/özel bir dosya olabilir!")
            print("-" * 60 + "\n")
            return {"durum": "Dosya Bulunamadı (Zero-Day İhtimali)"}
        else:
            print(f"    [!] API Hatası: Yetkisiz erişim veya limit aşımı (Kod: {response.status_code})")
            print("-" * 60 + "\n")
            return {"durum": f"API Hatasi {response.status_code}"}

    except Exception as e:
        print(f"    [!] İnternet bağlantısı veya sorgu hatası: {e}")
        print("-" * 60 + "\n")
        return {"hata": str(e)}

def print_iocs(iocs: dict):
    """Tespit edilen IoC (Uzlaşma Göstergesi) verilerini terminale basar."""
    print("[+] GİZLİ TEHDİT GÖSTERGELERİ (IoC) VE AĞ BAĞLANTILARI")
    
    if not iocs:
        print("    [OK] Dosya içerisinde gömülü IP, URL veya E-posta adresine rastlanmadı.")
    else:
        for category, items in iocs.items():
            print(f"    [*] {category} ({len(items)} adet bulundu):")
            # Çok fazla çıktı olup terminali boğmaması için sadece ilk 5'ini göster
            for item in items[:5]:
                print(f"        - {item}")
            if len(items) > 5:
                print(f"        ... ve {len(items) - 5} adet daha (Tamamı JSON raporunda).")
                
    print("-" * 60 + "\n")

def calculate_and_print_risk_score(sections, imports, ip_metadata, iocs, vt_results) -> dict:
    """Toplanan tüm kanıtları heuristik olarak değerlendirip nihai bir risk skoru (0-100) üretir."""
    risk_score = 0
    reasons = []

    # 1. Entropi Analizi (Paketlenmiş/Şifrelenmiş Kod)
    high_entropy = any(sec.get('Entropy', 0.0) > 7.0 for sec in sections)
    if high_entropy:
        risk_score += 20
        reasons.append("Yüksek entropi tespit edildi (Kod paketlenmiş veya şifrelenmiş olabilir).")

    # 2. Şüpheli API Kontrolü
    suspicious_list = [
        'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 
        'ReadProcessMemory', 'LoadLibraryA', 'GetProcAddress', 
        'SetWindowsHookEx', 'RegSetValueEx', 'WinExec', 'ShellExecute'
    ]
    found_suspicious = sum(1 for apis in imports.values() for api in apis if api in suspicious_list)
    if found_suspicious > 0:
        added_score = min(found_suspicious * 5, 25) # Her şüpheli API 5 puan, maksimum 25 puan
        risk_score += added_score
        reasons.append(f"{found_suspicious} adet şüpheli API çağrısı bulundu (+{added_score} Puan).")

    # 3. Fikri Mülkiyet (IP Audit) Kontrolü
    legal_keys = ['CompanyName', 'LegalCopyright', 'OriginalFilename']
    has_legal_meta = any(key in ip_metadata and ip_metadata[key].strip() for key in legal_keys)
    if not has_legal_meta:
        risk_score += 15
        reasons.append("Yasal meta veriler eksik (Amatör, korsan veya manipüle edilmiş dosya).")

    # 4. IoC (Gizli Ağ Bağlantıları) Kontrolü
    has_iocs = any(len(items) > 0 for items in iocs.values())
    if has_iocs:
        risk_score += 10
        reasons.append("Dosya içerisine gömülü gizli IP/URL adresleri (IoC) tespit edildi.")

    # 5. VirusTotal Canlı İstihbarat Kontrolü
    if vt_results and vt_results.get("tespit_edilen", 0) > 0:
        risk_score += 50
        reasons.append(f"VirusTotal İstihbaratı: {vt_results['tespit_edilen']} motor dosyayı ZARARLI olarak işaretledi!")

    # Skoru 100 ile sınırla
    risk_score = min(risk_score, 100)

    # Karar Mekanizması
    if risk_score >= 70:
        verdict = "KRİTİK RİSK (YÜKSEK İHTİMALLE ZARARLI YAZILIM)"
        color_code = "\033[91m" # Kırmızı
    elif risk_score >= 40:
        verdict = "ŞÜPHELİ (DİKKATLİ İNCELENMELİ)"
        color_code = "\033[93m" # Sarı
    else:
        verdict = "DÜŞÜK RİSK (TEMİZ GÖRÜNÜYOR)"
        color_code = "\033[92m" # Yeşil
        
    reset_color = "\033[0m"

    print("=" * 60)
    print("[+] NİHAİ KARAR VE HEURİSTİK RİSK SKORU")
    print("=" * 60)
    print(f"    RİSK SKORU: {color_code}{risk_score} / 100{reset_color}")
    print(f"    KARAR:      {color_code}{verdict}{reset_color}\n")
    print("    Gerekçeler:")
    for reason in reasons:
        print(f"    - {reason}")
    if not reasons:
        print("    - Belirgin bir tehdit vektörü tespit edilmedi.")
    print("=" * 60 + "\n")

    return {
        "skor": risk_score,
        "karar": verdict,
        "gerekceler": reasons
    }
