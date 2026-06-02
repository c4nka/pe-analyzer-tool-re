# Research Notes / Araştırma Notları

> Module / Konu: Cryptographic Hash Analysis and Threat Intelligence Integration
> Date / Tarih: 2026-06-02

---

## What I'm Investigating / Araştırdığım Konu

Zararlı yazılımların (Malware) statik analizi sırasında, dosya bütünlüğünü doğrulamak ve harici tehdit istihbarat platformlarında (VirusTotal) arama yapabilmek için kriptografik hash algoritmalarının (MD5, SHA-256) Python ile bellek dostu (memory-efficient) bir şekilde nasıl hesaplanacağını araştırıyorum.

## Resources Found / Bulunan Kaynaklar

- [Python hashlib Documentation](https://docs.python.org/3/library/hashlib.html) — Büyük dosyaların RAM'i şişirmeden "chunk" (parça) mantığıyla nasıl okunacağını öğrendim.
- [VirusTotal API v3 Reference](https://developers.virustotal.com/reference/overview) — Dosya yüklemek yerine sadece hash sorgulaması yaparak API limitlerinin nasıl daha verimli kullanılacağını inceledim.

## Key Findings / Temel Bulgular

1. MD5 algoritması "collision" (çarpışma) zafiyetlerine sahip olduğu için adli bilişim standartlarında tek başına yeterli değildir; benzersiz kimliklendirme için mutlaka SHA-256 ile birlikte kullanılmalıdır.
2. Statik analizde zararlı yazılımı çalıştırmak çok riskli olduğu için, hash hesaplama işlemi "Sandboxing" (Kum havuzu) izolasyonu sağlayan Docker konteynerleri içinde yapılmalıdır.

## Dead Ends / Çıkmaz Sokaklar

Things I tried that didn't work and why:
- **Tüm dosyayı tek seferde okumak:** Büyük boyutlu bir PE dosyasını `file.read()` ile tek seferde değişkene atamaya çalıştım → Başarısız oldu çünkü bu yöntem büyük dosyalarda RAM tüketimini inanılmaz artırıyor. Yerine `file.read(4096)` şeklinde parçalı okuma mantığına geçildi.

## Questions Remaining / Kalan Sorular

- [ ] Polimorfik (kendi kodunu değiştiren) zararlı yazılımlar her kopyalamada farklı bir hash üretiyor. Bu durumda sadece hash tabanlı analiz yapmak yerine "Fuzzy Hashing" (Örn: SSDeep) araca nasıl entegre edilebilir?
- [x] VirusTotal API'sinden gelen JSON yanıtında gereksiz verileri filtreleyip sadece "detection" oranlarını nasıl ayıklarım?

## 50-Step Breakdown / 50 Adımlık Çözümleme (Özet)

1. Step 1: Kriptografik hash nedir ve tek yönlü fonksiyonlar nasıl çalışır?
2. Step 2: Python `hashlib` kütüphanesi PE dosyaları üzerinde nasıl kullanılır?
3. Step 3: Büyük dosyalar analiz edilirken "Memory Leak" (Bellek Sızıntısı) nasıl önlenir?
4. Step 4: Hesaplanmış bir SHA-256 değeri REST API üzerinden VirusTotal'e nasıl GET isteği olarak gönderilir?
5. Step 5: Dönen JSON verisi içindeki risk skorları Python sözlüklerine (dictionary) nasıl parse edilir?
