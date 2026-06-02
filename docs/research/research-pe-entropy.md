# Research Notes / Araştırma Notları

> Module / Konu: Statik Analizin Teknik Derinliği: PE Başlık Manipülasyonları ve Shannon Entropisi
> Date / Tarih: 2026-06-02

---

## What I'm Investigating / Araştırdığım Konu

Geliştirdiğim PE Analyzer aracının teknik teorisini temellendirmek amacıyla, Windows Portable Executable (PE) formatının mimarisini ve zararlı yazılım geliştiricilerinin antivirüs (AV) çözümlerini atlatmak için bu başlıkları (Headers) nasıl manipüle ettiğini araştırıyorum. Aynı zamanda, aracın kullandığı "Shannon Entropisi" (Shannon Entropy) algoritmasının, sıkıştırılmış (packed) veya şifrelenmiş (obfuscated) zararlı kodları matematiksel olarak nasıl tespit ettiğini inceliyorum.

## Resources Found / Bulunan Kaynaklar

- [Microsoft PE Format Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — DOS Başlığı (`IMAGE_DOS_HEADER`), NT Başlıkları (`IMAGE_NT_HEADERS`) ve Bölüm Tablolarının (`Section Table`) bellek haritalamasındaki (Memory Mapping) resmi yapısı.
- [A Mathematical Theory of Communication (Claude Shannon, 1948)](https://people.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf) — Bilgi teorisi ve verideki rastgelelik/belirsizlik miktarının ölçümü.
- [SANS Institute: Malware Forensics](https://www.sans.org/) — UPX, Themida gibi paketleyicilerin (packers) PE bölümlerini (sections) nasıl değiştirdiğine dair vaka analizleri.

## Key Findings / Temel Bulgular

1. **PE Başlık Manipülasyonu:** Zararlı yazılımlar genellikle `DOS Stub` ("This program cannot be run in DOS mode" yazan kısım) içine kendi zararlı kod parçacıklarını veya şifreleme anahtarlarını saklayarak statik imza tabanlı (Signature-based) tespitleri atlatmaya (Evasion) çalışırlar. Aracımızın `pefile` kütüphanesi kullanarak doğrudan `e_lfanew` offset'ine (NT Başlıklarının başlangıcına) gitmesi bu manipülasyonu bypass etmemizi sağlar.
2. **Shannon Entropisinin Matematiği:** Entropi, bir veri kümesindeki baytların rastgelelik derecesini 0 ile 8 arasında bir ölçekte ölçer. Temiz bir Windows `.exe` dosyasında kod bölümü (`.text`) genellikle İngilizce kelimeler ve düzenli assembly komutları içerdiğinden entropisi 4.0 - 5.5 arasındadır. Ancak dosya UPX ile paketlenmişse (sıkıştırılmışsa) veya AES ile şifrelenmişse, bayt dizilimi tamamen rastgele bir hal alır ve entropi değeri **7.0'ın üzerine** çıkar.
3. **Anormal Bölüm İsimleri (Section Names):** Standart derleyiciler (Visual Studio, GCC) `.text`, `.data`, `.rdata` gibi standart bölümler oluşturur. Zararlı yazılımlarda `.upx0`, `.vmp0` gibi bölüm isimlerinin görülmesi doğrudan heuristik risk skorunu artırmalıdır.

## Dead Ends / Çıkmaz Sokaklar

- **Tüm Dosyanın Entropisini Tek Seferde Hesaplamak:** İlk denemelerimde dosyanın tamamını okuyup tek bir entropi skoru ürettim.
  - *Sonuç:* Başarısız/Yetersiz oldu. Dosyanın içine gömülmüş büyük ve zararsız bir resim (Bitmap/Icon) dosyanın genel entropisini etkiliyordu.
  - *Çözüm:* Kod mimarisini değiştirerek entropi hesaplamasını dosyanın tamamına değil, **PE Bölümlerine (Section-based Entropy)** indirgedim. Artık aracımız sadece `.text` (çalıştırılabilir kod) bölümünün entropisine bakarak çok daha keskin kararlar veriyor.

## Questions Remaining / Kalan Sorular

- [x] Sıkıştırılmamış ancak "Polimorfik" (kendi kodunu sürekli değiştiren) bir zararlı yazılım, standart bir entropi hesaplamasını aşabilir mi? *(Cevap: Aşabilir. Polimorfik kodlar şifreleme kullanmadan sadece Assembly komutlarının yerini değiştirdiği için entropiyi düşük tutabilirler. Bu yüzden aracımıza "Şüpheli API (Imports)" tespit modülünü de ekledik).*
- [ ] Orijinal (orijinal Entry Point - OEP) bellek adresini, araç çalışmadan (statik olarak) tam anlamıyla tespit etmenin matematiksel olarak kesin bir yolu var mıdır?

## 50-Step Breakdown / 50 Adımlık Çözümleme (Özet: Analiz Motorunun Arka Plan İşlemleri)

1. Adım: Motor hedef dosyayı okur ve ilk iki baytın `4D 5A` (MZ - Mark Zbikowski) olup olmadığını doğrular (Magic Number kontrolü).
2. Adım: `e_lfanew` işaretçisi okunur ve PE başlığının (Signature `50 45 00 00`) başladığı offset bulunur.
3. Adım: İthal edilen API tablosu (Import Address Table - IAT) parse edilir. `VirtualAlloc`, `CreateRemoteThread` gibi "Process Injection" potansiyeli olan fonksiyonlar aranır.
4. Adım: Dosyanın bölümleri (Sections) döngüye sokulur. Her bölümün ham (raw) verisi üzerinde Claude Shannon'ın Entropi formülü ($H(X) = -\sum P(x_i) \log_2 P(x_i)$) uygulanır.
5. Adım: Eğer `.text` bölümünün entropisi 7.2'den büyükse, heuristik motora `PACKED_OR_OBFUSCATED` sinyali gönderilir ve risk skoru +40 puan artırılır.
