# Mimari ve Tasarım (Architecture)

Bu proje, "Separation of Concerns" (Sorumlulukların Ayrılığı) prensibine sadık kalınarak modüler bir yapıda tasarlanmıştır. Tüm kodlar tek bir dosyaya yığılmak yerine, mantıksal modüllere bölünmüştür.

## Modüller

* **`main.py`**: Uygulamanın giriş noktasıdır (Entry Point). Komut satırı argümanlarını (`argparse` ile) yakalar ve kullanıcıya şık bir terminal arayüzü sunar.
* **`analyzer/pe_parser.py`**: `pefile` kütüphanesini sarmalayan ana sınıftır. PE dosyasını okur, başlık bilgilerini ayrıştırır ve `.dll` içe aktarmalarını (imports) liste haline getirir.
* **`analyzer/entropy.py`**: Matematiksel hesaplamaları barındırır. Shannon Entropy formülü kullanılarak verilen byte dizisinin entropisini (0.0 ile 8.0 arasında) hesaplar. Yüksek entropi (>7.0), verinin paketlenmiş (packed) veya şifrelenmiş olduğuna işaret eder.
* **`analyzer/utils.py`**: Terminal çıktılarını düzenleyen (banner basma, tablo formatlama) ve **Güvenlik Analizi** (şüpheli API tespiti) yapan yardımcı fonksiyonları içerir.

## Güvenlik Analizi Yaklaşımı
Araç sadece dosyayı okumakla kalmaz, aynı zamanda zararlı yazılımların sıkça başvurduğu API'leri (örn: `IsDebuggerPresent`, `VirtualAllocEx`) statik olarak tespit ederek güvenlik uzmanına erken uyarı (Early Warning) sağlar.
