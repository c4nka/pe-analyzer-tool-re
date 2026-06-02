# Fikri Mülkiyet (IP) ve Lisans Denetimi Modülü

Bu araç, zararlı yazılım analizinin ötesine geçerek, incelenen yürütülebilir dosyaların (PE) yasal durumunu da analiz edecek şekilde tasarlanmıştır.

## Neden Önemli?
Tersine mühendislik süreçlerinde bir dosyanın kime ait olduğunu kanıtlamak hukuki bir süreçtir. Bu modül; dosyanın içindeki metadata bloklarını ayrıştırarak `LegalCopyright`, `CompanyName`, ve `LegalTrademarks` gibi değerleri otomatik olarak çıkarır.

## Analiz Senaryoları
1. **Zararlı Yazılım Tespiti:** Birçok zararlı yazılım, tespit edilmemek için kendini "Microsoft Corporation" veya "Google LLC" gibi yasal şirketlerin ürünleriymiş gibi gösterir (Spoofing). Bu araç, Orijinal Dosya Adı ile mevcut dosya adının uyuşmazlığını veya sahte telif hakkı bildirimlerini saniyeler içinde ortaya çıkarır.
2. **Fikri Mülkiyet İhlalleri:** Yazılım korsanlığı vakalarında, kodları çalınan orijinal yazılımın içerisindeki telif hakkı bildirimleri genellikle silinir veya değiştirilir. Araç, bu manipülasyonları hukuki bir delil olarak rapora işler.
