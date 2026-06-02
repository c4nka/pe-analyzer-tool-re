# Heuristik Risk Skorlama Motoru

Gelişmiş PE Analiz aracı, elde ettiği statik ve dinamik verileri korele ederek otomatik bir "Risk Skoru" (0-100) üretir. Bu motor, adli bilişim analistlerine olay müdahalesi (Incident Response) sırasında hızlı karar verme imkanı sunar.

## 🧮 Puanlama Algoritması
- **VirusTotal Tespiti (+50 Puan):** Dosya daha önce küresel motorlar tarafından zararlı işaretlendiyse doğrudan kritik risk seviyesine çekilir.
- **Yüksek Entropi (+20 Puan):** Dosya bölümlerinden herhangi birinin entropisi 7.0 üzerindeyse, kodun gizlendiği (packing/obfuscation) varsayılır.
- **Fikri Mülkiyet Eksikliği (+15 Puan):** Şirket veya telif hakkı gibi yasal meta verilerin silinmiş olması manipülasyon göstergesidir.
- **Gizli IoC Varlığı (+10 Puan):** Kod içerisine gömülü IP ve URL adresleri şüpheli iletişim kanalları olarak değerlendirilir.
- **Şüpheli API'ler (+5 Puan / Maks +25):** İşletim sistemine doğrudan müdahale eden (örn: `WriteProcessMemory`, `CreateRemoteThread`) her API çağrısı riski artırır.
