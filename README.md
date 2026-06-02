<div align="center">
  <a href="https://istinye.edu.tr">
    <img src="https://images.seeklogo.com/logo-png/61/1/istinye-universitesi-logo-png_seeklogo-610039.png" alt="Istinye University" width="180"/>
  </a>

  # Advanced PE Analyzer & Threat Intelligence Tool

  ![GitHub](https://img.shields.io/badge/GitHub-Public-red?style=flat-square&logo=github)
  ![Language](https://img.shields.io/badge/Language-Python-blue?style=flat-square)
  ![Status](https://img.shields.io/badge/Status-Completed-success?style=flat-square)
  ![Course](https://img.shields.io/badge/Course-BGT210-purple?style=flat-square)
  ![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
</div>

---

## 🎓 Instructor / Danışman

| | |
|---|---|
| **Name / Ad** | Keyvan Arasteh |
| **GitHub** | [@keyvanarasteh](https://github.com/keyvanarasteh) |
| **Email** | [keyvan.arasteh@istinye.edu.tr](mailto:keyvan.arasteh@istinye.edu.tr) |
| **LinkedIn** | [keyvanarasteh](https://www.linkedin.com/in/keyvanarasteh/) |
| **Website** | [qline.tech](https://qline.tech) |

---

## 👤 Student / Öğrenci

| | |
|---|---|
| **Name / Ad Soyad** | Raşit Çankaya |
| **Student ID / Öğrenci No** | `****[ÖĞRENCİ NUMARANIZIN ORTA RAKAMLARI]****` |

---

## 📚 Course Information / Ders Bilgileri

| | |
|---|---|
| **Course Name / Ders Adı** | Reverse Engineering / Tersine Mühendislik |
| **Course Code / Ders Kodu** | BGT210 |
| **Credits / Kredi** | 3 ECTS |
| **Semester / Dönem** | 2025-2026 Spring / 2025-2026 Bahar |
| **Institution / Üniversite** | [Istinye University](https://istinye.edu.tr) |

---

## 📋 Project Overview / Proje Özeti

This project is an automated static analysis and threat intelligence tool for Portable Executable (PE) files. It acts as an Incident Response sandbox, extracting cryptographic hashes, analyzing section entropy (to detect packing/obfuscation), inspecting suspicious API calls, and extracting hidden Indicators of Compromise (IoCs) like IPs and URLs. It integrates with the VirusTotal API for live threat intelligence and features a Heuristic Risk Scoring Engine to automatically generate a final malware verdict.

Bu proje, Portable Executable (PE) dosyaları için otomatikleştirilmiş bir statik analiz ve tehdit istihbarat aracıdır. Kriptografik hash'leri çıkaran, bölüm entropisini analiz eden (zararlı paketlemeyi tespit için), şüpheli API çağrılarını denetleyen ve gizli IP/URL gibi Tehdit Göstergelerini (IoC) yakalayan bir Adli Bilişim kum havuzu (sandbox) işlevi görür. Canlı istihbarat için VirusTotal API ile entegredir ve nihai bir zararlı yazılım kararı (Hüküm) üretmek üzere Heuristik Risk Skorlama Motoru barındırır.

---

## 🗂 Repository Structure / Repo Yapısı

```text
.
├── docs/                 # Dokümantasyon ve araştırma notları
│   ├── modules/          # Risk skorlama, IoC tespiti teknik analizleri
│   ├── research/         # Entropi ve API hook teorileri
│   └── references/       # Referans materyaller
├── src/                  # Core application source code
│   ├── main.py              # CLI arayüzünü tetikleyen ana dosyan
│   ├── __init__.py          # (Opsiyonel boş dosya)
│   │
│   └── analyzer/            # <-- Klasör bütünlüğü korunarak buraya geldi
│       ├── __init__.py      # (Kesinlikle olması gereken boş dosya)
│       ├── pe_parser.py     # Analiz motoru
│       └── utils.py         # Yardımcı araçlar
├── samples/              # Analiz edilecek şüpheli dosyaların konacağı klasör
├── reports/              # Üretilen JSON analiz raporları
├── requirements.txt      # Python bağımlılıkları
├── Dockerfile            # Kum havuzu (Sandbox) imaj yapılandırması
├── docker-compose.yml    # İzole ağ ve volume yapılandırması
├── .env.example          # API anahtarı şablonu
├── .gitignore
├── README.md
└── ROADMAP.md
```
## 🚀 Getting Started / Kurulum

```bash
git clone [https://github.com/rasitcankaya/](https://github.com/rasitcankaya/)[your-repo]
cd [your-repo]

# Ortam değişkenlerini ayarlayın (VirusTotal API anahtarınızı girin)
cp .env.example .env

# Aracı izole Docker kum havuzunda (Sandbox) çalıştırmak için:
docker-compose run --rm analyzer python src/main.py /samples/hedef_dosya.exe --export /reports/analiz_sonucu.json
```

## 📊 Deliverables / Teslimler

| Item | Status |
|------|--------|
| Kriptografik Kimliklendirme ve Temel PE Başlık Analizi | ✅ |
| Regex Tabanlı IoC Avcısı (IP, URL, Email Tespiti) | ✅ |
| VirusTotal API Canlı İstihbarat Entegrasyonu | ✅ |
| Entropi ve Şüpheli API Tespiti Modülü | ✅ |
| Karar Mekanizmalı Heuristik Risk Skorlama Motoru | ✅ |
| Güvenli Docker Kum Havuzu (Sandbox) Mimarisi | ✅ |

---

## 📚 Documentation / Belgeleme

All module docs → [`docs/modules/`](./docs/modules/)  
Research notes → [`docs/research/`](./docs/research/)

---

## 🔗 References / Kaynaklar

- [VirusTotal API v3 Documentation](https://developers.virustotal.com/reference/overview)
- [Microsoft PE Format Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [pefile Python Library](https://github.com/erocarrera/pefile)
