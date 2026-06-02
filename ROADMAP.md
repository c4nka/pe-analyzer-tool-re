# ROADMAP — Advanced PE Analyzer & Threat Intelligence Tool
# ROADMAP — Gelişmiş PE Analiz ve Tehdit İstihbarat Aracı

> Course / Ders: Reverse Engineering (BGT210) · Istinye University
> Instructor / Danışman: Keyvan Arasteh

---

## Phase 0 / Faz 0: Understand Before You Build / Yazmadan Önce Anla

Before writing a single line of code, I answered these questions:
Tek satır kod yazmadan önce şu soruları yanıtladım:

- **What is the project? / Proje nedir?** A static malware analysis CLI tool that safely dissects Windows executables (PE files) to identify malicious traits without executing them.
- **How does it work? / Nasıl çalışır?** It parses PE headers, calculates mathematical entropy, hunts for specific Regex patterns (IoCs), queries external threat databases (VirusTotal), and feeds all this data into a custom risk-scoring algorithm.
- **What are the inputs/outputs? / Girdiler/çıktılar neler?** Input: A suspicious `.exe` or `.dll` file. Output: A comprehensive console report and a structured JSON file detailing the malware's anatomy and a final severity score.
- **What tools will I use and why? / Hangi araçları kullanacağım ve neden?** Python (pefile, hashlib) for deep parsing, VirusTotal API for external intelligence, and Docker to create an isolated, ephemeral sandbox that prevents accidental host infection.

---

## Phase 1 / Faz 1: Research & Investigation / Araştırma ve Keşif

> Folder / Klasör: `docs/research/`

| Topic / Konu | Status / Durum | Notes / Notlar |
|--------------|----------------|----------------|
| PE File Structure & Headers | ✅ Completed | Studied the layout of DOS Header, NT Headers, and Data Directories to understand how executables are mapped in memory. |
| Packing, Obfuscation & Entropy | ✅ Completed | Investigated Shannon Entropy; learned that values > 7.0 usually indicate compressed or encrypted payloads. |
| Windows API Abuse | ✅ Completed | Researched suspicious imports like `CreateRemoteThread` or `WriteProcessMemory` commonly used in Process Injection techniques. |

---

## Phase 2 / Faz 2: Environment Setup / Ortam Kurulumu

- [x] Isolated lab environment (Docker / VM) / İzole lab ortamı `docker-compose.yml` ile oluşturuldu (Volume eşleştirmeli sandbox).
- [x] Tools installed and verified / Araçlar kuruldu ve test edildi (`pefile`, `requests`).
- [x] `.env.example` created / oluşturuldu (VirusTotal API entegrasyonu için).

---

## Phase 3 / Faz 3: Implementation / Uygulama

### Module / Modül: Core Parsing & Threat Extraction

1. Step 1 / Adım 1 — Implemented cryptographic hashing (MD5, SHA-256) and basic PE structure parsing.
2. Step 2 / Adım 2 — Built the Section Analyzer (Entropy calculation) and Suspicious API Inspector.
3. Step 3 / Adım 3 — Developed the Regex-based IoC Hunter to extract hidden C2 IPs, URLs, and emails from raw binary data.
4. Step 4 / Adım 4 — Integrated VirusTotal API for real-time threat intelligence correlation.
5. Step 5 / Adım 5 — Engineered the Heuristic Risk Scoring Engine to mathematically weigh all findings and output a definitive verdict (0-100 Score).

---

## Phase 4 / Faz 4: Testing & Reporting / Test ve Raporlama

- [x] Ran tests against target/sample / Hedef/örnek üzerinde testler çalıştırıldı (Packer içeren dosyalar, temiz Windows sistem dosyaları).
- [x] Documented all findings with evidence / Tüm bulgular kanıtlarıyla belgelendi (JSON çıktılarıyla).
- [x] Wrote final report (Markdown) / Final raporu yazıldı (Heuristik motor ve IoC modülü dokümantasyonu tamamlandı).

---

## Phase 5 / Faz 5: Delivery / Teslim

- [x] GitHub repository is clean and organized / Repo temiz ve düzenli
- [x] README.md complete / eksiksiz
- [x] Docker verified (`docker-compose run --rm`) / doğrulandı
- [x] Instructor invited as collaborator / Danışman collaborator olarak eklendi → **keyvanarasteh**

---

## What I Learned / Öğrendiklerim

Building this tool was a deep dive into the mind of an Incident Responder. I learned that static analysis is like digital forensics; you don't need to run the malware to understand its intent. Identifying high entropy in a `.text` section taught me how attackers hide their code (packing), while tracking specific Win32 API imports revealed exactly how they plan to manipulate the operating system. Furthermore, building a scoring engine showed me the importance of correlating multiple data points (IoCs, API calls, external threat intel) to reduce false positives and make confident, automated security decisions.
