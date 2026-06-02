# Module Name / Modül Adı: VirusTotal API & IoC Detection Engine

## Purpose / Amaç

This module automates the extraction of cryptographic hashes from PE files and queries the VirusTotal API to identify known malware signatures without executing the payload.
Bu modül, PE dosyalarından kriptografik hash'leri otomatik olarak çıkarır ve zararlı yazılımı çalıştırmadan bilinen tehditleri tespit etmek için VirusTotal API'sini sorgular.

## How It Works / Nasıl Çalışır

Step-by-step explanation:
1. **Hash Calculation:** The `calculate_hashes` function reads the target executable in chunks and generates MD5 and SHA-256 cryptographic signatures.
2. **API Integration:** The generated SHA-256 hash is sent via secure REST request to the VirusTotal v3 API endpoints using the provided environment key (`.env`).
3. **Verdict Generation:** The JSON response is parsed to extract the detection ratio (e.g., 45/72 vendors flagged as malicious) and appends this to the final heuristic risk score.

## Usage / Kullanım

```bash
# Example command / Örnek komut
docker-compose run --rm analyzer python src/main.py /samples/hedef_dosya.exe --export /reports/vt_analiz_sonucu.json
```

Output / Çıktı
The output is a structured JSON file containing the calculated hashes, basic PE header details, and a virustotal_report object showing the number of positive detections, threat labels, and scan dates.

Known Limitations / Bilinen Kısıtlamalar
API Rate Limits: The free tier of the VirusTotal API restricts queries to 4 requests per minute and 500 per day.

Zero-Day Threats: If a PE file is a completely new variant (zero-day), its hash will not exist in the VirusTotal database, requiring reliance on the local entropy and API inspection modules.
