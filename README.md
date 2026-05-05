<div align="center">
  <img src="https://images.seeklogo.com/logo-png/61/1/istinye-universitesi-logo-png_seeklogo-610039.png" width="300" alt="İstinye Üniversitesi Logosu">
</div>

# Gelişmiş PE Analiz ve Entropi Aracı (Advanced PE Analyzer)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square)
![Security](https://img.shields.io/badge/Security-Static%20Analysis-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## Proje Bilgileri
* **Kurum:** İstinye Üniversitesi
* **Ders:** Bilişim Güvenliği Teknolojisi - Tersine Mühendislik (Reverse Engineering)
* **Danışman:** Keyvan Arasteh Abbasabad
* **Geliştirici:** Raşit Çankaya

## İçindekiler
- [Proje Hakkında](#proje-hakkında)
- [Özellikler](#özellikler)
- [Mimari ve Dosya Yapısı](#mimari-ve-dosya-yapısı)
- [Kurulum ve Kullanım](#kurulum-ve-kullanım)

## Proje Hakkında
Bu araç, Windows PE (Portable Executable) dosyalarının statik analizini yapmak ve entropi (Shannon Entropy) algoritması kullanarak dosyaların paketlenmiş (packed) veya şifrelenmiş olma ihtimalini tespit etmek amacıyla geliştirilmiştir. Geleneksel ayrıştırıcılardan farklı olarak, içerisinde potansiyel zararlı yazılım indikatörlerini (Malware Indicators) tespit eden bir güvenlik modülü barındırır.

## Özellikler
- **PE Header Analizi:** Dosya mimarisi, entry point ve bölüm sayısı tespiti.
- **Entropi Hesaplama:** Her PE bölümü (.text, .data vb.) için Shannon Entropy hesaplaması ve paketlenmiş dosya (packed) uyarısı.
- **Import Ayrıştırma:** Dosyanın sistemden çağırdığı DLL'leri ve API'leri listeleme.
- **Zararlı API Tespiti:** Anti-Debugging, Process Injection veya Keylogging için kullanılan şüpheli API'lerin statik olarak tespiti.

## Mimari ve Dosya Yapısı
Uygulama tamamen modüler bir yapıda tasarlanmıştır. Sınıf hiyerarşisi, modüllerin görevleri ve güvenlik analizinin çalışma mantığı hakkında detaylı bilgi için lütfen [Mimari Dokümantasyonunu](docs/architecture.md) inceleyiniz.

## Kurulum ve Kullanım
Adım adım kurulum, gereksinimler ve örnek analiz komutları için lütfen [Kullanım Kılavuzunu](docs/usage.md) inceleyiniz.
