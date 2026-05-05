import pefile
from .entropy import calculate_shannon_entropy

class PEAnalyzer:
    """Windows PE dosyalarını analiz eden ana sınıf."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        # TODO: Büyük dosyalar yüklendiğinde bellek taşmasını önlemek için chunk okuma eklenebilir.
        try:
            self.pe = pefile.PE(file_path)
        except Exception as e:
            raise ValueError(f"PE dosyası okunamadı veya format geçersiz: {e}")

    def get_basic_info(self) -> dict:
        """Dosya başlığındaki (header) temel bilgileri döndürür."""
        arch = "64-bit" if self.pe.OPTIONAL_HEADER.Magic == 0x20B else "32-bit"
        return {
            "Mimari": arch,
            "Image Base": hex(self.pe.OPTIONAL_HEADER.ImageBase),
            "Entry Point": hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "Bölüm Sayısı": self.pe.FILE_HEADER.NumberOfSections
        }

    def analyze_sections(self) -> list:
        """PE içindeki bölümleri (.text, .data vb.) ve entropi değerlerini analiz eder."""
        sections_info = []
        for section in self.pe.sections:
            name = section.Name.decode('utf-8').rstrip('\x00')
            entropy = calculate_shannon_entropy(section.get_data())
            status = "ŞÜPHELİ (Packed/Encrypted)" if entropy > 7.0 else "Normal"
            
            sections_info.append({
                "İsim": name,
                "Sanal Boyut": hex(section.Misc_VirtualSize),
                "Entropi": round(entropy, 4),
                "Durum": status
            })
        return sections_info
