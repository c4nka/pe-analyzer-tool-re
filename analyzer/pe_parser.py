import pefile
import re
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

    def get_imports(self) -> dict:
        """İçe aktarılan (Imported) DLL'leri ve fonksiyonları analiz eder."""
        imports_info = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8')
                    funcs = []
                    for imp in entry.imports:
                        if imp.name:
                            funcs.append(imp.name.decode('utf-8'))
                    imports_info[dll_name] = funcs
                except Exception:
                    continue
        return imports_info

def get_ip_metadata(self) -> dict:
        """PE dosyasının içindeki yasal meta verileri (Fikri Mülkiyet/Lisans) çıkarır."""
        version_info = {}
        
        # Dosyada sürüm/meta veri bloğu olup olmadığını kontrol et
        if hasattr(self.pe, 'VS_VERSIONINFO') and hasattr(self.pe, 'FileInfo'):
            for fileinfo in self.pe.FileInfo:
                for file_info_item in fileinfo:
                    if hasattr(file_info_item, 'StringTable'):
                        for st in file_info_item.StringTable:
                            for entry in st.entries.items():
                                try:
                                    # Veriler genellikle byte (UTF-8) olarak saklanır
                                    key = entry[0].decode('utf-8', 'ignore')
                                    value = entry[1].decode('utf-8', 'ignore')
                                    version_info[key] = value
                                except Exception:
                                    continue
        return version_info
