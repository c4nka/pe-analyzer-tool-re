import math
import collections

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Verilen byte dizisinin Shannon Entropisini hesaplar.
    Sonuç 7.0 üzerinde ise verinin şifrelenmiş veya paketlenmiş (packed) olma ihtimali yüksektir.
    """
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    counts = collections.Counter(bytearray(data))
    
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log(probability, 2)
        
    # TODO: İlerleyen aşamalarda entropi grafiği çizdirmek için matplotlib entegrasyonu düşünülebilir.
    return entropy
