# Temel alınacak hafif Python imajı
FROM python:3.10-slim

# Konteyner içindeki çalışma dizini
WORKDIR /app

# Bağımlılıkları kopyala ve yükle
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Proje dosyalarını kopyala
COPY . .

# Konteyner çalıştığında çalıştırılacak varsayılan komut
# Not: Argüman dışarıdan verileceği için ENTRYPOINT kullanıyoruz
ENTRYPOINT ["python", "main.py"]
