import requests

url = "https://icdn.cam/api/Lovely-Runner.2024.Ep1.en.srt"  # Tam URL (istenen .srt dosyası)

headers = {
    "sec-ch-ua-platform": "\"Windows\"",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "accept": "application/json, text/plain, */*",
    "sec-ch-ua": "\"Chromium\";v=\"136\", \"Google Chrome\";v=\"136\", \"Not.A/Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0",
    "origin": "https://kisskh.co",
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "referer": "https://kisskh.co/",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "en-US,en;q=0.9",
    "priority": "u=1, i"
}

# İsteği gönder
response = requests.get(url, headers=headers)

# Yanıtı kaydet
if response.status_code == 200:
    filename = "Lovely-Runner.2024.Ep1.en.srt"
    with open(filename, "wb") as f:
        f.write(response.content)
    print(f"{filename} başarıyla indirildi.")
else:
    print(f"İstek başarısız oldu. Durum kodu: {response.status_code}")
