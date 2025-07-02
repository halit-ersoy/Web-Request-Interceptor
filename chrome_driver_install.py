#!/usr/bin/env python3
# check_chromedriver.py

import sys
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

def get_chrome_driver():
    """
    - Eğer sistemde uyumlu bir chromedriver yoksa:
        webdriver_manager otomatik olarak uygun sürümü indirir ve path'ini döner.
    - Varsa, zaten indirilmiş olanı kullanır.
    """
    # ChromeDriverManager().install() chromedriver'ı ~/.wdm altında cache'ler
    chromedriver_path = ChromeDriverManager().install()
    service = Service(chromedriver_path)
    # Yeni Selenium v4 API'si ile:
    driver = webdriver.Chrome(service=service)
    return driver

def main():
    print("ChromeDriver kontrol ediliyor ve gerekirse indiriliyor...")
    try:
        driver = get_chrome_driver()
    except Exception as e:
        print("ChromeDriver kurulumu sırasında hata oluştu:", e, file=sys.stderr)
        sys.exit(1)

    print("ChromeDriver hazır. Tarayıcı açılıyor...")
    # Buraya kendi kodunuzu ekleyin:
    driver.get("https://www.google.com")
    print("Sayfa başlığı:", driver.title)

    # ... buradan sonra selenium ile yapmak istediğiniz tüm otomasyon adımları gelebilir ...
    driver.quit()

if __name__ == "__main__":
    main()
