#!/usr/bin/env python3
# clean_chromedriver.py

import os
import shutil
import stat
import platform
import time
import ctypes
import psutil
from webdriver_manager.chrome import ChromeDriverManager

def kill_chromedriver_processes():
    """psutil ile tüm chromedriver.exe süreçlerini bulup kapatır."""
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == 'chromedriver.exe':
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

def schedule_deletion_on_reboot(path):
    """
    Windows API MoveFileExW ile silinmesi gereken yolu bir sonraki reboot’a kaydeder.
    MOVEFILE_DELAY_UNTIL_REBOOT = 0x04
    """
    MOVEFILE_DELAY_UNTIL_REBOOT = 0x04
    # Her dosya ve alt dizin için çağracağız:
    ctypes.windll.kernel32.MoveFileExW(str(path), None, MOVEFILE_DELAY_UNTIL_REBOOT)

def delete_chromedriver():
    # 1) Cache’deki driver yolunu alıyoruz (yoksa indirir, varsa varolanı döner)
    driver_path = ChromeDriverManager().install()
    driver_dir  = os.path.dirname(driver_path)

    if not os.path.isdir(driver_dir):
        print("ℹ️ ChromeDriver klasörü zaten yok:", driver_dir)
        return

    print(f"🔍 Bulundu: {driver_dir}")
    if platform.system() == "Windows":
        print("⚙️  chromedriver.exe süreçleri kapatılıyor…")
        kill_chromedriver_processes()
        time.sleep(1)

    # 2) Salt-okunur dosya izinlerini yazılabilir yap
    for root, dirs, files in os.walk(driver_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                os.chmod(fpath, stat.S_IWRITE)
            except Exception:
                pass

    # 3) Hemen silmeyi dene
    try:
        shutil.rmtree(driver_dir)
        print(f"✅ Başarıyla silindi: {driver_dir}")
    except PermissionError:
        print("❌ Hemen silme başarısız — yeniden başlatmada silinmesi planlanıyor.")
        # 4) Bir sonraki reboot’ta silinsin diye kaydet
        #    Önce dosyaları, sonra klasörü
        for root, dirs, files in os.walk(driver_dir, topdown=False):
            for fname in files:
                schedule_deletion_on_reboot(os.path.join(root, fname))
            for d in dirs:
                schedule_deletion_on_reboot(os.path.join(root, d))
        schedule_deletion_on_reboot(driver_dir)
        print("🔄 Bir sonraki yeniden başlatmada silinecek.")

if __name__ == "__main__":
    delete_chromedriver()
