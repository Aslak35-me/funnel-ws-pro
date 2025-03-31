#!/bin/bash

# Funnel WS Ultimate Kurulum Scripti
# Türkçe açıklamalı

echo -e "\033[1;34mFunnel WS Ultimate Kurulumu Başlatılıyor...\033[0m"

# Gerekli paketlerin kontrolü ve kurulumu
echo -e "\033[1;33mGerekli sistem paketleri kontrol ediliyor...\033[0m"
sudo apt update && sudo apt upgrade -y
sudo apt install python3 -y

# Python sürüm kontrolü (3.7+ gereklidir)
if ! command -v python3 &>/dev/null; then
    echo -e "\033[1;31mPython3 bulunamadı! Lütfen Python3 kurun.\033[0m"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))')
if [[ "$PYTHON_VERSION" < "3.7" ]]; then
    echo -e "\033[1;31mPython 3.7 veya üzeri gereklidir. Mevcut sürüm: $PYTHON_VERSION\033[0m"
    exit 1
fi

# Gerekli sistem bağımlılıkları
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv nmap nikto sqlmap git wget

# Sanal ortam oluşturma
echo -e "\033[1;33mPython sanal ortamı oluşturuluyor...\033[0m"
python3 -m venv funnel-env
source funnel-env/bin/activate

# Python bağımlılıklarının kurulumu
echo -e "\033[1;33mPython bağımlılıkları yükleniyor...\033[0m"
pip install --upgrade pip
pip install -r requirements.txt

# Harici araçların kontrolü
echo -e "\033[1;33mHarici güvenlik araçları kontrol ediliyor...\033[0m"

# SQLMap kontrolü
if ! command -v sqlmap &>/dev/null; then
    echo -e "\033[1;31mSQLMap bulunamadı! Manuel olarak kurulum yapılması önerilir.\033[0m"
fi

# Nikto kontrolü
if ! command -v nikto &>/dev/null; then
    echo -e "\033[1;31mNikto bulunamadı! Manuel olarak kurulum yapılması önerilir.\033[0m"
fi

# OWASP ZAP kontrolü
if ! command -v zap.sh &>/dev/null; then
    echo -e "\033[1;31mOWASP ZAP bulunamadı! Manuel olarak kurulum yapılması önerilir.\033[0m"
fi

# Sistem linki oluşturma
echo -e "\033[1;33mSistem linki oluşturuluyor...\033[0m"
if [ ! -f "/usr/local/bin/funnelws" ]; then
    sudo ln -s "$(pwd)/funnelws.py" /usr/local/bin/funnelws
    sudo chmod +x /usr/local/bin/funnelws
    echo -e "\033[1;32mFunnel WS başarıyla kuruldu! 'funnelws' komutu ile çalıştırabilirsiniz.\033[0m"
else
    echo -e "\033[1;32mFunnel WS zaten kurulu görünüyor.\033[0m"
fi

# Payload dosyalarının indirilmesi
echo -e "\033[1;33mPayload dosyaları indiriliyor...\033[0m"
if [ ! -d "payloads" ]; then
    mkdir payloads
    wget https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt -O payloads/xss.txt
    wget https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/sql-injection-payload-list.txt -O payloads/sqli.txt
    wget https://raw.githubusercontent.com/payloadbox/rce-payloads/master/Intruder/rce-payloads.txt -O payloads/rce.txt
    wget https://raw.githubusercontent.com/payloadbox/lfi-payload-list/master/Intruder/LFI.txt -O payloads/lfi.txt
    wget https://raw.githubusercontent.com/payloadbox/xxe-injection-payload-list/master/Intruder/xxe-injection-payload-list.txt -O payloads/xxe.txt
fi

# Kurulum tamamlandı
echo -e "\033[1;32mKurulum başarıyla tamamlandı!\033[0m"
echo -e "\033[1;36mKullanım için: funnelws --help\033[0m"
echo -e "\033[1;33mNot: Sanal ortamı aktif etmek için (her çalıştırmada gereklidir lütfen ilk önce bu komutu girin!): source funnel-env/bin/activate\033[0m"