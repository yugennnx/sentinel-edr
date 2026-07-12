@echo off
title SENTINEL - Temiz Test Modu (Yonetici)

net session >nul 2>&1
if %errorLevel% == 0 (
    goto :basla
) else (
    echo [*] Yonetici izinleri isteniyor...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit
)

:basla
cd /d "C:\Users\tugra\Desktop\Sentinel"

echo [*] Arka planda asili kalan zombi Python surecleri imha ediliyor...
taskkill /F /IM python.exe /T >nul 2>&1
timeout /t 1 /nobreak >nul

if exist sentinel_logs.db (
    del /f /q sentinel_logs.db
    echo [+] Eski loglar basariyla silindi.
)

echo [*] SENTINEL Arka Plan Motoru ve Arayuzu Baslatiliyor...
start "SENTINEL CORE" cmd /k "python baslat.py"
exit