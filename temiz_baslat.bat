@echo off
title SENTINEL - Temiz Test Modu (Yonetici)

net session >nul 2>&1
if %errorLevel% == 0 (
    goto :basla
) else (
    echo [*] Yonetici izinleri isteniyor...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:basla
rem Betik hangi klasordeyse orada calisir (sabit kullanici yolu yok)
cd /d "%~dp0"

echo [*] Asili kalan SENTINEL surecleri kapatiliyor...
rem Sadece bu projenin surecleri kapatilir; sistemdeki diger Python programlarina dokunulmaz.
python tools\sentinel_durdur.py
timeout /t 1 /nobreak >nul

for %%F in (data\sentinel_logs.db data\sentinel_logs.db-wal data\sentinel_logs.db-shm) do (
    if exist "%%F" del /f /q "%%F"
)
echo [+] Eski loglar silindi.

echo [*] SENTINEL Arka Plan Motoru ve Arayuzu Baslatiliyor...
start "SENTINEL CORE" cmd /k "python run.py"
exit /b
