@echo off
mode con: cols=110 lines=35
color 0a
title UPLINK ESTABLISHED - EXFILTRATION NODE
echo ===============================================================================
echo                [ E N C R Y P T E D   T U N N E L   A C T I V E ]
echo ===============================================================================
echo [+] KORSAN SUNUCU: BAGLANTI AKTIF (IP: 194.32.1.88)
echo [*] Hedef Dizin: Sentinel Projesi
ping 127.0.0.1 -n 2 > nul
echo [*] Sifrelenmis Veri Tüneli Aciliyor...
echo.

:: Ekranda hizlica akan Matrix tarzı sayılar
for /l %%x in (1, 1, 100) do (
    echo %random% %random% %random% %random% %random% %random% %random% %random% %random% %random% %random% %random% %random% %random% %random%
)
echo.
echo [*] Proje dosyalari basariyla okundu ve paketlendi.
echo.
echo [^>] SUNUCUYA AKTARIM BASLADI (Gecikmeli Gonderim)...
echo [#########                   ] %%30

:: Sentinel'in müdahale edeceği an.
ping 127.0.0.1 -n 10 > nul

echo [+] TUM VERILER SIZDIRILDI.
pause