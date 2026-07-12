@echo off
mode con: cols=110 lines=35
color 0c
title CRITICAL ALERT - SYSTEM COMPROMISE
echo ===============================================================================
echo                [ W A R N I N G - U N A U T H O R I Z E D   A C C E S S ]
echo ===============================================================================
echo [!!!] YETKISIZ ERISIM TESPIT EDILDI [!!!]
echo [*] Guvenlik Duvari Bypass Ediliyor... [BASARILI]
ping 127.0.0.1 -n 2 > nul
echo [*] Sifreleme Anahtarlari Icin Bellek Taramasi Baslatildi...
ping 127.0.0.1 -n 2 > nul
echo.
echo [>] KABA KUVVET (BRUTE-FORCE) SALDIRISI:
echo.

:: Ekranda hizlica akan sahte bellek ve sifre denemeleri
for /l %%x in (1, 1, 60) do (
    echo [0x00%%x] Deneniyor HASH: %%x9A4B%random%%random%... [BASARISIZ]
)
echo [0x0061] Deneniyor HASH: 88B2A%random%%random%... [BASARILI!]
echo.
echo [*] Anahtar Bulundu. Proje Dosyalarina Erisiliyor...
echo.
echo [>] VERILER KOPYALANIYOR... LUTFEN BEKLEYIN.
echo [====================          ] %%65

:: Sentinel'in müdahale edeceği an.
ping 127.0.0.1 -n 10 > nul

echo [+] VERILER CALINDI.
pause