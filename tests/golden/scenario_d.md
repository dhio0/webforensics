# Laporan Insiden Website

_WF-5D640831B0 · 2026-10-28 09:00:00 WIB_

## 1. Ringkasan

- Tidak ditemukan file mencurigakan yang terkait dengan request HTTP. Ini tidak menjamin server bersih.
- 2 login lewat SQL injection ke /admin/login.php tampaknya berhasil (respons seperti login yang sukses), dari 2 klien yang tidak terkait insiden. Tidak ada yang dituduh, tetapi endpoint login ini kemungkinan besar bisa dibobol dan perlu diperbaiki.
- 1 perubahan file perlu ditinjau manual.
- 6 request berpola serangan dari pihak lain (misalnya bot) tidak terkait insiden ini.

## 2. Informasi Kasus

- **ID kasus:** WF-5D640831B0
- **Analis:** -
- **Host target:** b5838e084553
- **Laporan dibuat:** 2026-10-28 09:00:00 WIB
- **Zona waktu laporan:** WIB (UTC+07:00)

### Cakupan bukti

- **Periode access log:** 2026-10-28 10:49:31 WIB s.d. 2026-10-28 10:49:52 WIB
- **Access log:** 32 baris terbaca
- **Error log:** 2 entri
- **Webroot:** 12 file
- **Bukti dikumpulkan:** 2026-10-28 10:49:52 WIB
- **Baseline:** 10 file

## 3. Kronologi Serangan

Tidak ada.

## 4. Akar Masalah

Akar masalah tidak dapat ditentukan dari bukti yang ada.

## 5. File Terdampak

Tidak ada.

## 6. Perubahan yang Perlu Ditinjau

File kode berubah tanpa kaitan HTTP yang cukup kuat untuk dituduh (misalnya cache CMS atau deploy). Periksa manual:

- cache/page-1.php

## 7. Indikator Kompromi (IOC)

Tidak ada IOC.

## 8. Celah Bukti

Tidak ada celah bukti yang terdeteksi.

## 9. Aktivitas Serangan Lain (Tidak Terkait Insiden)

Request ini cocok dengan pola serangan, tetapi pengirimnya tidak terkait dengan file yang disusupkan. Biasanya bot atau pemindai otomatis.

| Aturan | Jumlah | Klien | Klien terbanyak | Rentang waktu | Contoh |
|---|---|---|---|---|---|
| SQL injection (tautologi) (LOG-SQLI-TAUTOLOGY) | 4 | 2 | 192.0.2.21 (2), 203.0.113.21 (2) | 2026-10-28 10:49:33 WIB s.d. 2026-10-28 10:49:44 WIB | access.log:21 |
| Login bypass SQL injection yang tampaknya berhasil (CORR-SQLI-LOGIN-BYPASS) | 2 | 2 | 192.0.2.21 (1), 203.0.113.21 (1) | 2026-10-28 10:49:37 WIB s.d. 2026-10-28 10:49:44 WIB | access.log:23 |
| SQL injection (kutip + komentar) (LOG-SQLI-QUOTE-COMMENT) | 2 | 2 | 192.0.2.21 (1), 203.0.113.21 (1) | 2026-10-28 10:49:37 WIB s.d. 2026-10-28 10:49:44 WIB | access.log:23 |
| SQL injection (UNION) (LOG-SQLI-UNION) | 2 | 2 | 192.0.2.21 (1), 203.0.113.21 (1) | 2026-10-28 10:49:35 WIB s.d. 2026-10-28 10:49:42 WIB | access.log:22 |

## 10. Tindakan yang Disarankan

### Penahanan (containment)

- Amankan bukti dulu: salin log dan webroot beserta hash-nya sebelum mengubah apa pun di server.

### Pembersihan (eradication)

- Perbaiki query login di /admin/login.php dengan prepared statement, lalu periksa query lain yang menyusun SQL dari input user.

### Pemulihan (recovery)

- Ganti password admin dan akhiri semua sesi login yang aktif, karena pihak lain kemungkinan sempat masuk lewat /admin/login.php.
- Tinjau 1 perubahan yang belum terjelaskan sebelum menyatakan server bersih.

### Pembelajaran (lessons learned)

- Aktifkan pemantauan integritas file (FIM) pada webroot.

## 11. Keterbatasan

- Laporan ini dibuat otomatis dengan aturan deterministik. Kesimpulannya perlu diverifikasi analis.
- Isi request POST tidak tercatat di access log. Payload SQL injection lewat POST dan nama file upload tidak terlihat.
- Penyerang dengan akses root bisa memalsukan timestamp file. Alat ini hanya mendeteksi ketidakkonsistenan, tidak bisa membuktikan keaslian.
- Penyerang dengan akses root bisa menghapus baris log. Yang bisa dideteksi hanya celah waktu yang mencolok.
- IP yang dipakai bersama (NAT, proxy, CDN tanpa X-Forwarded-For) bisa menggabungkan beberapa orang menjadi satu aktor.
- Versi ini belum menganalisis kode sumber untuk menunjuk baris yang rentan.

## Lampiran A. Rujukan Bukti

| Rujukan | Kutipan |
|---|---|
| access.log:21 | 172.30.0.3 - - \[28/Oct/2026:03:49:33 +0000\] "GET /product.php?id=1+OR+1%3D1 HTTP/1.0" 200 212 "-" "webforensics-lab/1.0 scenario-d" "192.0.2.21" |
| access.log:23 | 172.30.0.3 - - \[28/Oct/2026:03:49:37 +0000\] "GET /admin/login.php?username=admin%27+OR+%271%27%3D%271%27+--+\&password= HTTP/1.0" 200 347 "-" "webforensics-lab/1.0 scenario-d" "192.0.2.21" |
| access.log:22 | 172.30.0.3 - - \[28/Oct/2026:03:49:35 +0000\] "GET /product.php?id=1+UNION+SELECT+1%2C2 HTTP/1.0" 200 205 "-" "webforensics-lab/1.0 scenario-d" "192.0.2.21" |

## Lampiran B. Reproduksibilitas

- **Versi alat:** 0.1.0
- **Versi ruleset:** 0.1.0
- **Hash konfigurasi:** a327ad9cd4b7b387c7dbfe4a49da4ceac364dddc5291bf29aeadbcf8722e1dda

### File input

| File | SHA-256 | Ukuran |
|---|---|---|
| access.log | 65a9e7f85e7eaa41f16bdb6619a77f388982635ce273b03a73d8ead62d756b52 | 4463 byte |
| baseline.tsv | 6b9c25cdd13d074aba706b6c74f28a19d5d54ad09575f333e315af988d1cc6dd | 1790 byte |
| error.log | c5c1ba27c651faad6b8bbdca29eaa8361c4030a313b40a14731fc521e35fa616 | 337 byte |
| manifest.tsv | b88b773f5e4bb390e32b9a1d934b3f5d06f2a28d15d7ef25aa2537b02997d9e6 | 2124 byte |

Input, versi, dan konfigurasi yang sama menghasilkan laporan yang sama persis.
