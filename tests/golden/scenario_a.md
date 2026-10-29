# Laporan Insiden Website

_WF-16040EE35A · 2026-10-28 09:00:00 WIB_

## 1. Ringkasan

- Ditemukan 1 file mencurigakan yang terkait dengan 1 alamat IP. Aktivitas pertama aktor pada 2026-10-29 12:16:08 WIB, terakhir pada 2026-10-29 12:16:18 WIB.
- Titik masuk yang paling mungkin: unrestricted file upload (upload tanpa validasi) lewat POST /admin/upload.php pada 2026-10-29 12:16:16 WIB (keyakinan sedang).

### Alur serangan

- \#3 2026-10-29 12:16:16 WIB: Upload yang menulis uploads/lab-marker.php tanpa login sebelumnya: POST /admin/upload.php → 200.
- \#4 2026-10-29 12:16:16 WIB: File uploads/lab-marker.php dibuat (SHA-256 52d31ac74301…).
- \#5 2026-10-29 12:16:18 WIB: File uploads/lab-marker.php diakses: GET /uploads/lab-marker.php → 200.

## 2. Informasi Kasus

- **ID kasus:** WF-16040EE35A
- **Analis:** -
- **Host target:** bf89ed992aef
- **Laporan dibuat:** 2026-10-28 09:00:00 WIB
- **Zona waktu laporan:** WIB (UTC+07:00)

### Cakupan bukti

- **Periode access log:** 2026-10-29 12:16:08 WIB s.d. 2026-10-29 12:16:18 WIB
- **Access log:** 6 baris terbaca
- **Webroot:** 11 file
- **Bukti dikumpulkan:** 2026-10-29 12:16:25 WIB
- **Baseline:** tidak ada

## 3. Kronologi Serangan

| # | Waktu | Dasar waktu | Fase (ATT\&CK) | Aktor | Kejadian | Keyakinan | Bukti |
|---|---|---|---|---|---|---|---|
| #1 | 2026-10-29 12:16:08 WIB | log | - | 172.30.0.1 | Request pertama aktor ini di log: GET / → 200. | tinggi | access.log:1 |
| #2 | 2026-10-29 12:16:14 WIB | log | Initial Access (akses awal) · T1190 | 172.30.0.1 | Percobaan eksploitasi: GET /product.php → 200 (SQL injection (tautologi)). | sedang | access.log:4 |
| #3 | 2026-10-29 12:16:16 WIB | log | Initial Access (akses awal) · T1190 | 172.30.0.1 | **AKAR MASALAH: Upload yang menulis uploads/lab-marker.php tanpa login sebelumnya: POST /admin/upload.php → 200.** | tinggi (sebagai titik masuk: sedang) | access.log:5, uploads/lab-marker.php @52d31ac74301 |
| #4 | 2026-10-29 12:16:16 WIB | btime | Persistence (bertahan) · T1505.003 | - | File uploads/lab-marker.php dibuat (SHA-256 52d31ac74301…). | tinggi | uploads/lab-marker.php @52d31ac74301 |
| #5 | 2026-10-29 12:16:18 WIB | log | Persistence (bertahan) · T1505.003 | 172.30.0.1 | File uploads/lab-marker.php diakses: GET /uploads/lab-marker.php → 200. | tinggi | access.log:6 |

### Catatan keyakinan

- \#3: Hanya satu request penulis yang cocok dengan waktu file dibuat. Aktor yang sama kemudian mengakses file ini. Isi POST tidak tercatat di access log, jadi nama file yang diupload tidak terbukti dari log.
- \#4: Waktu dari btime (waktu file lahir), yang tidak bisa diubah dengan touch.

## 4. Akar Masalah

- **Kejadian:** #3 Upload yang menulis uploads/lab-marker.php tanpa login sebelumnya: POST /admin/upload.php → 200.
- **Jenis kelemahan:** unrestricted file upload (upload tanpa validasi)
- **Keyakinan:** sedang
- **Bukti:** access.log:5, uploads/lab-marker.php @52d31ac74301

### Baris log asli

```
172.30.0.1 - - [29/Oct/2026:05:16:16 +0000] "POST /admin/upload.php HTTP/1.1" 200 44 "-" "webforensics-lab/1.0 scenario-a" "-"
```

### Alasan

- Hanya satu request penulis yang cocok dengan waktu file dibuat.
- Aktor yang sama kemudian mengakses file ini.
- Isi POST tidak tercatat di access log, jadi nama file yang diupload tidak terbukti dari log.
- Tidak ada login yang terlihat sebelum request penulis, jadi request itu sendiri dianggap titik masuk.
- Tidak terlihat login bukan berarti tidak ada login: sesi bisa dibuat sebelum periode log.

## 5. File Terdampak

### uploads/lab-marker.php

- **SHA-256:** 52d31ac74301cc8fd601913c9cc75e1bc0b2f2ffd26fe71b9864200eda78865d
- **Ukuran:** 24 byte
- **Status baseline:** tidak diketahui (tanpa baseline)
- **Timestamp:** btime 2026-10-29 12:16:16 WIB; ctime 2026-10-29 12:16:16 WIB; mtime 2026-10-29 12:16:16 WIB
- **Sumber timestamp:** manifest collect.sh
- **URL:** /uploads/lab-marker.php

Temuan

- File skrip di folder yang bisa ditulis: uploads/lab-marker.php (FILE-WEBSHELL-WRITABLE-EXEC, keyakinan sedang)

## 6. Perubahan yang Perlu Ditinjau

Tidak ada.

## 7. Indikator Kompromi (IOC)

### Alamat IP

```
172.30.0.1
```

### User agent

```
webforensics-lab/1.0 scenario-a
```

### Hash SHA-256

```
52d31ac74301cc8fd601913c9cc75e1bc0b2f2ffd26fe71b9864200eda78865d
```

### Path file

```
uploads/lab-marker.php
```

### URL

```
/uploads/lab-marker.php
```

## 8. Celah Bukti

| ID | Jenis | Rentang waktu | Keterangan | Melemahkan |
|---|---|---|---|---|
| G1 | Tanpa baseline | - | Tidak ada baseline (salinan bersih) untuk pembanding, jadi status file hanya dari heuristik. | - |

## 9. Aktivitas Serangan Lain (Tidak Terkait Insiden)

Tidak ada.

## 10. Tindakan yang Disarankan

### Penahanan (containment)

- Amankan bukti dulu: salin log dan webroot beserta hash-nya sebelum mengubah apa pun di server.
- Batasi akses ke situs (mode maintenance atau firewall) sampai file berbahaya dihapus.
- Blokir sementara IP berikut: 172.30.0.1.

### Pembersihan (eradication)

- Karantina lalu hapus file berikut setelah disalin sebagai bukti: uploads/lab-marker.php.
- Perbaiki endpoint /admin/upload.php: batasi ekstensi dan tipe file, simpan upload di luar webroot, dan matikan eksekusi skrip di folder upload.

### Pemulihan (recovery)

- Ganti password admin aplikasi, database, dan semua kredensial yang tersimpan di file konfigurasi webroot.
- Pulihkan webroot dari sumber yang terpercaya (git atau backup sebelum insiden), bukan dengan menghapus file satu per satu saja.
- Setelah pemulihan, pantau akses ke /uploads/lab-marker.php dan aktivitas dari IP di daftar IOC.

### Pembelajaran (lessons learned)

- Simpan baseline webroot (daftar hash file) secara berkala supaya file baru atau berubah bisa dipastikan.
- Aktifkan pemantauan integritas file (FIM) pada webroot.
- Catat nama file upload di log aplikasi, karena access log tidak mencatat isi POST.

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
| access.log:1 | 172.30.0.1 - - \[29/Oct/2026:05:16:08 +0000\] "GET / HTTP/1.1" 200 298 "-" "webforensics-lab/1.0 scenario-a" "-" |
| access.log:4 | 172.30.0.1 - - \[29/Oct/2026:05:16:14 +0000\] "GET /product.php?id=1+OR+1%3D1 HTTP/1.1" 200 223 "-" "webforensics-lab/1.0 scenario-a" "-" |
| access.log:5 | 172.30.0.1 - - \[29/Oct/2026:05:16:16 +0000\] "POST /admin/upload.php HTTP/1.1" 200 44 "-" "webforensics-lab/1.0 scenario-a" "-" |
| uploads/lab-marker.php @52d31ac74301 | SHA-256 52d31ac74301cc8fd601913c9cc75e1bc0b2f2ffd26fe71b9864200eda78865d |
| access.log:6 | 172.30.0.1 - - \[29/Oct/2026:05:16:18 +0000\] "GET /uploads/lab-marker.php HTTP/1.1" 200 35 "-" "webforensics-lab/1.0 scenario-a" "-" |

## Lampiran B. Reproduksibilitas

- **Versi alat:** 0.1.0
- **Versi ruleset:** 0.1.0
- **Hash konfigurasi:** c5151d3a2f13b07748750ef54e0aa218107778fc0a16cbf3101325edba953255

### File input

| File | SHA-256 | Ukuran |
|---|---|---|
| access.log | 27d5072520346aa778ef58b90d89f073afe4541ca6bf382183c60cc460138d17 | 760 byte |
| manifest.tsv | 917ceb04335113a0c83d87337185c8f126f9fed19aa37970fff53f81aa22feec | 1973 byte |

Input, versi, dan konfigurasi yang sama menghasilkan laporan yang sama persis.
