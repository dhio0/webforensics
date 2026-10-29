# Laporan Insiden Website

_WF-E887DEB66B · 2026-10-28 09:00:00 WIB_

## 1. Ringkasan

- Ditemukan 1 file mencurigakan yang terkait dengan 1 alamat IP. Aktivitas pertama aktor pada 2026-10-29 12:19:47 WIB, terakhir pada 2026-10-29 12:19:59 WIB.
- Titik masuk yang paling mungkin: SQL injection pada login (bypass autentikasi) lewat GET /admin/login.php pada 2026-10-29 12:19:55 WIB (keyakinan sedang).

### Alur serangan

- \#3 2026-10-29 12:19:55 WIB: Bypass login dengan SQL injection: GET /admin/login.php → 200.
- \#4 2026-10-29 12:19:57 WIB: Request yang menulis uploads/scenario-f-marker.php: POST /admin/auth\_upload.php → 200.
- \#5 2026-10-29 12:19:57 WIB: File uploads/scenario-f-marker.php dibuat (SHA-256 c2f45202f02a…).
- \#6 2026-10-29 12:19:59 WIB: File uploads/scenario-f-marker.php diakses: GET /uploads/scenario-f-marker.php → 200.

## 2. Informasi Kasus

- **ID kasus:** WF-E887DEB66B
- **Analis:** -
- **Host target:** 563daf0056be
- **Laporan dibuat:** 2026-10-28 09:00:00 WIB
- **Zona waktu laporan:** WIB (UTC+07:00)

### Cakupan bukti

- **Periode access log:** 2026-10-29 12:19:47 WIB s.d. 2026-10-29 12:19:59 WIB
- **Access log:** 7 baris terbaca
- **Webroot:** 11 file
- **Bukti dikumpulkan:** 2026-10-29 12:20:10 WIB
- **Baseline:** tidak ada

## 3. Kronologi Serangan

| # | Waktu | Dasar waktu | Fase (ATT\&CK) | Aktor | Kejadian | Keyakinan | Bukti |
|---|---|---|---|---|---|---|---|
| #1 | 2026-10-29 12:19:47 WIB | log | - | 172.30.0.1 | Request pertama aktor ini di log: GET / → 200. | tinggi | access.log:1 |
| #2 | 2026-10-29 12:19:53 WIB | log | - | 172.30.0.1 | Login gagal: GET /admin/login.php → 401. | tinggi | access.log:4 |
| #3 | 2026-10-29 12:19:55 WIB | log | Initial Access (akses awal) · T1190 | 172.30.0.1 | **AKAR MASALAH: Bypass login dengan SQL injection: GET /admin/login.php → 200.** | sedang | access.log:5 |
| #4 | 2026-10-29 12:19:57 WIB | log | Persistence (bertahan) · T1505.003 | 172.30.0.1 | Request yang menulis uploads/scenario-f-marker.php: POST /admin/auth\_upload.php → 200. | tinggi | access.log:6, uploads/scenario-f-marker.php @c2f45202f02a |
| #5 | 2026-10-29 12:19:57 WIB | btime | Persistence (bertahan) · T1505.003 | - | File uploads/scenario-f-marker.php dibuat (SHA-256 c2f45202f02a…). | tinggi | uploads/scenario-f-marker.php @c2f45202f02a |
| #6 | 2026-10-29 12:19:59 WIB | log | Persistence (bertahan) · T1505.003 | 172.30.0.1 | File uploads/scenario-f-marker.php diakses: GET /uploads/scenario-f-marker.php → 200. | tinggi | access.log:7 |

### Catatan keyakinan

- \#2: Server membalas 401.
- \#3: Login dengan payload SQL injection berhasil, lalu aktor yang sama menulis file di area yang sama. Respons berbeda dari login yang gagal dan tidak diikuti percobaan ulang. Kaitan login dan upload disimpulkan dari IP dan area yang sama, karena cookie sesi tidak tercatat.
- \#4: Hanya satu request penulis yang cocok dengan waktu file dibuat. Aktor yang sama kemudian mengakses file ini. Isi POST tidak tercatat di access log, jadi nama file yang diupload tidak terbukti dari log.
- \#5: Waktu dari btime (waktu file lahir), yang tidak bisa diubah dengan touch.

## 4. Akar Masalah

- **Kejadian:** #3 Bypass login dengan SQL injection: GET /admin/login.php → 200.
- **Jenis kelemahan:** SQL injection pada login (bypass autentikasi)
- **Keyakinan:** sedang
- **Bukti:** access.log:5

### Baris log asli

```
172.30.0.1 - - [29/Oct/2026:05:19:55 +0000] "GET /admin/login.php?username=admin%27+OR+%271%27%3D%271+--+&password= HTTP/1.1" 200 359 "-" "webforensics-lab/1.0 scenario-f" "-"
```

### Alasan

- Login dengan payload SQL injection berhasil, lalu aktor yang sama menulis file di area yang sama.
- Respons berbeda dari login yang gagal dan tidak diikuti percobaan ulang.
- Kaitan login dan upload disimpulkan dari IP dan area yang sama, karena cookie sesi tidak tercatat.

## 5. File Terdampak

### uploads/scenario-f-marker.php

- **SHA-256:** c2f45202f02ab18a6ad3965db67be368436a3a245819798ad1601464405f838c
- **Ukuran:** 26 byte
- **Status baseline:** tidak diketahui (tanpa baseline)
- **Timestamp:** btime 2026-10-29 12:19:57 WIB; ctime 2026-10-29 12:19:57 WIB; mtime 2026-10-29 12:19:57 WIB
- **Sumber timestamp:** manifest collect.sh
- **URL:** /uploads/scenario-f-marker.php

Temuan

- File skrip di folder yang bisa ditulis: uploads/scenario-f-marker.php (FILE-WEBSHELL-WRITABLE-EXEC, keyakinan sedang)

## 6. Perubahan yang Perlu Ditinjau

Tidak ada.

## 7. Indikator Kompromi (IOC)

### Alamat IP

```
172.30.0.1
```

### User agent

```
webforensics-lab/1.0 scenario-f
```

### Hash SHA-256

```
c2f45202f02ab18a6ad3965db67be368436a3a245819798ad1601464405f838c
```

### Path file

```
uploads/scenario-f-marker.php
```

### URL

```
/uploads/scenario-f-marker.php
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

- Karantina lalu hapus file berikut setelah disalin sebagai bukti: uploads/scenario-f-marker.php.
- Perbaiki query login di /admin/login.php dengan prepared statement, lalu periksa query lain yang menyusun SQL dari input user.
- Perbaiki endpoint /admin/auth\_upload.php: batasi ekstensi dan tipe file, simpan upload di luar webroot, dan matikan eksekusi skrip di folder upload.

### Pemulihan (recovery)

- Ganti password admin aplikasi, database, dan semua kredensial yang tersimpan di file konfigurasi webroot.
- Pulihkan webroot dari sumber yang terpercaya (git atau backup sebelum insiden), bukan dengan menghapus file satu per satu saja.
- Setelah pemulihan, pantau akses ke /uploads/scenario-f-marker.php dan aktivitas dari IP di daftar IOC.

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
| access.log:1 | 172.30.0.1 - - \[29/Oct/2026:05:19:47 +0000\] "GET / HTTP/1.1" 200 298 "-" "webforensics-lab/1.0 scenario-f" "-" |
| access.log:4 | 172.30.0.1 - - \[29/Oct/2026:05:19:53 +0000\] "GET /admin/login.php?username=admin\&password=wrong-lab-password HTTP/1.1" 401 355 "-" "webforensics-lab/1.0 scenario-f" "-" |
| access.log:5 | 172.30.0.1 - - \[29/Oct/2026:05:19:55 +0000\] "GET /admin/login.php?username=admin%27+OR+%271%27%3D%271+--+\&password= HTTP/1.1" 200 359 "-" "webforensics-lab/1.0 scenario-f" "-" |
| access.log:6 | 172.30.0.1 - - \[29/Oct/2026:05:19:57 +0000\] "POST /admin/auth\_upload.php HTTP/1.1" 200 51 "-" "webforensics-lab/1.0 scenario-f" "-" |
| uploads/scenario-f-marker.php @c2f45202f02a | SHA-256 c2f45202f02ab18a6ad3965db67be368436a3a245819798ad1601464405f838c |
| access.log:7 | 172.30.0.1 - - \[29/Oct/2026:05:19:59 +0000\] "GET /uploads/scenario-f-marker.php HTTP/1.1" 200 37 "-" "webforensics-lab/1.0 scenario-f" "-" |

## Lampiran B. Reproduksibilitas

- **Versi alat:** 0.1.0
- **Versi ruleset:** 0.1.0
- **Hash konfigurasi:** c5151d3a2f13b07748750ef54e0aa218107778fc0a16cbf3101325edba953255

### File input

| File | SHA-256 | Ukuran |
|---|---|---|
| access.log | d790e8e4e30e74b214ba5a76d631e9b48355ba6e2004189ffe7d72d01172bdb4 | 980 byte |
| manifest.tsv | dc514b240fa3667f9b7af0ce486c823e96b308dac532485ad6e4c45e91d98d7f | 1987 byte |

Input, versi, dan konfigurasi yang sama menghasilkan laporan yang sama persis.
