# Laporan Insiden Website

_WF-EA5033B89A · 2026-10-28 09:00:00 WIB_

## 1. Ringkasan

- Ditemukan 1 file mencurigakan yang terkait dengan 1 alamat IP. Aktivitas pertama aktor pada 2026-10-28 10:48:52 WIB, terakhir pada 2026-10-28 10:49:02 WIB.
- Titik masuk yang paling mungkin: kelemahan yang belum bisa dipastikan lewat POST /admin/login.php pada 2026-10-28 10:48:58 WIB (keyakinan rendah).

### Alur serangan

- \#2 2026-10-28 10:48:58 WIB: Login berhasil dengan cara yang tidak terlihat di log: POST /admin/login.php → 200.
- \#3 2026-10-28 10:49:00 WIB: Request yang menulis uploads/scenario-b-marker.php: POST /admin/auth\_upload.php → 200.
- \#4 2026-10-28 10:49:00 WIB: File uploads/scenario-b-marker.php dibuat (SHA-256 105ddd6ab59b…).
- \#5 2026-10-28 10:49:02 WIB: File uploads/scenario-b-marker.php diakses: GET /uploads/scenario-b-marker.php → 200.

## 2. Informasi Kasus

- **ID kasus:** WF-EA5033B89A
- **Analis:** -
- **Host target:** 9f61b9407738
- **Laporan dibuat:** 2026-10-28 09:00:00 WIB
- **Zona waktu laporan:** WIB (UTC+07:00)

### Cakupan bukti

- **Periode access log:** 2026-10-28 10:48:52 WIB s.d. 2026-10-28 10:49:02 WIB
- **Access log:** 6 baris terbaca
- **Error log:** 2 entri
- **Webroot:** 11 file
- **Bukti dikumpulkan:** 2026-10-28 10:49:02 WIB
- **Baseline:** tidak ada

## 3. Kronologi Serangan

| # | Waktu | Dasar waktu | Fase (ATT\&CK) | Aktor | Kejadian | Keyakinan | Bukti |
|---|---|---|---|---|---|---|---|
| #1 | 2026-10-28 10:48:52 WIB | log | - | 192.0.2.10 | Login gagal: POST /admin/login.php → 401. | tinggi | access.log:1 |
| #2 | 2026-10-28 10:48:58 WIB | log | Initial Access (akses awal) · T1078 | 192.0.2.10 | **AKAR MASALAH: Login berhasil dengan cara yang tidak terlihat di log: POST /admin/login.php → 200.** | rendah | access.log:4 |
| #3 | 2026-10-28 10:49:00 WIB | log | Persistence (bertahan) · T1505.003 | 192.0.2.10 | Request yang menulis uploads/scenario-b-marker.php: POST /admin/auth\_upload.php → 200. | tinggi | access.log:5, uploads/scenario-b-marker.php @105ddd6ab59b, error.log:2 |
| #4 | 2026-10-28 10:49:00 WIB | btime | Persistence (bertahan) · T1505.003 | - | File uploads/scenario-b-marker.php dibuat (SHA-256 105ddd6ab59b…). | tinggi | uploads/scenario-b-marker.php @105ddd6ab59b |
| #5 | 2026-10-28 10:49:02 WIB | log | Persistence (bertahan) · T1505.003 | 192.0.2.10 | File uploads/scenario-b-marker.php diakses: GET /uploads/scenario-b-marker.php → 200. | tinggi | access.log:6 |

### Catatan keyakinan

- \#1: Server membalas 401.
- \#2: Login berhasil, lalu aktor yang sama menulis file di area yang sama. Respons berbeda dari login yang gagal dan tidak diikuti percobaan ulang. Cara login tidak terlihat (misalnya kredensial bocor, atau SQL injection lewat POST).
- \#3: Hanya satu request penulis yang cocok dengan waktu file dibuat. Aktor yang sama kemudian mengakses file ini. Isi POST tidak tercatat di access log, jadi nama file yang diupload tidak terbukti dari log. Didukung error log baris 2 (diasumsikan UTC+0000).
- \#4: Waktu dari btime (waktu file lahir), yang tidak bisa diubah dengan touch.

## 4. Akar Masalah

- **Kejadian:** #2 Login berhasil dengan cara yang tidak terlihat di log: POST /admin/login.php → 200.
- **Jenis kelemahan:** kelemahan yang belum bisa dipastikan
- **Keyakinan:** rendah
- **Bukti:** access.log:4

### Baris log asli

```
172.30.0.3 - - [28/Oct/2026:03:48:58 +0000] "POST /admin/login.php HTTP/1.0" 200 347 "-" "webforensics-lab/1.0 scenario-b" "192.0.2.10"
```

### Alasan

- Login berhasil, lalu aktor yang sama menulis file di area yang sama.
- Respons berbeda dari login yang gagal dan tidak diikuti percobaan ulang.
- Cara login tidak terlihat (misalnya kredensial bocor, atau SQL injection lewat POST).

## 5. File Terdampak

### uploads/scenario-b-marker.php

- **SHA-256:** 105ddd6ab59b87c2013943bab1e598aae952be1f7ae85aac56da08beec344bf6
- **Ukuran:** 26 byte
- **Status baseline:** tidak diketahui (tanpa baseline)
- **Timestamp:** btime 2026-10-28 10:49:00 WIB; ctime 2026-10-28 10:49:00 WIB; mtime 2026-10-28 10:49:00 WIB
- **Sumber timestamp:** manifest collect.sh
- **URL:** /uploads/scenario-b-marker.php

Temuan

- File skrip di folder yang bisa ditulis: uploads/scenario-b-marker.php (FILE-WEBSHELL-WRITABLE-EXEC, keyakinan sedang)

## 6. Perubahan yang Perlu Ditinjau

Tidak ada.

## 7. Indikator Kompromi (IOC)

### Alamat IP

```
192.0.2.10
```

### User agent

```
webforensics-lab/1.0 scenario-b
```

### Hash SHA-256

```
105ddd6ab59b87c2013943bab1e598aae952be1f7ae85aac56da08beec344bf6
```

### Path file

```
uploads/scenario-b-marker.php
```

### URL

```
/uploads/scenario-b-marker.php
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
- Blokir sementara IP berikut: 192.0.2.10.

### Pembersihan (eradication)

- Karantina lalu hapus file berikut setelah disalin sebagai bukti: uploads/scenario-b-marker.php.
- Periksa cara login di /admin/login.php berhasil: kredensial bocor, password lemah, atau SQL injection lewat POST.
- Perbaiki endpoint /admin/auth\_upload.php: batasi ekstensi dan tipe file, simpan upload di luar webroot, dan matikan eksekusi skrip di folder upload.

### Pemulihan (recovery)

- Ganti password admin aplikasi, database, dan semua kredensial yang tersimpan di file konfigurasi webroot.
- Pulihkan webroot dari sumber yang terpercaya (git atau backup sebelum insiden), bukan dengan menghapus file satu per satu saja.
- Setelah pemulihan, pantau akses ke /uploads/scenario-b-marker.php dan aktivitas dari IP di daftar IOC.

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
| access.log:1 | 172.30.0.3 - - \[28/Oct/2026:03:48:52 +0000\] "POST /admin/login.php HTTP/1.0" 401 343 "-" "webforensics-lab/1.0 scenario-b" "192.0.2.10" |
| access.log:4 | 172.30.0.3 - - \[28/Oct/2026:03:48:58 +0000\] "POST /admin/login.php HTTP/1.0" 200 347 "-" "webforensics-lab/1.0 scenario-b" "192.0.2.10" |
| access.log:5 | 172.30.0.3 - - \[28/Oct/2026:03:49:00 +0000\] "POST /admin/auth\_upload.php HTTP/1.0" 200 40 "-" "webforensics-lab/1.0 scenario-b" "192.0.2.10" |
| uploads/scenario-b-marker.php @105ddd6ab59b | SHA-256 105ddd6ab59b87c2013943bab1e598aae952be1f7ae85aac56da08beec344bf6 |
| error.log:2 | 2026/10/28 03:49:00 \[error\] 25#25: \*9 FastCGI sent in stderr: "PHP message: lab upload stored" while reading response header from upstream, client: 172.30.0.3, server: \_, request: "POST /admin/auth\_upload.php HTTP/1.0", upstream: "fastcgi://172.19.0.3:9000", host: "127.0.0.1" |
| access.log:6 | 172.30.0.3 - - \[28/Oct/2026:03:49:02 +0000\] "GET /uploads/scenario-b-marker.php HTTP/1.0" 200 26 "-" "webforensics-lab/1.0 scenario-b" "192.0.2.10" |

## Lampiran B. Reproduksibilitas

- **Versi alat:** 0.1.0
- **Versi ruleset:** 0.1.0
- **Hash konfigurasi:** a327ad9cd4b7b387c7dbfe4a49da4ceac364dddc5291bf29aeadbcf8722e1dda

### File input

| File | SHA-256 | Ukuran |
|---|---|---|
| access.log | d96ea214ae16b239c4fb8d58dab198e0c4423958638ef9c58ff8a5d85209e206 | 822 byte |
| error.log | 6c388822fb88b8a4085db85243cbc9435647aa7b39b248d59e753b722b1bdbf5 | 336 byte |
| manifest.tsv | 8bf9eb254df011c6ab69854b10ca02be21290ea93e01dfd7623b4c8b5330e56d | 1976 byte |

Input, versi, dan konfigurasi yang sama menghasilkan laporan yang sama persis.
