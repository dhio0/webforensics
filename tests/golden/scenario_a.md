# Laporan Insiden Website

_WF-16040EE35A · 2026-10-28 09:00:00 WIB_

## 1. Ringkasan

- Ditemukan 1 file mencurigakan yang terkait dengan 1 alamat IP. Aktivitas pertama aktor pada 2026-10-29 12:16:08 WIB, terakhir pada 2026-10-29 12:16:18 WIB.
- Titik masuk yang paling mungkin: unrestricted file upload (upload tanpa validasi) lewat POST /admin/upload.php pada 2026-10-29 12:16:16 WIB (keyakinan sedang).

### Alur serangan

- \#5 2026-10-29 12:16:16 WIB: Upload yang menulis uploads/lab-marker.php tanpa login sebelumnya: POST /admin/upload.php → 200.
- \#6 2026-10-29 12:16:16 WIB: File uploads/lab-marker.php dibuat (SHA-256 52d31ac74301…).
- \#7 2026-10-29 12:16:18 WIB: File uploads/lab-marker.php diakses: GET /uploads/lab-marker.php → 200.

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
| #2 | 2026-10-29 12:16:10 WIB | log | - | 172.30.0.1 | Aktivitas aktor sebelum file ditulis: GET /product.php → 200. | tinggi | access.log:2 |
| #3 | 2026-10-29 12:16:12 WIB | log | - | 172.30.0.1 | Aktivitas aktor sebelum file ditulis: GET /admin/upload.php → 200. | tinggi | access.log:3 |
| #4 | 2026-10-29 12:16:14 WIB | log | Initial Access (akses awal) · T1190 | 172.30.0.1 | Percobaan eksploitasi: GET /product.php → 200 (SQL injection (tautologi)). | sedang | access.log:4 |
| #5 | 2026-10-29 12:16:16 WIB | log | Initial Access (akses awal) · T1190 | 172.30.0.1 | **AKAR MASALAH: Upload yang menulis uploads/lab-marker.php tanpa login sebelumnya: POST /admin/upload.php → 200.** | tinggi (sebagai titik masuk: sedang) | access.log:5, uploads/lab-marker.php @52d31ac74301 |
| #6 | 2026-10-29 12:16:16 WIB | btime | Persistence (bertahan) · T1505.003 | - | File uploads/lab-marker.php dibuat (SHA-256 52d31ac74301…). | tinggi | uploads/lab-marker.php @52d31ac74301 |
| #7 | 2026-10-29 12:16:18 WIB | log | Persistence (bertahan) · T1505.003 | 172.30.0.1 | File uploads/lab-marker.php diakses: GET /uploads/lab-marker.php → 200. | tinggi | access.log:6 |

### Catatan keyakinan

- \#5: Hanya satu request penulis yang cocok dengan waktu file dibuat. Aktor yang sama kemudian mengakses file ini. Isi POST tidak tercatat di access log, jadi nama file yang diupload tidak terbukti dari log.
- \#6: Waktu dari btime (waktu file lahir), yang tidak bisa diubah dengan touch.

## 4. Akar Masalah

- **Kejadian:** #5 Upload yang menulis uploads/lab-marker.php tanpa login sebelumnya: POST /admin/upload.php → 200.
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

### Baris kode yang rentan

- **Lokasi:** product.php:4
- **Kenapa dianalisis:** endpoint yang diserang SQL injection oleh penyerang dan menjawab 2xx (belum tentu titik masuk)
- **Keyakinan:** tinggi
- **Input dari:** \$\_GET\['id'\]
- **Query dijalankan di:** product.php:5 (\$pdo-\>query)
- **Bukti:** product.php @d80c2c86cba7

```
$query = "SELECT id, name FROM products WHERE id = $id";
```

Contoh perbaikan (prepared statement)

```
$stmt = $pdo->prepare("SELECT id, name FROM products WHERE id = ?");
$stmt->execute([$id]);
```

- **File yang dianalisis:** admin/upload.php, product.php

## 5. File Terdampak

### uploads/lab-marker.php

- **SHA-256:** 52d31ac74301cc8fd601913c9cc75e1bc0b2f2ffd26fe71b9864200eda78865d
- **Ukuran:** 24 byte
- **Status baseline:** tidak diketahui (tanpa baseline)
- **Timestamp:** btime 2026-10-29 12:16:16 WIB; ctime 2026-10-29 12:16:16 WIB; mtime 2026-10-29 12:16:16 WIB
- **Sumber timestamp:** manifest webroot
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
- Ganti query di product.php baris 4 dengan prepared statement (contoh perbaikan ada di bagian Akar Masalah).

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
- Analisis kode hanya mencari SQL injection di file PHP yang terlibat dan file yang di-include-nya (satu tingkat, dari pola path include), per file dan per fungsi. Alur lewat pemanggilan fungsi, input dari framework, dan ORM tidak dilacak, jadi "tidak ditemukan" bukan berarti aman. Celah upload belum dilokalisasi di kode.

## Lampiran A. Rujukan Bukti

| Rujukan | Kutipan |
|---|---|
| access.log:1 | 172.30.0.1 - - \[29/Oct/2026:05:16:08 +0000\] "GET / HTTP/1.1" 200 298 "-" "webforensics-lab/1.0 scenario-a" "-" |
| access.log:2 | 172.30.0.1 - - \[29/Oct/2026:05:16:10 +0000\] "GET /product.php?id=1 HTTP/1.1" 200 197 "-" "webforensics-lab/1.0 scenario-a" "-" |
| access.log:3 | 172.30.0.1 - - \[29/Oct/2026:05:16:12 +0000\] "GET /admin/upload.php HTTP/1.1" 200 317 "-" "webforensics-lab/1.0 scenario-a" "-" |
| access.log:4 | 172.30.0.1 - - \[29/Oct/2026:05:16:14 +0000\] "GET /product.php?id=1+OR+1%3D1 HTTP/1.1" 200 223 "-" "webforensics-lab/1.0 scenario-a" "-" |
| access.log:5 | 172.30.0.1 - - \[29/Oct/2026:05:16:16 +0000\] "POST /admin/upload.php HTTP/1.1" 200 44 "-" "webforensics-lab/1.0 scenario-a" "-" |
| uploads/lab-marker.php @52d31ac74301 | SHA-256 52d31ac74301cc8fd601913c9cc75e1bc0b2f2ffd26fe71b9864200eda78865d |
| access.log:6 | 172.30.0.1 - - \[29/Oct/2026:05:16:18 +0000\] "GET /uploads/lab-marker.php HTTP/1.1" 200 35 "-" "webforensics-lab/1.0 scenario-a" "-" |
| product.php @d80c2c86cba7 | SHA-256 d80c2c86cba7c17c99b964c776ecc45d92874b73b57d4718b07063d80244d3b5 |

## Lampiran B. Reproduksibilitas

- **Versi alat:** 0.1.0
- **Versi ruleset:** 0.1.0
- **Hash konfigurasi:** 7cabfdcdf016d39c2da7bcee773e1d9849ef20e55c633338b4fe17124069ca0d

### File input

| File | SHA-256 | Ukuran |
|---|---|---|
| access.log | 27d5072520346aa778ef58b90d89f073afe4541ca6bf382183c60cc460138d17 | 760 byte |
| manifest.tsv | 917ceb04335113a0c83d87337185c8f126f9fed19aa37970fff53f81aa22feec | 1973 byte |

Input, versi, dan konfigurasi yang sama menghasilkan laporan yang sama persis.
