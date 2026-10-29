# Laporan Insiden Website

_WF-54BD23F4D5 · 2026-10-28 09:00:00 WIB_

## 1. Ringkasan

- Ditemukan 1 file mencurigakan yang terkait dengan 1 alamat IP. Aktivitas pertama aktor pada 2026-10-29 12:18:59 WIB, terakhir pada 2026-10-29 12:19:01 WIB.
- Titik masuk yang paling mungkin: unrestricted file upload (upload tanpa validasi) lewat POST /admin/upload.php pada 2026-10-29 12:18:59 WIB (keyakinan sedang).

### Alur serangan

- \#1 2026-10-29 12:18:59 WIB: Upload yang menulis uploads/scenario-e-marker.php tanpa login sebelumnya: POST /admin/upload.php → 200.
- \#2 2026-10-29 12:18:59 WIB: File uploads/scenario-e-marker.php dibuat (SHA-256 3a33ab856f7e…).
- \#3 2026-10-29 12:19:01 WIB: File uploads/scenario-e-marker.php diakses: GET /uploads/scenario-e-marker.php → 200.
- \#4 2026-10-29 12:19:03 WIB: Timestamp uploads/scenario-e-marker.php kemungkinan dipalsukan (timestomping).

## 2. Informasi Kasus

- **ID kasus:** WF-54BD23F4D5
- **Analis:** -
- **Host target:** 705740dbd2a2
- **Laporan dibuat:** 2026-10-28 09:00:00 WIB
- **Zona waktu laporan:** WIB (UTC+07:00)

### Cakupan bukti

- **Periode access log:** 2026-10-29 12:18:53 WIB s.d. 2026-10-29 12:19:08 WIB
- **Access log:** 7 baris terbaca
- **Error log:** 1 entri
- **Webroot:** 11 file
- **Bukti dikumpulkan:** 2026-10-29 12:19:16 WIB
- **Baseline:** 10 file

## 3. Kronologi Serangan

| # | Waktu | Dasar waktu | Fase (ATT\&CK) | Aktor | Kejadian | Keyakinan | Bukti |
|---|---|---|---|---|---|---|---|
| #1 | 2026-10-29 12:18:59 WIB | log | Initial Access (akses awal) · T1190 | 192.0.2.31 | **AKAR MASALAH: Upload yang menulis uploads/scenario-e-marker.php tanpa login sebelumnya: POST /admin/upload.php → 200.** | tinggi (sebagai titik masuk: sedang) | access.log:4, uploads/scenario-e-marker.php @3a33ab856f7e, error.log:1 |
| #2 | 2026-10-29 12:18:59 WIB | btime | Persistence (bertahan) · T1505.003 | - | File uploads/scenario-e-marker.php dibuat (SHA-256 3a33ab856f7e…). | tinggi | uploads/scenario-e-marker.php @3a33ab856f7e |
| #3 | 2026-10-29 12:19:01 WIB | log | Persistence (bertahan) · T1505.003 | 192.0.2.31 | File uploads/scenario-e-marker.php diakses: GET /uploads/scenario-e-marker.php → 200. | tinggi | access.log:5 |
| #4 | 2026-10-29 12:19:03 WIB | ctime | Defense Evasion (menghindari deteksi) · T1070.006 | - | Timestamp uploads/scenario-e-marker.php kemungkinan dipalsukan (timestomping). | sedang | uploads/scenario-e-marker.php @3a33ab856f7e |

### Catatan keyakinan

- \#1: Hanya satu request penulis yang cocok dengan waktu file dibuat. Aktor yang sama kemudian mengakses file ini. Isi POST tidak tercatat di access log, jadi nama file yang diupload tidak terbukti dari log. Didukung error log (error.log baris 1, diasumsikan UTC+0000).
- \#2: Waktu dari btime (waktu file lahir), yang tidak bisa diubah dengan touch.

## 4. Akar Masalah

- **Kejadian:** #1 Upload yang menulis uploads/scenario-e-marker.php tanpa login sebelumnya: POST /admin/upload.php → 200.
- **Jenis kelemahan:** unrestricted file upload (upload tanpa validasi)
- **Keyakinan:** sedang
- **Bukti:** access.log:4, uploads/scenario-e-marker.php @3a33ab856f7e, error.log:1

### Baris log asli

```
172.30.0.3 - - [29/Oct/2026:05:18:59 +0000] "POST /admin/upload.php HTTP/1.0" 200 40 "-" "webforensics-lab/1.0 scenario-e" "192.0.2.31"
```

### Alasan

- Hanya satu request penulis yang cocok dengan waktu file dibuat.
- Aktor yang sama kemudian mengakses file ini.
- Isi POST tidak tercatat di access log, jadi nama file yang diupload tidak terbukti dari log.
- Didukung error log (error.log baris 1, diasumsikan UTC+0000).
- Tidak ada login yang terlihat sebelum request penulis, jadi request itu sendiri dianggap titik masuk.
- Tidak terlihat login bukan berarti tidak ada login: sesi bisa dibuat sebelum periode log.

## 5. File Terdampak

### uploads/scenario-e-marker.php

- **SHA-256:** 3a33ab856f7e7f89d67a73cb05ae9b4b96d0253b5b225e3d0b911636e7170a25
- **Ukuran:** 26 byte
- **Status baseline:** baru
- **Timestamp:** btime 2026-10-29 12:18:59 WIB; ctime 2026-10-29 12:19:03 WIB; mtime 2024-01-15 10:00:00 WIB
- **Sumber timestamp:** manifest collect.sh
- **URL:** /uploads/scenario-e-marker.php

Temuan

- File skrip di folder yang bisa ditulis: uploads/scenario-e-marker.php (FILE-WEBSHELL-WRITABLE-EXEC, keyakinan sedang)
- mtime (2024-01-15 10:00:00 WIB) lebih awal dari btime (2026-10-29 12:18:59 WIB). (FILE-ANTIFORENSICS-TIMESTOMP, keyakinan sedang)

## 6. Perubahan yang Perlu Ditinjau

Tidak ada.

## 7. Indikator Kompromi (IOC)

### Alamat IP

```
192.0.2.31
```

### User agent

```
webforensics-lab/1.0 scenario-e
```

### Hash SHA-256

```
3a33ab856f7e7f89d67a73cb05ae9b4b96d0253b5b225e3d0b911636e7170a25
```

### Path file

```
uploads/scenario-e-marker.php
```

### URL

```
/uploads/scenario-e-marker.php
```

## 8. Celah Bukti

Tidak ada celah bukti yang terdeteksi.

## 9. Aktivitas Serangan Lain (Tidak Terkait Insiden)

Tidak ada.

## 10. Tindakan yang Disarankan

### Penahanan (containment)

- Amankan bukti dulu: salin log dan webroot beserta hash-nya sebelum mengubah apa pun di server.
- Batasi akses ke situs (mode maintenance atau firewall) sampai file berbahaya dihapus.
- Blokir sementara IP berikut: 192.0.2.31.

### Pembersihan (eradication)

- Karantina lalu hapus file berikut setelah disalin sebagai bukti: uploads/scenario-e-marker.php.
- Perbaiki endpoint /admin/upload.php: batasi ekstensi dan tipe file, simpan upload di luar webroot, dan matikan eksekusi skrip di folder upload.

### Pemulihan (recovery)

- Ganti password admin aplikasi, database, dan semua kredensial yang tersimpan di file konfigurasi webroot.
- Pulihkan webroot dari sumber yang terpercaya (git atau backup sebelum insiden), bukan dengan menghapus file satu per satu saja.
- Setelah pemulihan, pantau akses ke /uploads/scenario-e-marker.php dan aktivitas dari IP di daftar IOC.

### Pembelajaran (lessons learned)

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
| access.log:4 | 172.30.0.3 - - \[29/Oct/2026:05:18:59 +0000\] "POST /admin/upload.php HTTP/1.0" 200 40 "-" "webforensics-lab/1.0 scenario-e" "192.0.2.31" |
| uploads/scenario-e-marker.php @3a33ab856f7e | SHA-256 3a33ab856f7e7f89d67a73cb05ae9b4b96d0253b5b225e3d0b911636e7170a25 |
| error.log:1 | 2026/10/29 05:18:59 \[error\] 24#24: \*7 FastCGI sent in stderr: "PHP message: lab upload stored" while reading response header from upstream, client: 172.30.0.3, server: \_, request: "POST /admin/upload.php HTTP/1.0", upstream: "fastcgi://172.21.0.3:9000", host: "127.0.0.1" |
| access.log:5 | 172.30.0.3 - - \[29/Oct/2026:05:19:01 +0000\] "GET /uploads/scenario-e-marker.php HTTP/1.0" 200 26 "-" "webforensics-lab/1.0 scenario-e" "192.0.2.31" |

## Lampiran B. Reproduksibilitas

- **Versi alat:** 0.1.0
- **Versi ruleset:** 0.1.0
- **Hash konfigurasi:** a327ad9cd4b7b387c7dbfe4a49da4ceac364dddc5291bf29aeadbcf8722e1dda

### File input

| File | SHA-256 | Ukuran |
|---|---|---|
| access.log | e956adb21584deab8fb56595f181fc6aab9e366242610ed6d303411693a4a3bf | 944 byte |
| baseline.tsv | 0f2acc4f2ecd64fb107f3f6a7808420f6953dbd5e5f23c201efa8f14818d9ca3 | 1800 byte |
| error.log | d2b6c13f5b53ecf4d3c68e58c43aeb79f0d6da53f01bbc44238d915283717d29 | 272 byte |
| manifest.tsv | f7b3245e98d554bd0c951f5a615f3f6cf6bfcbdb6a50d1980dc0050619ce8af1 | 1987 byte |

Input, versi, dan konfigurasi yang sama menghasilkan laporan yang sama persis.
