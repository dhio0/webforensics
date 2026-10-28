"""Indonesian strings for every message key the engine, rules and report builder emit (D12).

Templates are plain text with `{param}` placeholders. They hold no markup: the renderers
escape the finished text for Markdown or HTML, so a parameter (often attacker-controlled,
like a path or user agent) can never inject markup. `tests/unit/test_messages.py` checks
that every key the code can emit has an entry here.
"""

MESSAGES: dict[str, str] = {
    # --- Timeline events --------------------------------------------------------------
    "timeline.actor_first_seen": "Request pertama aktor ini di log: {method} {path} → {status}.",
    "timeline.recon": "Pemindaian/pengintaian: {method} {path} → {status} ({rule_name}).",
    "timeline.exploit_attempt": "Percobaan eksploitasi: {method} {path} → {status} ({rule_name}).",
    "timeline.login_failed": "Login gagal: {method} {path} → {status}.",
    "timeline.auth_bypass_sqli": "Bypass login dengan SQL injection: {method} {path} → {status}.",
    "timeline.login_method_unknown": (
        "Login berhasil dengan cara yang tidak terlihat di log: {method} {path} → {status}."),
    "timeline.upload_exploit": (
        "Upload yang menulis {file} tanpa login sebelumnya: {method} {path} → {status}."),
    "timeline.write_exploit": (
        "Request yang kemungkinan menulis {file} tanpa login sebelumnya: "
        "{method} {path} → {status}."),
    "timeline.file_write_request": "Request yang menulis {file}: {method} {path} → {status}.",
    "timeline.file_write_candidate": (
        "Kandidat lain penulis {file}: {method} {path} → {status}."),
    "timeline.file_created": "File {path} dibuat (SHA-256 {sha256_short}).",
    "timeline.file_changed": "File {path} terakhir diubah (SHA-256 {sha256_short}).",
    "timeline.file_modified_mtime": (
        "File {path} diubah menurut mtime, yang bisa dipalsukan (SHA-256 {sha256_short})."),
    "timeline.file_invoked": "File {file} diakses: {method} {path} → {status}.",
    "timeline.file_timestomp": "Timestamp {path} kemungkinan dipalsukan (timestomping).",
    # --- Why a time was chosen ----------------------------------------------------------
    "anchor.btime": "Waktu dari btime (waktu file lahir), yang tidak bisa diubah dengan touch.",
    "anchor.ctime": "Waktu dari ctime (perubahan inode terakhir), yang tidak bisa diatur "
                    "dengan touch.",
    "anchor.mtime_only": "Hanya ada mtime, dan mtime mudah dipalsukan. Keyakinan paling "
                         "tinggi: sedang.",
    "anchor.copied_timestamps": "Timestamp berasal dari salinan file, bukan dari server asli. "
                                "Keyakinan paling tinggi: rendah.",
    # --- Which request wrote the file ---------------------------------------------------
    "creation.single_candidate": "Hanya satu request penulis yang cocok dengan waktu file dibuat.",
    "creation.multiple_candidates": "Ada {count} request kandidat di sekitar waktu file dibuat.",
    "creation.same_actor_invoked_file": "Aktor yang sama kemudian mengakses file ini.",
    "creation.no_invocation_by_actor": "Aktor penulis tidak terlihat mengakses file ini.",
    "creation.endpoint_not_upload_like": "Endpoint-nya tidak terlihat seperti endpoint upload.",
    "creation.post_body_not_logged": "Isi POST tidak tercatat di access log, jadi nama file "
                                     "yang diupload tidak terbukti dari log.",
    "creation.no_http_request_found": "Tidak ada request HTTP yang cocok dengan waktu file "
                                      "dibuat. File mungkin ditulis lewat jalur lain "
                                      "(SSH, FTP, deploy) atau log-nya hilang.",
    "creation.error_log_only": "Hanya ditemukan di error log, tanpa baris access log.",
    "creation.alternative_candidate": "Kandidat alternatif. Bukti tidak cukup untuk "
                                      "memilih satu request saja.",
    "error_log.assumed_utc_offset": "Waktu error log diasumsikan UTC{offset}.",
    "error_log.corroborates": "Didukung error log baris {lines} (diasumsikan UTC{offset}).",
    "file.invoked_before_anchor": "File sudah berhasil diakses {count} kali sebelum waktu "
                                  "lahirnya (pertama di baris {first_line}). Timestamp atau "
                                  "riwayat file tidak konsisten.",
    "seed.lonely_write": "File kode ditulis sendirian, di luar batch deploy. Tanpa baseline, "
                         "ini hanya sinyal lemah.",
    # --- Entry point ----------------------------------------------------------------------
    "root.write_without_prior_login": "Tidak ada login yang terlihat sebelum request penulis, "
                                      "jadi request itu sendiri dianggap titik masuk.",
    "root.sqli_login_then_write_same_area": "Login dengan payload SQL injection berhasil, lalu "
                                            "aktor yang sama menulis file di area yang sama.",
    "root.login_then_write_same_area": "Login berhasil, lalu aktor yang sama menulis file di "
                                       "area yang sama.",
    "login.failed_status": "Server membalas {status}.",
    "login.retried": "Aktor mencoba login lagi (baris {retry_line}) tanpa membuka halaman di "
                     "area tersebut.",
    "login.same_response_as_failure": "Respons sama persis (status dan ukuran) dengan login "
                                      "yang gagal.",
    "login.success_unlike_failures": "Respons berbeda dari login yang gagal dan tidak diikuti "
                                     "percobaan ulang.",
    "actor.user_agent_changed": "User agent berubah antara login dan penulisan file (bisa "
                                "ganti tool, bisa juga IP dipakai bersama/NAT).",
    # --- Confidence -----------------------------------------------------------------------
    "confidence.no_login_is_absence_of_evidence": "Tidak terlihat login bukan berarti tidak "
                                                  "ada login: sesi bisa dibuat sebelum "
                                                  "periode log.",
    "confidence.session_link_inferred": "Kaitan login dan upload disimpulkan dari IP dan area "
                                        "yang sama, karena cookie sesi tidak tercatat.",
    "confidence.auth_method_not_visible": "Cara login tidak terlihat (misalnya kredensial "
                                          "bocor, atau SQL injection lewat POST).",
    "confidence.gap_overlap": "Celah bukti {gap} tumpang tindih dengan waktu kejadian ini, "
                              "jadi keyakinan diturunkan.",
    "timestomp.mtime_before_btime": "mtime ({mtime}) lebih awal dari btime ({btime}).",
    "timestomp.mtime_older_than_ctime": "mtime ({mtime}) jauh lebih tua dari ctime ({ctime}).",
    # --- Evidence gaps --------------------------------------------------------------------
    "gap.log_silence": "Tidak ada baris log selama {seconds} detik (ambang lokal {threshold} "
                       "detik). Log mungkin dihapus, dirotasi, atau server mati.",
    "gap.no_log_coverage": "Log tidak mencakup waktu penulisan {path}.",
    "gap.parse_errors": ("{count} baris log tidak bisa dibaca "
                         "(baris {first_line} s.d. {last_line})."),
    "gap.no_baseline": "Tidak ada baseline (salinan bersih) untuk pembanding, jadi status file "
                       "hanya dari heuristik.",
    "gap.no_manifest": "Webroot dibaca tanpa manifest collect.sh, jadi timestamp kurang "
                       "terpercaya.",
    "gap.untrusted_file_timestamps": "Timestamp file berasal dari salinan, bukan server asli.",
    "gap.rotation_boundary": "Batas rotasi log; baris di sekitar batas ini bisa hilang.",
    "gap.missing_timestamps": "Sebagian data tidak punya timestamp.",
    "gap.clock_skew_suspected": "Jam antar sumber bukti diduga tidak sinkron.",
    "gap.post_body_not_logged": "Isi request POST tidak tercatat.",
    # --- Findings (one per rule) ----------------------------------------------------------
    "finding.LOG-SQLI-UNION": "Pola SQL injection UNION SELECT: {matched}",
    "finding.LOG-SQLI-TAUTOLOGY": "Pola SQL injection tautologi (OR 1=1): {matched}",
    "finding.LOG-SQLI-BLIND": "Pola blind SQL injection (sleep/benchmark): {matched}",
    "finding.LOG-SQLI-SCHEMA": "Akses skema atau file lewat SQL: {matched}",
    "finding.LOG-SQLI-QUOTE-COMMENT": "Kutip diikuti komentar SQL: {matched}",
    "finding.LOG-TRAVERSAL-DOTS": "Path traversal (../): {matched}",
    "finding.LOG-TRAVERSAL-SENSITIVE": "Upaya membaca file sensitif: {matched}",
    "finding.LOG-SCANNER-UA": "User agent tool pemindai: {matched}",
    "finding.LOG-WEBSHELL-UPLOAD-DIR": "Akses ke skrip di folder upload: {matched}",
    "finding.LOG-WEBSHELL-CMD-PARAM": "Parameter yang mirip perintah webshell: {matched}",
    "finding.FILE-WEBSHELL-WRITABLE-EXEC": "File skrip di folder yang bisa ditulis: {path}",
    "finding.FILE-WEBSHELL-REQUEST-EXEC": "Fungsi berbahaya {function}() menerima input dari "
                                          "request.",
    "finding.FILE-WEBSHELL-OBFUSCATION": "Konten terobfuskasi ({signal}, {length} karakter).",
    "finding.FILE-PERSISTENCE-ENTRYPOINT-CHANGE": "File entry point {path} berstatus {status}.",
    "finding.CORR-LONELY-EXEC-WRITE": "File kode {path} ditulis di luar batch deploy.",
    "finding.CORR-RARE-POST-TARGET": "File jarang diakses tapi menerima POST: {posts} POST dari "
                                     "{clients} klien, {hits} akses total.",
    "finding.CORR-SQLI-LOGIN-BYPASS": "Login lewat SQL injection ke {path} tampaknya berhasil.",
    # --- Summary (built by report/build.py) -----------------------------------------------
    "summary.compromise_found": "Ditemukan {files} file mencurigakan yang terkait dengan "
                                "{actors} alamat IP. Aktivitas pertama aktor pada {first_at}, "
                                "terakhir pada {last_at}.",
    "summary.root_cause": "Titik masuk yang paling mungkin: {vuln_class} lewat {method} {path} "
                          "pada {at} (keyakinan {confidence}).",
    "summary.root_cause_unknown": "Titik masuk belum bisa ditentukan dari bukti yang ada.",
    "summary.alternatives": "Ada {count} kandidat titik masuk lain. Lihat bagian Akar Masalah.",
    "summary.no_compromise": "Tidak ditemukan file mencurigakan yang terkait dengan request "
                             "HTTP. Ini tidak menjamin server bersih.",
    "summary.gaps_affect": "{count} celah bukti melemahkan kesimpulan. Lihat bagian Celah Bukti.",
    "summary.unexplained": "{count} perubahan file perlu ditinjau manual.",
    "summary.deleted": "{count} file dari baseline sudah tidak ada.",
    "summary.unlinked_bypass": "{count} login lewat SQL injection ke {paths} tampaknya "
                               "berhasil (respons seperti login yang sukses), dari {clients} "
                               "klien yang tidak terkait insiden. Tidak ada yang dituduh, tetapi "
                               "endpoint login ini kemungkinan besar bisa dibobol dan perlu "
                               "diperbaiki.",
    "summary.background": "{count} request berpola serangan dari pihak lain (misalnya bot) "
                          "tidak terkait insiden ini.",
    # --- Recommendations (CSIRT phases) ----------------------------------------------------
    "rec.containment.preserve": "Amankan bukti dulu: salin log dan webroot beserta hash-nya "
                                "sebelum mengubah apa pun di server.",
    "rec.containment.isolate": "Batasi akses ke situs (mode maintenance atau firewall) sampai "
                               "file berbahaya dihapus.",
    "rec.containment.block_ips": "Blokir sementara IP berikut: {ips}.",
    "rec.eradication.remove_files": "Karantina lalu hapus file berikut setelah disalin sebagai "
                                    "bukti: {paths}.",
    "rec.eradication.fix_upload": "Perbaiki endpoint {path}: batasi ekstensi dan tipe file, "
                                  "simpan upload di luar webroot, dan matikan eksekusi skrip "
                                  "di folder upload.",
    "rec.eradication.fix_sqli_login": "Perbaiki query login di {path} dengan prepared "
                                      "statement, lalu periksa query lain yang menyusun SQL "
                                      "dari input user.",
    "rec.eradication.fix_sqli_write": "Perbaiki SQL injection di {path} dengan prepared "
                                      "statement dan cabut hak FILE dari user database aplikasi.",
    "rec.eradication.fix_login": "Periksa cara login di {path} berhasil: kredensial bocor, "
                                 "password lemah, atau SQL injection lewat POST.",
    "rec.eradication.unknown_entry": "Titik masuk belum pasti. Periksa endpoint di kronologi, "
                                     "akun admin, dan akses non-HTTP (SSH, FTP, panel hosting).",
    "rec.recovery.rotate_credentials": "Ganti password admin aplikasi, database, dan semua "
                                       "kredensial yang tersimpan di file konfigurasi webroot.",
    "rec.recovery.restore_clean": "Pulihkan webroot dari sumber yang terpercaya (git atau "
                                  "backup sebelum insiden), bukan dengan menghapus file satu "
                                  "per satu saja.",
    "rec.recovery.revoke_sessions": "Ganti password admin dan akhiri semua sesi login yang "
                                    "aktif, karena pihak lain kemungkinan sempat masuk lewat "
                                    "{paths}.",
    "rec.recovery.review_unexplained": "Tinjau {count} perubahan yang belum terjelaskan sebelum "
                                       "menyatakan server bersih.",
    "rec.recovery.monitor": "Setelah pemulihan, pantau akses ke {urls} dan aktivitas dari IP "
                            "di daftar IOC.",
    "rec.lessons.log_retention": "Perbaiki retensi log dan sinkronisasi waktu (NTP). Celah "
                                 "log membuat sebagian kesimpulan lemah.",
    "rec.lessons.baseline": "Simpan baseline webroot (daftar hash file) secara berkala supaya "
                            "file baru atau berubah bisa dipastikan.",
    "rec.lessons.fim": "Aktifkan pemantauan integritas file (FIM) pada webroot.",
    "rec.lessons.log_uploads": "Catat nama file upload di log aplikasi, karena access log "
                               "tidak mencatat isi POST.",
    # --- Standard limitations ---------------------------------------------------------------
    "limit.automated": "Laporan ini dibuat otomatis dengan aturan deterministik. Kesimpulannya "
                       "perlu diverifikasi analis.",
    "limit.post_body": "Isi request POST tidak tercatat di access log. Payload SQL injection "
                       "lewat POST dan nama file upload tidak terlihat.",
    "limit.timestamps": "Penyerang dengan akses root bisa memalsukan timestamp file. Alat ini "
                        "hanya mendeteksi ketidakkonsistenan, tidak bisa membuktikan keaslian.",
    "limit.log_tampering": "Penyerang dengan akses root bisa menghapus baris log. Yang bisa "
                           "dideteksi hanya celah waktu yang mencolok.",
    "limit.shared_ip": "IP yang dipakai bersama (NAT, proxy, CDN tanpa X-Forwarded-For) bisa "
                       "menggabungkan beberapa orang menjadi satu aktor.",
    "limit.no_code_analysis": "Versi ini belum menganalisis kode sumber untuk menunjuk baris "
                              "yang rentan.",
}

RULE_NAMES: dict[str, str] = {
    "LOG-SQLI-UNION": "SQL injection (UNION)",
    "LOG-SQLI-TAUTOLOGY": "SQL injection (tautologi)",
    "LOG-SQLI-BLIND": "Blind SQL injection",
    "LOG-SQLI-SCHEMA": "SQL injection (skema/file)",
    "LOG-SQLI-QUOTE-COMMENT": "SQL injection (kutip + komentar)",
    "LOG-TRAVERSAL-DOTS": "Path traversal",
    "LOG-TRAVERSAL-SENSITIVE": "Path traversal ke file sensitif",
    "LOG-SCANNER-UA": "Tool pemindai",
    "LOG-WEBSHELL-UPLOAD-DIR": "Akses skrip di folder upload",
    "LOG-WEBSHELL-CMD-PARAM": "Parameter perintah webshell",
    "FILE-WEBSHELL-WRITABLE-EXEC": "Skrip di folder writable",
    "FILE-WEBSHELL-REQUEST-EXEC": "Eksekusi input request",
    "FILE-WEBSHELL-OBFUSCATION": "Konten terobfuskasi",
    "FILE-PERSISTENCE-ENTRYPOINT-CHANGE": "Entry point berubah",
    "FILE-ANTIFORENSICS-TIMESTOMP": "Timestomping",
    "CORR-LONELY-EXEC-WRITE": "Penulisan kode di luar deploy",
    "CORR-RARE-POST-TARGET": "POST ke file yang jarang diakses",
    "CORR-SQLI-LOGIN-BYPASS": "Login bypass SQL injection yang tampaknya berhasil",
}

VULN_CLASSES: dict[str, str] = {
    "unrestricted_file_upload": "unrestricted file upload (upload tanpa validasi)",
    "sql_injection_auth_bypass": "SQL injection pada login (bypass autentikasi)",
    "sql_injection_file_write": "SQL injection yang menulis file",
}
VULN_UNKNOWN = "kelemahan yang belum bisa dipastikan"

CONFIDENCE: dict[str, str] = {"high": "tinggi", "medium": "sedang", "low": "rendah"}

TIME_BASIS: dict[str, str] = {
    "log": "log", "btime": "btime", "ctime": "ctime", "mtime": "mtime (lemah)",
    "fim": "FIM", "inferred": "disimpulkan",
}

BASELINE_STATUS: dict[str, str] = {
    "new": "baru", "modified": "berubah", "unchanged": "tidak berubah",
    "unknown": "tidak diketahui (tanpa baseline)",
}

TIMESTAMP_SOURCE: dict[str, str] = {
    "manifest": "manifest collect.sh", "live_stat": "stat langsung di server",
    "wazuh_fim": "Wazuh FIM", "copied": "salinan (kurang terpercaya)",
}

GAP_KINDS: dict[str, str] = {
    "no_log_lines": "Log kosong", "rotation_boundary": "Batas rotasi",
    "parse_errors": "Baris tak terbaca", "missing_timestamps": "Tanpa timestamp",
    "clock_skew_suspected": "Jam tidak sinkron", "no_baseline": "Tanpa baseline",
    "post_body_not_logged": "Isi POST tidak tercatat", "no_manifest": "Tanpa manifest",
    "untrusted_file_timestamps": "Timestamp tidak terpercaya",
}

PHASES: dict[str, str] = {
    "containment": "Penahanan (containment)",
    "eradication": "Pembersihan (eradication)",
    "recovery": "Pemulihan (recovery)",
    "lessons": "Pembelajaran (lessons learned)",
}

# ATT&CK tactic names stay in English (that is how analysts search for them).
TACTICS_ID: dict[str, str] = {
    "Reconnaissance": "Reconnaissance (pengintaian)",
    "Initial Access": "Initial Access (akses awal)",
    "Persistence": "Persistence (bertahan)",
    "Execution": "Execution (eksekusi)",
    "Discovery": "Discovery (penjelajahan)",
    "Defense Evasion": "Defense Evasion (menghindari deteksi)",
}

# Fixed offsets are enough: Indonesia has no daylight saving time.
ZONE_NAMES: dict[str, str] = {"+07:00": "WIB", "+08:00": "WITA", "+09:00": "WIT",
                              "+00:00": "UTC"}

LABELS: dict[str, str] = {
    "title": "Laporan Insiden Website",
    "s.summary": "1. Ringkasan",
    "s.case": "2. Informasi Kasus",
    "s.timeline": "3. Kronologi Serangan",
    "s.root": "4. Akar Masalah",
    "s.files": "5. File Terdampak",
    "s.review": "6. Perubahan yang Perlu Ditinjau",
    "s.iocs": "7. Indikator Kompromi (IOC)",
    "s.gaps": "8. Celah Bukti",
    "s.background": "9. Aktivitas Serangan Lain (Tidak Terkait Insiden)",
    "s.actions": "10. Tindakan yang Disarankan",
    "s.limits": "11. Keterbatasan",
    "s.evidence": "Lampiran A. Rujukan Bukti",
    "s.run": "Lampiran B. Reproduksibilitas",
    "case_id": "ID kasus", "analyst": "Analis", "host": "Host target",
    "generated_at": "Laporan dibuat", "times_in": "Zona waktu laporan",
    "not_set": "-", "redacted": "(disamarkan)",
    "col.time": "Waktu", "col.phase": "Fase (ATT&CK)", "col.actor": "Aktor",
    "col.event": "Kejadian", "col.confidence": "Keyakinan", "col.evidence": "Bukti",
    "col.basis": "Dasar waktu",
    "root_marker": "AKAR MASALAH",
    "root.conf_note": "{event} (sebagai titik masuk: {root})",
    "root.request": "Baris log asli",
    "story": "Alur serangan",
    "confidence": "keyakinan",
    "scope": "Cakupan bukti",
    "scope.period": "Periode access log",
    "scope.access": "Access log",
    "scope.errors": "Error log",
    "scope.webroot": "Webroot",
    "scope.collected_at": "Bukti dikumpulkan",
    "scope.baseline": "Baseline",
    "scope.no_logs": "tidak ada access log yang terbaca",
    "scope.no_baseline": "tidak ada",
    "scope.lines": "baris terbaca",
    "scope.unparsed": "baris gagal dibaca",
    "scope.entries": "entri",
    "scope.files": "file",
    "scope.rejected": "baris manifest ditolak",
    "timeline.notes": "Catatan keyakinan",
    "root.event": "Kejadian", "root.vuln": "Jenis kelemahan", "root.confidence": "Keyakinan",
    "root.why": "Alasan", "root.alternatives": "Kandidat lain",
    "root.none": "Akar masalah tidak dapat ditentukan dari bukti yang ada.",
    "file.sha256": "SHA-256", "file.size": "Ukuran", "file.status": "Status baseline",
    "file.times": "Timestamp", "file.ts_source": "Sumber timestamp", "file.urls": "URL",
    "file.findings": "Temuan", "bytes": "byte",
    "review.unexplained": "File kode berubah tanpa kaitan HTTP yang cukup kuat untuk "
                          "dituduh (misalnya cache CMS atau deploy). Periksa manual:",
    "review.deleted": "Ada di baseline tetapi sekarang hilang:",
    "review.none": "Tidak ada.",
    "ioc.ips": "Alamat IP", "ioc.user_agents": "User agent", "ioc.sha256s": "Hash SHA-256",
    "ioc.paths": "Path file", "ioc.urls": "URL", "ioc.none": "Tidak ada IOC.",
    "gap.id": "ID", "gap.kind": "Jenis", "gap.when": "Rentang waktu", "gap.detail": "Keterangan",
    "gap.affects": "Melemahkan", "gap.none": "Tidak ada celah bukti yang terdeteksi.",
    "gap.affects_none": "-", "gap.events": "{count} kejadian",
    "bg.rule": "Aturan", "bg.count": "Jumlah", "bg.clients": "Klien",
    "bg.top": "Klien terbanyak", "bg.range": "Rentang waktu", "bg.example": "Contoh",
    "bg.none": "Tidak ada.",
    "bg.note": "Request ini cocok dengan pola serangan, tetapi pengirimnya tidak terkait "
               "dengan file yang disusupkan. Biasanya bot atau pemindai otomatis.",
    "ev.ref": "Rujukan", "ev.excerpt": "Kutipan",
    "run.tool": "Versi alat", "run.ruleset": "Versi ruleset", "run.config": "Hash konfigurasi",
    "run.inputs": "File input", "run.note": "Input, versi, dan konfigurasi yang sama "
                                            "menghasilkan laporan yang sama persis.",
    "actor.none": "-",
}
