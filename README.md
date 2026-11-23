# WazuhMCP

MCP server berbasis Go untuk **membaca apa yang dilihat Wazuh** (serangan,
kerentanan, agent) dan **merespons**, dengan tingkat otonomi AI yang bisa diatur
lewat feature flag. Target: Wazuh **4.14.x**.

```
AI client ──MCP/HTTP──┐
                      ├─► wazuhmcp ──► Wazuh Manager API (:55000, JWT)   agent, aksi
Manusia ──admin API───┘            └─► Wazuh Indexer     (:9200)         alert, kerentanan
```

Sejak Wazuh 4.8, alert dan data kerentanan disimpan di **Indexer**, bukan di
Manager API, jadi server memakai dua client dengan kredensial terpisah.

## Fitur

**Baca (selalu aktif, read-only)**

| Tool | Fungsi |
|---|---|
| `health` | koneksi Manager dan Indexer, versi, jumlah agent per status |
| `agents_list`, `agent_packages` | daftar agent, paket terpasang |
| `alerts_summary` | top rule, agent, source IP, MITRE, level, aktivitas per waktu |
| `alerts_search`, `alert_get` | cari alert (IP, agent, group, MITRE, level, `from`/`to`), detail satu alert |
| `vulns_summary`, `vulns_search` | kerentanan per severity, agent, paket, CVE |
| `mitigation_options` | opsi mitigasi untuk satu alert atau CVE, lengkap dengan parameter siap pakai |
| `alerts_timeline` | alert urut **terlama dulu**, rentang `from`/`to` absolut (bisa >30 hari), paging `next_cursor` |
| `attacker_profile` | satu IP sumber: kapan pertama/terakhir, agent yang disentuh, teknik MITRE berurutan, user, **login berhasil**, apakah IP itu agent kita sendiri (pivot) |
| `host_triage` | satu agent: proses mencurigakan, port terbuka, akun (uid 0 ganda, ganti password), login dan asalnya, perubahan file di lokasi persistensi, serangan **dari** host ini, kerentanan |
| `ssh_key_usage` | peta login SSH per kunci (fingerprint) → IP sumber → agent → user; menandai pasangan yang muncul di periode terbaru tapi **tidak pernah** di baseline. Untuk kasus private key bocor yang dipakai bersama banyak server |
| `autonomy_status` | apa yang boleh dilakukan AI untuk tiap aksi |

**Prompt MCP:** `investigate_incident`, yaitu permintaan investigasi siap pakai
yang menghasilkan laporan lengkap (lihat [Investigasi penyusupan](#investigasi-penyusupan)).

**Respons (tergantung level otonomi)**

| Tool | Muncul mulai level |
|---|---|
| `response_propose`, `response_plans`, `blocks_list` | `propose` |
| `response_execute` | `approve` |

Aksi: `block_ip` (durasi harus salah satu timeout yang terdaftar di manager), `restart_agent`, `scan_fim`. Wazuh melepas blokir sendiri saat timeout habis; API-nya tidak punya cara membuka blokir lebih awal, jadi tidak ada `unblock_ip`.

## Investigasi penyusupan

Untuk pertanyaan seperti "dari mana saja serangan datang, host mana yang sudah
disusupi, apa yang dilakukan penyerang dan dalam urutan apa". Alur ini juga
tertulis di instruksi server, jadi klien AI mengikutinya sendiri:

1. `alerts_summary` untuk periode panjang (`window: "30d"`, atau `from`/`to`
   untuk data lebih tua): `top_srcips` adalah kandidat sumber, `top_agents`
   host yang terlibat.
2. `attacker_profile` untuk tiap IP: host yang disentuh, teknik MITRE
   berurutan, user yang dicoba, **login yang berhasil**, dan apakah IP itu
   agent kita sendiri (host yang sudah dikuasai lalu dipakai menyerang host lain).
3. `host_triage` untuk tiap host yang berhasil dimasuki atau muncul sebagai
   sumber. Jalankan `scan_fim` **sebelum** `restart_agent`, karena restart bisa
   menghilangkan jejak perubahan file.
   Bila ada dugaan private key SSH bocor, jalankan `ssh_key_usage` (dengan
   `fingerprint` kunci itu) untuk melihat sumber/tujuan yang baru muncul.
4. `alerts_timeline` dengan filter `srcip` atau `agent_id`, mulai dari
   `first_seen` paling awal, untuk urutan kejadian.
5. `mitigation_options` dan `response_propose` untuk langkah mitigasi.

Contoh pertanyaan ke klien AI:

- *Dalam 24 jam terakhir, IP mana saja yang menyerang jaringan kita, dan host
  mana yang jadi sasaran?*
- *Apa saja yang dilakukan IP 203.0.113.7? Apakah dia berhasil login?*
- *Periksa host web-1 (agent 002). Apakah ada tanda host ini sudah disusupi?*
- *Buat urutan kejadian serangan dari IP 203.0.113.7, dari yang paling awal.*
- *Anggap ada penyusup yang mungkin sudah lama tidak ketahuan. Selidiki 30 hari
  terakhir: dari mana saja serangan berasal, host mana yang sudah disusupi, apa
  saja yang dilakukan penyerang secara berurutan, dan langkah mitigasinya.
  Sebutkan juga apa yang tidak bisa kamu pastikan dari data yang ada.*

**Prompt MCP `investigate_incident`.** Di klien yang mendukung prompt MCP
(mis. Claude Desktop atau Claude Code: `/mcp__wazuh__investigate_incident`),
pengguna memilih prompt ini dan mengisi argumen opsional: `period` (`7d`, `30d`,
atau tanggal mulai `2026-10-01`), `srcip`, `agent_id`, dan `language` (default
Bahasa Indonesia). Hasilnya permintaan lengkap berisi alur di atas, aturan
(hanya memakai data dari tool, mencantumkan alert id, tidak mengeksekusi aksi),
dan format laporan: ringkasan, sumber serangan, host yang disusupi beserta
tingkat keyakinan, timeline, mitigasi, dan batasan data. Argumen divalidasi
karena dibaca model sebagai instruksi. Klien yang tidak mendukung prompt (mis.
lewat bot chat) tetap bisa memakai pertanyaan biasa seperti contoh di atas.

Pastikan jawaban benar-benar berasal dari Wazuh: log server harus menampilkan
baris `tool: <nama> ✓` untuk setiap tool yang dipanggil.

Indikator di `host_triage` adalah petunjuk untuk diperiksa, bukan bukti.
Hasilnya hanya sebaik data yang dikumpulkan Wazuh: lihat batasannya di
[Status pengujian](#status-pengujian). Untuk penyusupan yang sudah lama,
lengkapi sumber data di sisi Wazuh: log firewall/IDS, auditd atau who-data di
server data, `logall_json` (indeks archives), dan masa simpan Indexer yang
cukup panjang.

`ssh_key_usage` butuh agent membaca log sshd (`/var/log/auth.log` atau
`/var/log/secure`; agent bawaan tidak selalu memantaunya) dan OpenSSH 6.8+
agar fingerprint SHA256 tercatat. Fingerprint diambil dari `full_log`, jadi
satu panggilan memindai paling banyak 10.000 login terbaru (`truncated: true`
bila terpotong). Penyerang yang memakai kunci dari host yang memang biasa
memakainya **tidak** tertandai; periksa perilakunya dengan `host_triage`.

## Level otonomi

Default-nya **`readonly`**. Atur global dengan `-autonomy`, dan per aksi dengan
`-autonomy-action`.

| Level | AI boleh | Manusia |
|---|---|---|
| `readonly` | hanya membaca; tool respons tidak terdaftar | tidak bisa eksekusi |
| `propose` | membuat plan | mengeksekusi plan lewat admin API |
| `approve` | membuat plan, mengeksekusi plan yang **sudah disetujui** | menyetujui atau menolak |
| `auto` | membuat dan mengeksekusi sendiri | bisa memantau lewat audit log |

```sh
# aman: AI hanya mengusulkan
wazuhmcp serve -autonomy propose

# campuran: scan FIM otomatis, blokir IP perlu persetujuan, restart agent hanya usulan
wazuhmcp serve -autonomy propose \
  -autonomy-action "scan_fim=auto,block_ip=approve"
```

**Guardrail berlaku di semua level** dan tidak bisa diubah dari tool MCP:
protected IP/CIDR dan protected agent (agent `000` selalu), batas agent per plan,
rate limit per aksi per jam, validasi IP/ID/TTL, plan kedaluwarsa (default 30
menit) dan hanya jalan satu kali, serta audit log yang harus berhasil ditulis
sebelum aksi dikirim. Detail: [docs/autonomy.md](docs/autonomy.md).

Ringkasan akses untuk produksi (siapa boleh memanggil apa, izin akun Wazuh,
endpoint yang dipanggil tiap tool, cara menghubungkan Hermes):
[docs/akses-dan-kewenangan.md](docs/akses-dan-kewenangan.md).

## Quick start

```sh
go build -o wazuhmcp .

export WAZUHMCP_API_USER=wazuh-readonly-user
export WAZUHMCP_API_PASSWORD=...
export WAZUHMCP_INDEXER_USER=readonly-indexer-user
export WAZUHMCP_INDEXER_PASSWORD=...

./wazuhmcp serve -ca-file /etc/wazuh/root-ca.pem
```

Server mencetak alamat dan dua token (dibuat otomatis kalau kosong):

- **mcp token** untuk klien AI → `http://127.0.0.1:8090/mcp`
- **admin token** untuk manusia → `http://127.0.0.1:8090/admin/...`. Dua token ini
  harus berbeda; token AI tidak bisa menyetujui plan.

Config klien MCP:

```json
{ "mcpServers": { "wazuh": {
    "type": "http", "url": "http://127.0.0.1:8090/mcp",
    "headers": { "Authorization": "Bearer <mcp token>" } } } }
```

Menyetujui dan mengeksekusi sebagai manusia:

```sh
A="Authorization: Bearer <admin token>"
curl -H "$A" localhost:8090/admin/plans?status=pending
curl -H "$A" -X POST localhost:8090/admin/plans/<id>/approve
curl -H "$A" -X POST localhost:8090/admin/plans/<id>/reject
curl -H "$A" -X POST localhost:8090/admin/plans/<id>/execute   # level propose/approve/auto
curl -H "$A" localhost:8090/admin/blocks
```

## Konfigurasi

Prioritas: flag > environment > default. Daftar lengkap: `wazuhmcp help`.
Password hanya dari environment (`WAZUHMCP_API_PASSWORD`,
`WAZUHMCP_INDEXER_PASSWORD`).

Saran akun: jangan pakai `admin` atau `wazuh-wui`. Buat user `wazuhmcp`
least-privilege. Skrip pembuatnya: `deploy/create-wazuhmcp-users.sh` (dijalankan di
server Wazuh, ikut di paket `make dist`):

| Akun | Izin | Untuk |
|---|---|---|
| Indexer | `read` pada `wazuh-alerts-4.x-*` dan `wazuh-states-vulnerabilities-*` | alert, kerentanan, investigasi |
| API, mode `readonly` | `agent:read`, `syscollector:read` pada `agent:id:*` | agent, paket, `host_triage` (proses, port, akun) |
| API, tambahan untuk respons | `active-response:command`, `agent:restart`, `syscheck:run` | `block_ip`, `restart_agent`, `scan_fim` |

Jangan beri `manager:read`: izin itu membuka `/manager/configuration`, yaitu
seluruh `ossec.conf` termasuk secret integrasi. `health` memakai `GET /` yang
tidak butuh izin.

## Keamanan

- Isi alert dan log adalah **data tak tepercaya** (penyerang bisa menaruh teks di
  log). Output dibersihkan dari karakter kontrol dan dipotong, dan instruksi
  server menyuruh klien menganggapnya data, bukan perintah. Ini mengurangi risiko
  prompt injection tapi tidak menghilangkannya; itulah alasan level `approve`
  ada.
- Query ke Indexer dibuat dari parameter bertipe, bukan DSL mentah; nama index
  tetap; semua hasil dibatasi: maks 50 alert/temuan per panggilan (100 per
  halaman di `alerts_timeline`, lanjut dengan `next_cursor`). `window` relatif
  maks 30 hari; `from`/`to` absolut boleh lebih jauh, sejauh data masih
  disimpan Indexer.
- TLS selalu diverifikasi. Sertifikat Wazuh berisi nama DNS saja (API: `localhost`,
  Indexer: nama node), jadi bila Anda menyambung lewat IP atau tunnel pakai
  `-ca-file` bersama `-api-tls-name` dan `-indexer-tls-name`.
- Dengar di `127.0.0.1` secara default. Kalau dibuka ke jaringan, aktifkan
  HTTPS bawaan dengan `-tls-cert` dan `-tls-key` (`WAZUHMCP_TLS_CERT`,
  `WAZUHMCP_TLS_KEY`, TLS 1.2+), atau taruh di belakang reverse proxy TLS. Tanpa
  salah satunya, token terkirim dalam HTTP biasa (server memberi peringatan).
  Batasi juga port-nya di firewall hanya untuk host klien AI. Langkah lengkap
  untuk server Wazuh: [deploy/INSTALL.md](deploy/INSTALL.md).
- Plan disimpan di memori dan hilang saat restart (disengaja). Audit log
  (`~/.local/state/wazuhmcp/audit.jsonl`, mode 0600) persisten.

## Syarat di sisi Wazuh: active response

API Wazuh hanya menjalankan command yang ada di `ar.conf`, yang dibuat dari blok
`<active-response>` di `ossec.conf` manager dengan nama **`<command><timeout>`**
(contoh: `firewall-drop3600`). Konfigurasi bawaan Wazuh tidak punya blok itu
(hanya komentar), jadi **tambahkan sendiri**, satu per durasi blokir yang ingin
ditawarkan:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>999999</rules_id>   <!-- rule yang tidak pernah muncul: tidak ada pemicu otomatis -->
  <timeout>3600</timeout>
</active-response>
```

Tanpa `rules_id`/`level`/`rules_group`, blok itu akan aktif untuk semua alert,
karena itu contoh di atas memakai id yang tidak pernah terpakai. Lalu petakan
durasi ke command lewat `-block-commands`
(default `300=firewall-drop300,3600=firewall-drop3600`). Nilai `ttl_seconds` pada
`response_propose` hanya boleh salah satu durasi itu. Nama yang diawali `!`
(skrip custom) ditolak. Contoh lengkap ada di `../wazuh-lab/manager/wazuh_manager.conf`.

## Status pengujian

Diuji terhadap **Wazuh 4.14.9 sungguhan** (lab di `../wazuh-lab`): `health`,
agent, ringkasan dan pencarian alert (brute force SSH, MITRE T1110),
`mitigation_options`, alur propose, approve, execute dengan pemasangan rule
iptables nyata di agent, dan pelepasan otomatis oleh Wazuh. Hal yang ditemukan dan
sudah diperbaiki lewat lab: sertifikat Wazuh hanya berisi nama DNS (lihat
`-api-tls-name`), nama command active response, dan TTL.

Juga diuji (2026-11-18) memakai akun least-privilege `wazuhmcp` dari
`create-wazuhmcp-users.sh`, bukan admin: semua tool baca, `scan_fim` dengan
`-autonomy-action scan_fim=auto` (tanpa persetujuan), `restart_agent` lewat
approve (eksekusi sebelum approve ditolak; agent kembali tersambung ~30 detik),
`block_ip`, serta `vulns_search`, `vulns_summary` dan `mitigation_options` per CVE
dengan data nyata (8 CVE pada paket `sudo` yang diturunkan versinya). Izin
role tersebut cukup untuk semua tool.

Investigasi (2026-11-18, lab, akun least-privilege): skenario dua sumber
(A brute force lalu login sebagai `deploy`, sudo, akun uid 0 `toor`, listener
`/tmp/.x/nc` di port 4444, file cron; B hanya gagal login). `alerts_summary`
menemukan kedua IP, `attacker_profile` membedakan A (login berhasil) dari B,
`host_triage` memunculkan semua jejak, `alerts_timeline` mem-paging 17 event A
berurutan. Temuan dari lab: login yang berhasil setelah brute force muncul
sebagai rule **40112** (grup `attacks`), bukan `authentication_success`;
restart agent sebelum `scan_fim` bisa menghilangkan perubahan file yang terjadi
sebelumnya.

Yang tidak bisa dilihat alat ini: host tanpa agent, aktivitas yang tidak memicu
rule (mis. membaca `/etc/shadow` tanpa auditd), pemindaian jaringan tanpa log
firewall/IDS, dan data yang lebih tua dari masa simpan Indexer. Inventory
(proses, port, akun) adalah hasil scan syscollector terakhir, bukan tampilan
langsung.

Belum diuji: mode `auto` untuk `block_ip`/`restart_agent` (guardrail sama),
lateral movement antar dua agent nyata (baru unit test), dan apa pun di Wazuh
produksi.

## Belum ada (rencana)

Web UI / TUI untuk antrean persetujuan (sementara lewat admin API), SSE untuk
alert realtime, manajemen rule dan decoder, CDB list, multi-cluster, aksi
containment (isolasi host).

## Pengembangan

```sh
make test       # go test -race ./... + scripts/test-update.sh
make build
```

**Rilis untuk `wazuhmcp-update`** (server produksi memperbarui diri dari GitHub
Releases, lihat `deploy/INSTALL.md`):

```sh
# sekali: kunci penanda tangan, sebaiknya di hardware key (-t ed25519-sk) atau ber-passphrase
ssh-keygen -t ed25519 -f ~/.ssh/wazuhmcp-release -C wazuhmcp-release
echo "wazuhmcp-release namespaces=\"wazuhmcp-release\" $(cut -d' ' -f1,2 ~/.ssh/wazuhmcp-release.pub)" > deploy/allowed_signers
# tiap rilis: commit, tag vX.Y.Z, lalu
make release    # dist/wazuhmcp-linux-amd64.tar.gz + .sig: unggah keduanya ke rilis tag itu
```

Penanda tangan = siapa pun yang memegang `~/.ssh/wazuhmcp-release`: kunci ini
setara akses ke semua agent Wazuh. Bila bocor, buat kunci baru dan minta pengelola
mengganti `/etc/wazuhmcp/allowed_signers`.

Struktur: `internal/policy` (level dan guardrail), `internal/plans`,
`internal/response` (satu-satunya jalur eksekusi), `internal/audit`,
`internal/wazuh/{api,indexer}`, `internal/mcpserver` (tool), `internal/app`
(HTTP + admin API), `internal/config`.
