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
| `alerts_search`, `alert_get` | cari alert (IP, agent, group, MITRE, level), detail satu alert |
| `vulns_summary`, `vulns_search` | kerentanan per severity, agent, paket, CVE |
| `mitigation_options` | opsi mitigasi untuk satu alert atau CVE, lengkap dengan parameter siap pakai |
| `autonomy_status` | apa yang boleh dilakukan AI untuk tiap aksi |

**Respons (tergantung level otonomi)**

| Tool | Muncul mulai level |
|---|---|
| `response_propose`, `response_plans`, `blocks_list` | `propose` |
| `response_execute` | `approve` |

Aksi: `block_ip` (durasi harus salah satu timeout yang terdaftar di manager), `restart_agent`, `scan_fim`. Wazuh melepas blokir sendiri saat timeout habis; API-nya tidak punya cara membuka blokir lebih awal, jadi tidak ada `unblock_ip`.

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

Saran akun: buat **user Indexer read-only** (akses baca ke `wazuh-alerts-*` dan
`wazuh-states-vulnerabilities-*`) dan **user API Wazuh dengan role minimal**.
Untuk mode `readonly`, role API cukup baca agent. Jangan pakai `admin` atau
`wazuh-wui`.

## Keamanan

- Isi alert dan log adalah **data tak tepercaya** (penyerang bisa menaruh teks di
  log). Output dibersihkan dari karakter kontrol dan dipotong, dan instruksi
  server menyuruh klien menganggapnya data, bukan perintah. Ini mengurangi risiko
  prompt injection tapi tidak menghilangkannya; itulah alasan level `approve`
  ada.
- Query ke Indexer dibuat dari parameter bertipe, bukan DSL mentah; nama index
  tetap; semua hasil dibatasi (maks 50 per panggilan, rentang maks 30 hari).
- TLS selalu diverifikasi. Sertifikat Wazuh berisi nama DNS saja (API: `localhost`,
  Indexer: nama node), jadi bila Anda menyambung lewat IP atau tunnel pakai
  `-ca-file` bersama `-api-tls-name` dan `-indexer-tls-name`.
- Dengar di `127.0.0.1` secara default. Kalau dibuka ke jaringan, taruh di
  belakang reverse proxy TLS.
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

Belum diuji: `restart_agent`, `scan_fim` di Wazuh asli, mode `auto`, dan
`vulns_*` dengan data kerentanan terisi (nama field sudah dicocokkan dengan
mapping indeks asli). Izin role API untuk `/active-response`, `/agents/restart`
dan `/syscheck` perlu dicek bila memakai user selain admin.

## Belum ada (rencana)

Web UI / TUI untuk antrean persetujuan (sementara lewat admin API), SSE untuk
alert realtime, manajemen rule dan decoder, CDB list, multi-cluster, MCP prompts.

## Pengembangan

```sh
make test       # go test -race ./...
make build
```

Struktur: `internal/policy` (level dan guardrail), `internal/plans`,
`internal/response` (satu-satunya jalur eksekusi), `internal/audit`,
`internal/wazuh/{api,indexer}`, `internal/mcpserver` (tool), `internal/app`
(HTTP + admin API), `internal/config`.
