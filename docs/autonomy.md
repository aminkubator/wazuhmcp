# Otonomi dan guardrail

## Dua lapisan

1. **Level otonomi** (feature flag): siapa yang boleh mengeksekusi sebuah aksi.
2. **Guardrail**: batas keras yang berlaku untuk setiap eksekusi, siapa pun yang
   memicunya dan apa pun levelnya.

Keduanya diatur saat start (flag atau environment). Tidak ada tool MCP yang bisa
mengubahnya, jadi AI tidak bisa memperlebar izinnya sendiri.

## Level

| Level | `response_propose` | `response_execute` oleh AI | Eksekusi oleh admin |
|---|---|---|---|
| `readonly` | tidak ada | tidak ada | ditolak |
| `propose` | ya | tidak ada (tool tidak terdaftar) | ya |
| `approve` | ya | hanya plan berstatus `approved` | ya |
| `auto` | ya | plan `pending` atau `approved` | ya |

Level per aksi: `-autonomy-action "block_ip=auto,restart_agent=propose"`.
Aksi tanpa override memakai `-autonomy`. Tool respons terdaftar kalau **ada**
aksi dengan level cukup, tapi tiap pemanggilan tetap dicek per aksi. Contoh:
`-autonomy readonly -autonomy-action scan_fim=auto` mendaftarkan
`response_execute`, namun `block_ip` tetap ditolak.

| Aksi | Risiko | Parameter |
|---|---|---|
| `scan_fim` | rendah | `agent_ids` |
| `block_ip` | sedang | `agent_ids`, `ip`, `ttl_seconds` (salah satu durasi yang terkonfigurasi, mis. 300 atau 3600) |
| `restart_agent` | tinggi | `agent_ids` |

Tidak ada `unblock_ip`: API Wazuh tidak bisa membuka blokir lebih awal. Blokir
dilepas oleh Wazuh saat `<timeout>` habis, dan server hanya mencatat kedaluwarsanya
di audit log (event `expire`). Lihat README untuk syarat konfigurasi active-response.

Server mencatat peringatan saat `auto` dipasang pada aksi non-rendah.

## Siklus plan

```
propose ─► pending ─► approved ─► executed | failed
              └──────► rejected
```

- Plan kedaluwarsa setelah `-plan-ttl` (default 30 menit): data alert yang basi
  tidak boleh memicu aksi.
- Plan **hanya jalan satu kali** (diklaim atomik, aman untuk panggilan serentak).
  Plan gagal tidak diulang; buat plan baru.
- Plan yang ditolak rate limit tidak dianggap terpakai.
- Hanya admin yang bisa `approve`/`reject`. Token AI tidak membuka `/admin`.

## Guardrail (selalu aktif)

| Guardrail | Atur dengan |
|---|---|
| Protected IP/CIDR tidak bisa diblokir; loopback, multicast, link-local ditolak | `-protected-ips` |
| Protected agent tidak bisa disentuh; agent `000` (manager) selalu | `-protected-agents` |
| Maks agent per plan | `-max-agents` (5) |
| Maks eksekusi per aksi per jam | `-max-per-hour` (10) |
| Format ID agent dan IP divalidasi; durasi blokir harus salah satu yang terkonfigurasi | `-block-commands` |
| `reason` wajib (5 sampai 500 karakter), ikut ke audit log | tetap |
| Audit ditulis **sebelum** aksi dikirim; gagal menulis berarti aksi dibatalkan | tetap |

Validasi dijalankan dua kali: saat `propose` dan lagi saat `execute`.

## Audit log

JSON lines, append-only, mode 0600, default
`~/.local/state/wazuhmcp/audit.jsonl`. Event: `propose`, `approve`, `reject`,
`execute_start`, `execute`, `expire`. Tiap baris memuat aktor (`mcp`, `admin`,
`system`), level efektif, parameter, hasil. Password dan token tidak pernah
masuk. File dibuka hanya kalau ada aksi yang bisa dieksekusi atau diusulkan.

## Memilih level

- Mulai dari `readonly`, lalu `propose` untuk melihat kualitas usulan AI.
- `approve` cocok untuk produksi: AI menyiapkan, manusia menekan tombol.
- `auto` pantas hanya untuk aksi berisiko rendah, atau saat protected list dan
  rate limit sudah diuji. Kombinasi umum:
  `-autonomy approve -autonomy-action "scan_fim=auto"`.
