# Pemasangan WazuhMCP di server Wazuh (Ubuntu 24.04, tanpa kontainer)

WazuhMCP adalah satu file binary (Go, statis, tanpa dependensi). Ia berjalan sebagai
service systemd dengan user sistem `wazuhmcp` tanpa hak root, membaca Wazuh lewat
`127.0.0.1`, dan melayani klien AI di server02 (182.253.222.86) lewat HTTPS port 8090.

Isi paket: `wazuhmcp` (binary linux/amd64), `wazuhmcp.service`, `wazuhmcp.env.example`, `INSTALL.md`.

## 1. Pasang binary dan user

```bash
tar xzf wazuhmcp-*-linux-amd64.tar.gz && cd wazuhmcp-*-linux-amd64
sudo install -m 0755 wazuhmcp /usr/local/bin/wazuhmcp
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wazuhmcp
sudo install -d -m 0750 -o root -g wazuhmcp /etc/wazuhmcp
```

## 2. Sertifikat

```bash
# a) Yang dipercaya WazuhMCP: cert API Wazuh (self-signed) + root CA indexer
sudo sh -c 'cat /var/ossec/api/configuration/ssl/server.crt /etc/wazuh-indexer/certs/root-ca.pem > /etc/wazuhmcp/wazuh-ca.pem'
sudo chmod 0644 /etc/wazuhmcp/wazuh-ca.pem

# b) Sertifikat HTTPS WazuhMCP sendiri (untuk klien di server02), berlaku 2 tahun
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
  -subj "/CN=wazuhmcp" -addext "subjectAltName=IP:163.7.16.251" \
  -keyout /etc/wazuhmcp/tls.key -out /etc/wazuhmcp/tls.crt
sudo chown root:wazuhmcp /etc/wazuhmcp/tls.key && sudo chmod 0640 /etc/wazuhmcp/tls.key
```

Kirim `/etc/wazuhmcp/tls.crt` (publik, bukan rahasia) ke pengelola server02 agar kliennya memercayai WazuhMCP.

## 3. Akun Wazuh dan konfigurasi

Buat user `wazuhmcp` di Indexer dan di API dengan izin sesuai daftar permintaan akses
(Indexer: `read` pada `wazuh-alerts-4.x-*` dan `wazuh-states-vulnerabilities-*`;
API: `agent:read`, `syscollector:read`, `active-response:command`, `agent:restart`, `syscheck:run`
pada `agent:id:*`; tanpa `manager:read`).

```bash
sudo install -m 0640 -o root -g wazuhmcp wazuhmcp.env.example /etc/wazuhmcp/wazuhmcp.env
openssl rand -hex 24   # jalankan dua kali: WAZUHMCP_TOKEN dan WAZUHMCP_ADMIN_TOKEN (harus berbeda)
sudo nano /etc/wazuhmcp/wazuhmcp.env   # isi password API/Indexer dan kedua token
```

- `WAZUHMCP_TOKEN` diberikan ke pengelola klien AI (server02).
- `WAZUHMCP_ADMIN_TOKEN` hanya untuk manusia yang menyetujui aksi; jangan diberikan ke klien AI.

Jika nama di sertifikat API bukan `localhost`, sesuaikan `WAZUHMCP_API_TLS_NAME`:
`sudo openssl x509 -in /var/ossec/api/configuration/ssl/server.crt -noout -ext subjectAltName`

## 4. Jalankan

```bash
sudo install -m 0644 wazuhmcp.service /etc/systemd/system/wazuhmcp.service
sudo systemctl daemon-reload
sudo systemctl enable --now wazuhmcp
sudo systemctl status wazuhmcp
sudo journalctl -u wazuhmcp -n 30
```

## 5. Firewall: port 8090 hanya untuk server02

```bash
sudo ufw allow from 182.253.222.86 to any port 8090 proto tcp
```

Setelah WazuhMCP berjalan, port 55000 dan 9200 tidak perlu lagi dibuka untuk server02
(WazuhMCP membacanya lewat 127.0.0.1); aturan firewall sebelumnya boleh dicabut.

## 6. Cek

```bash
curl --cacert /etc/wazuhmcp/tls.crt https://163.7.16.251:8090/healthz      # ok
TOKEN=$(sudo sed -n 's/^WAZUHMCP_TOKEN=//p' /etc/wazuhmcp/wazuhmcp.env)
curl --cacert /etc/wazuhmcp/tls.crt -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"check","version":"0"}}}' \
  https://163.7.16.251:8090/mcp | head -c 200; echo
```

Jika WazuhMCP gagal terhubung ke Wazuh, `journalctl -u wazuhmcp` menampilkan penyebabnya
(password salah, izin kurang, atau sertifikat tidak cocok).

## Blokir IP (opsional)

Agar aksi blokir IP bisa dijalankan, tambahkan di `/var/ossec/etc/ossec.conf` manager,
lalu `sudo systemctl restart wazuh-manager`:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>999999</rules_id>
  <timeout>300</timeout>
</active-response>
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>999999</rules_id>
  <timeout>3600</timeout>
</active-response>
```

`rules_id` 999999 tidak ada, jadi blok ini tidak terpicu otomatis; ia hanya mendaftarkan
command `firewall-drop300` dan `firewall-drop3600`. Wazuh melepas blokir sendiri setelah waktunya habis.

## Pembaruan dan pencopotan

```bash
# update: ganti binary lalu restart
sudo install -m 0755 wazuhmcp /usr/local/bin/wazuhmcp && sudo systemctl restart wazuhmcp
# copot
sudo systemctl disable --now wazuhmcp
sudo rm /etc/systemd/system/wazuhmcp.service /usr/local/bin/wazuhmcp
sudo rm -r /etc/wazuhmcp /var/lib/wazuhmcp   # termasuk audit log
sudo userdel wazuhmcp
```
