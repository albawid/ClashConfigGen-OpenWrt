# Clash Config Generator - OpenWrt Edition

Convert proxy URIs (VMess / VLESS / Shadowsocks / Trojan) ke OpenClash YAML config. Termasuk CLI tool dan LuCI web UI yang muncul di menu Services router OpenWrt.

Output **copy-paste ready** - tanpa download file, langsung copy dari terminal atau web UI lalu paste ke konfigurasi OpenClash.

---

## Fitur

- 4 protokol: `vmess://` `vless://` `ss://` `trojan://`
- TLS/nonTLS fleksibel (sesuai URI)
- `skip-cert-verify: true` selalu di-output (flat)
- 2 mode output: full config atau proxies only
- CLI tool untuk penggunaan di terminal
- LuCI web UI di menu Services router
- Pure POSIX shell (CLI), zero dependency selain `base64`
- Client-side JS converter (UI), ringan tanpa beban server

---

## Install

### 1. Transfer IPK ke router

```bash
# Via SCP
scp clash-config-gen_1.1.0-1_all.ipk root@192.168.1.1:/tmp/

# Atau download langsung dari GitHub
# Masuk ke router dulu:
ssh root@192.168.1.1
cd /tmp
curl -LO https://github.com/albawid/ClashConfigGen-OpenWrt/raw/main/clash-config-gen_1.1.0-1_all.ipk
```

### 2. Install

```bash
opkg install /tmp/clash-config-gen_1.1.0-1_all.ipk
```

### 3. Uninstall

```bash
opkg remove clash-config-gen
```

### Dependensi

IPK membutuhkan:
- `coreutils-base64` (biasanya sudah ada di OpenWrt)
- `luci` (untuk web UI)
- `uhttpd` (untuk serve static file)

Jika belum ada:
```bash
opkg update
opkg install coreutils-base64 luci uhttpd
```

---

## Penggunaan CLI

CLI tool berada di `/usr/bin/clash-config-gen`.

### Help

```bash
clash-config-gen -h
```

### Mode Proxies Only (paling sering dipakai)

Output hanya bagian `proxies:` - siap copy-paste ke config OpenClash yang sudah ada:

```bash
clash-config-gen -p 'vmess://eyJhZG...yIn0='
```

Output:
```yaml
proxies:
- name: "(albawid) [VMess - ws] nonTLS ✅"
  type: vmess
  server: biz02.wc-webkuy.web.id
  port: 80
  uuid: 1ca8e13c-f8bb-4feb-a53d-1e059595f1b7
  alterId: 0
  cipher: auto
  udp: true
  tls: false
  skip-cert-verify: true
  network: ws
  ws-opts:
    path: /vmess
    headers:
      Host: biz02.wc-webkuy.web.id
```

### Mode Full Config

Output config lengkap (DNS, proxy-groups, rules) - untuk config baru dari nol:

```bash
clash-config-gen 'vmess://eyJhZG...yIn0='
```

### Multi URI

Pisahkan URI dengan enter atau pipe `|`:

```bash
# Langsung di argumen
clash-config-gen -p 'vmess://...' 'trojan://...' 'vless://...'
```

### Dari File

Simpan URI di file teks (satu per baris), lalu:

```bash
clash-config-gen -p -f proxies.txt
```

### Dari Pipe / Subscription

```bash
# Pipe langsung
curl -sL https://example.com/sub | clash-config-gen -p

# Atau simpan dulu, lalu proses
curl -sL https://example.com/sub -o /tmp/sub.txt
clash-config-gen -p -f /tmp/sub.txt
```

### Pilih DNS Mode

```bash
# Redir-host (default)
clash-config-gen -m redir-host 'vmess://...'

# Fake-ip
clash-config-gen -m fake-ip 'vmess://...'
```

---

## Penggunaan LuCI Web UI

### Akses

Setelah install, buka browser:

```
http://<router_ip>/cgi-bin/luci/admin/services/clash_config_gen
```

Atau navigasi manual: **Services → Clash Config Gen**

### Cara Pakai

1. Paste proxy URIs di textarea "Input Proxy URIs"
2. Pilih jenis config (Standard Redir / Fake IP / Clash.Meta)
3. Pilih DNS mode
4. Centang "Proxies Only" jika hanya butuh bagian proxies (untuk paste ke config OpenClash yang sudah ada)
5. Klik **Generate**
6. Klik **Copy Output** - siap paste ke OpenClash config

### Flow Kerja OpenClash

Cara paling efisien:

1. Generate config di LuCI UI
2. Copy output (mode Proxies Only)
3. Buka OpenClash config editor
4. Paste bagian `proxies:` ke config yang sudah ada
5. Tambahkan nama proxy ke proxy-groups jika perlu

---

## Contoh URI per Protokol

### VMess TLS
```
vmess://eyJhZG...yIn0=
```

### VMess nonTLS
```
vmess://eyJhZG...yIn0=
```

### VLESS TLS
```
vless://uuid@server.com:443?type=ws&path=%2Fvless&host=server.com&security=tls&sni=server.com&fp=chrome
```

### VLESS nonTLS
```
vless://uuid@server.com:80?type=ws&path=%2Fvless&host=server.com&security=none
```

### Trojan TLS
```
trojan://password@server.com:443?security=tls&type=ws&path=%2Ftrojan&host=server.com&sni=server.com&fp=chrome&alpn=http%2F1.1
```

### Trojan nonTLS
```
trojan://password@server.com:80?security=none&type=ws&path=%2Ftrojan&host=server.com
```

### Shadowsocks
```
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@server.com:8388#SS-Proxy
```

---

## Flag CLI

| Flag | Fungsi |
|------|--------|
| `-p` | Proxies only (tanpa header/rules/DNS) |
| `-f <file>` | Baca URI dari file |
| `-m <mode>` | DNS mode: `redir-host` (default) atau `fake-ip` |
| `-h` | Tampilkan help |

---

## Struktur File IPK

```
/usr/bin/clash-config-gen                          # CLI script
/usr/lib/lua/luci/controller/clash_config_gen.lua # LuCI controller
/usr/lib/lua/luci/view/clash_config_gen/config.htm # LuCI view
/usr/share/clash-config-gen/converter.js           # JS converter (shared)
/www/lsgi/clash-config-gen/converter.js            # JS converter (served by uhttpd)
```

---

## Versi Web

Versi web (dengan download file YAML) tersedia di:
- **Live**: https://albawid.github.io/ClashConfigGen/
- **Repo**: https://github.com/albawid/ClashConfigGen

---

## Lisensi

MIT
