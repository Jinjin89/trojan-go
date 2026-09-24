# Trojan-Go

A Trojan proxy server (WebSocket over TLS, works behind Cloudflare), deployed with Docker Compose.

## Deploy

**1. Get the code**

```shell
git clone -b fix/stability-and-docker-compose https://github.com/Jinjin89/trojan-go.git
cd trojan-go
```

**2. Edit `deploy/config.json`**

Change these three things:

| Field | Set it to |
| --- | --- |
| `password` | your password (`CHANGE_ME`) |
| `sni` and `hostname` | your domain (`your-domain.com`) |
| `local_port` | the port to listen on (default `443`) |

**3. Add your certificate**

Copy your certificate and private key into `deploy/cert/`, named exactly:

```text
deploy/cert/cert.pem
deploy/cert/key.pem
```

**4. Start**

```shell
docker compose up -d --build
```

Done. Check it with `docker compose logs -f`. There should be no `FATAL` lines.

## Client settings

| Setting | Value |
| --- | --- |
| Protocol | Trojan |
| Address | your domain |
| Port | `local_port` (or `443` when using Cloudflare) |
| Password | your password |
| Transport | WebSocket, path `/ws`, host = your domain |
| TLS | on, SNI = your domain |

## Using Cloudflare

- DNS record: proxied (orange cloud).
- SSL/TLS mode: **Full (strict)**. A Cloudflare Origin Certificate works as the certificate in step 3.
- Network: **WebSockets** on.
- `local_port` must be a port Cloudflare forwards: 443, 2053, 2083, 2087, 2096 or 8443. If 443 is already used on the server, use 2053. Clients still connect to port 443.

## Commands

```shell
docker compose logs -f                      # view logs
docker compose restart                      # apply changes to config.json or certificates
git pull && docker compose up -d --build    # update to the latest code
docker compose down                         # stop
```

If a container named `trojan-go` already exists from an earlier setup, remove it before step 4:

```shell
docker stop trojan-go && docker rm trojan-go
```

## Notes

- `remote_addr` / `remote_port` in the config point to a normal website on the server (e.g. nginx on port 80). Traffic that is not from your clients is sent there, so the server looks like a regular website. It is optional: without it, such traffic is simply closed.
- Certificates in `deploy/cert/` are ignored by git. Don't commit `deploy/config.json` after putting your password in it.
- For debug logs, add `"log_level": 0` to the config and run `docker compose restart`.
