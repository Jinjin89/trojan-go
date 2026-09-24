# Trojan-Go

A Trojan proxy server (WebSocket over TLS, works behind Cloudflare), deployed with Docker Compose.

It comes with a built-in fake website: anyone who is not your proxy client (a browser, a scanner)
sees an ordinary blog, so the server looks like a normal web site. Nothing else needs to be installed.

## Deploy

**1. Get the code**

```shell
git clone -b fix/stability-and-docker-compose https://github.com/Jinjin89/trojan-go.git
cd trojan-go
```

**2. Create `deploy/config.json` from the template**

```shell
cp deploy/config.example.json deploy/config.json
```

Then edit `deploy/config.json` and change these three things:

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

Open `https://your-domain.com` in a browser: you should see the fake website.

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

## Fake website

The site is the static page in `deploy/web/`, served by the `web` container. It listens only on
`127.0.0.1:8088`, so it is never reachable directly from the internet, only through trojan-go.

To use your own site, replace the files in `deploy/web/` (any static HTML works). Changes show up
immediately, no restart needed.

## Notes

- `deploy/config.json` and the certificates in `deploy/cert/` are ignored by git, so your password and keys are never committed and `git pull` never conflicts with them.
- If `docker compose up` fails with an error about `config.json` being a directory, you skipped step 2: run `rm -rf deploy/config.json`, then do step 2.
- For debug logs, add `"log_level": 0` to the config and run `docker compose restart`.
