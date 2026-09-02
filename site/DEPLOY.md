# Deploying leastgrant.xyz

> **Current state.** The site is live. The zone is on Cloudflare (`betty` /
> `darwin` nameservers), a remotely-managed tunnel routes the apex to
> `127.0.0.1:8787`, `www` redirects to the apex with path and query preserved,
> and `leastgrant-web.service` is enabled and running on the origin under a
> dedicated unprivileged account. Node 22 is installed from the official tarball
> under `/opt/node`. Pushing to `main` rebuilds the site within ten minutes
> without anyone logging in (§3.2).
>
> Still open: HSTS (see §1.6 — ramp it, do not switch it straight on).
>
> Sections 1 and 2 below are the from-zero instructions, kept because they are
> the record of how this was set up and what to redo if the origin is rebuilt.
> For a routine content update you need nothing: push to `main`.

The shape of it:

```
Internet
   ↓  TLS terminated at the edge
Cloudflare
   ↓  outbound-only connection, port 7844
cloudflared  (already running on the VPS)
   ↓  http://127.0.0.1:8787
node serve.mjs  (loopback only, read-only web root)
   ↓
/srv/leastgrant/current → releases/<stamp>/
```

The origin opens **no inbound port**. Nothing listens on a public interface, there
is no certificate to renew on the VPS, and the only way in from the internet is
through Cloudflare. That is the point of using a tunnel rather than a reverse
proxy on :443.

This assumes `cloudflared` is already installed and running as a service on the
VPS, which it is. What is missing is the Cloudflare zone, the tunnel route, and
the origin service.

---

## 1. What you have to click on Cloudflare

`leastgrant.xyz` is registered but not yet on Cloudflare, so the zone comes
first. Nothing in this section can be automated from the repository, and none of
it has been done for you.

### 1.1 Add the zone

1. Cloudflare dashboard → **Add a domain** → `leastgrant.xyz`.
2. Choose a plan. **Free is sufficient** for this site — everything below works
   on it. The only paid feature worth knowing you are declining is the managed
   WAF ruleset, which matters much less for a site with no forms, no database
   and no dynamic anything.
3. Cloudflare scans for existing DNS records. Since the domain has never served
   anything, expect an empty or near-empty list. Delete anything the registrar
   parked there — a parking A record left in place will happily serve a holding
   page from a stale cache.

### 1.2 Move the nameservers

Cloudflare shows you two nameservers, something like `xxx.ns.cloudflare.com`.
At your registrar, replace the existing authoritative nameservers with exactly
those two. Remove the registrar's own, do not add Cloudflare's alongside them.

Then wait. Propagation is usually minutes and occasionally hours.

**Expected state when it is done:**

```bash
dig +short NS leastgrant.xyz          # the two Cloudflare nameservers, nothing else
```

The dashboard will say **Active**. Do not continue until it does — a tunnel
route created against a pending zone will look created and will not resolve.

### 1.3 Create the tunnel

In the dashboard: **Networking → Tunnels → Create a tunnel**.

- Connector: **Cloudflared**
- Name: `leastgrant-web`

Cloudflare then shows an install command containing a token. **You already have
`cloudflared` running**, so you have two choices:

- **If that connector is free to use for this site**, skip the install and go
  straight to routes. Attach this hostname to the tunnel you already have, and
  ignore the new one.
- **If you want this site on its own tunnel** (cleaner — the site's connector can
  be restarted without touching whatever else that box serves), run the
  dashboard's install command on the VPS. It registers a second `cloudflared`
  service.

Either way: **the token is a secret**. It authenticates as the tunnel. It must
never be committed, pasted into a script in this repository, echoed into a log,
or put into GitHub Actions. It belongs in the `cloudflared` service's own
environment on the VPS and nowhere else.

### 1.4 Route the apex hostname

Open the tunnel → **Routes** → **Add route** → **Published application**.

| field | value |
|---|---|
| Subdomain | *(leave empty — this is the apex)* |
| Domain | `leastgrant.xyz` |
| Path | *(empty)* |
| Service type | `HTTP` |
| Service URL | `localhost:8787` |

Saving this creates the proxied DNS record for the apex automatically. You do
not need to add one by hand, and you should not.

`HTTP` to `localhost` is correct and is not a downgrade: that hop never leaves
the machine. Everything between the visitor and `cloudflared` is TLS, and
`cloudflared` reaches the origin over loopback.

### 1.5 Send `www` to the apex, without creating a second site

Two canonical origins is worse than no `www` at all. Do not point `www` at the
tunnel — redirect it at the edge, before any origin is involved.

1. **DNS → Add record**: type `A`, name `www`, IPv4 `192.0.2.1`, **Proxied**
   (orange cloud). That address is the reserved documentation range and is never
   reached; it exists only so the hostname resolves through Cloudflare and the
   rule below can fire.
2. **Rules → Redirect Rules → Create rule**:
   - Name: `www to apex`
   - When: **Hostname** *equals* `www.leastgrant.xyz`
   - Then: **Dynamic** redirect, expression
     `concat("https://leastgrant.xyz", http.request.uri.path)`
   - Status **301**, **preserve query string** on.

### 1.6 Edge settings worth changing, and the ones to leave alone

**SSL/TLS → Overview.** Leave it on **Automatic**, or set **Full**. Do not set
Flexible. With a tunnel this setting governs how Cloudflare talks to the origin
*service URL*, which is loopback on the same host, so the practical difference is
small — but Flexible is the one mode that means "cleartext to the origin" as a
policy, and it is not a policy this site should have on record.

**SSL/TLS → Edge Certificates:**

- **Always Use HTTPS: on.** Redirects `http://` at the edge.
- **Minimum TLS Version: 1.2.** 1.0 and 1.1 are dead and nothing that needs them
  is going to read a threat model.
- **HSTS: ramp it, do not switch it straight on.**

  It is worth having. Without it, the first time someone types the bare domain
  the browser tries `http://` and an attacker on that network can intercept
  before the 301 arrives. HSTS closes that window.

  It is also the only header here that cannot be taken back. Turning it off
  stops the header being *sent*; every browser that already saw it keeps
  enforcing until `max-age` expires. So start short and raise it:

  | when | max-age | includeSubDomains | preload |
  |---|---|---|---|
  | first | `300` — five minutes | off | off |
  | after a day with no surprises | `86400` | off | off |
  | after a week | `15552000` — six months | deliberate choice | off |

  Set it at Cloudflare, not at the origin. Cloudflare terminates TLS, it is one
  toggle to change, and `serve.mjs` leaves its `--hsts` flag off precisely so
  there is one place this lives rather than two.

  `includeSubDomains` covers every `*.leastgrant.xyz`, including any subdomain
  a future service on this box might want. Through Cloudflare each of those gets
  HTTPS anyway, so the risk is small — but turn it on because you decided to,
  not because it was next to the other checkbox.

  **Do not preload.** It bakes the domain into browser binaries; removal takes
  months and ships on browser release schedules. It only helps people who have
  never visited, and it is the one setting that can genuinely strand you.

**Caching → Configuration:** defaults are fine. The origin already sends
`immutable` for content-hashed assets and `must-revalidate` for HTML, and
Cloudflare respects both. There is no need for a page rule.

**Speed → Optimization: turn everything off, or leave it off.** Specifically:

- **Rocket Loader** rewrites your scripts and injects its own. It would break the
  CSP and defeat the point of `script-src 'self'` with no `unsafe-inline`.
- **Auto Minify** (where still offered) edits files whose hashes this site's
  integrity story depends on.
- **Email Address Obfuscation** injects an inline script. There is no email
  address on the site anyway.
- **Cloudflare Web Analytics / Browser Insights** injects a third-party beacon.
  The site says it has zero third-party JavaScript and zero trackers; turning
  this on would make that a lie.

**Security → Bots:** the free bot fight mode also injects JavaScript. Leave it
off. A static site with no login and no forms has nothing to protect from a bot
that a rate limit would not handle.

---

## 2. The origin, on the VPS

### 2.1 One-time setup

```bash
# A dedicated account with no shell and no home.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin leastgrant

sudo mkdir -p /srv/leastgrant/releases
sudo chown -R "$USER":"$USER" /srv/leastgrant
sudo chmod 755 /srv/leastgrant
```

Node 20 or newer must be on the box. Ubuntu 24.04 ships Node 18, which is below
what this package supports, so install it from nodejs.org rather than adding a
third-party apt repository to the machine that serves a security tool's website:

```bash
V=$(curl -fsSL https://nodejs.org/dist/index.json | grep -o '"version":"v22[0-9.]*"' | head -1 | cut -d'"' -f4)
cd /tmp && curl -fsSLO "https://nodejs.org/dist/$V/node-$V-linux-x64.tar.xz" \
                -O "https://nodejs.org/dist/$V/SHASUMS256.txt"
grep "node-$V-linux-x64.tar.xz" SHASUMS256.txt | sha256sum -c -   # must print OK
sudo mkdir -p /opt/node
sudo tar -xJf "node-$V-linux-x64.tar.xz" -C /opt/node --strip-components=1
sudo ln -sfn /opt/node/bin/node /usr/local/bin/node
```

Check the checksum line actually prints `OK` before extracting; that is the
whole point of downloading `SHASUMS256.txt` separately.

The origin server has zero dependencies, so there is nothing to `npm install` on
the VPS — one `.mjs` file and the built site is the entire deployment.

### 2.2 Install the service

```bash
sudo cp site/deploy/leastgrant-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now leastgrant-web
systemctl status leastgrant-web
```

The unit binds `127.0.0.1:8787` only, mounts the web root read-only, drops every
capability, and denies all network addresses except loopback. Worth confirming:

```bash
systemd-analyze security leastgrant-web    # expect a low (good) exposure score
sudo ss -lntp | grep 8787                  # must show 127.0.0.1:8787, never 0.0.0.0
```

If that second command shows `0.0.0.0:8787`, stop and fix it before doing
anything else: the origin would be directly reachable, and everything Cloudflare
is doing in front of it becomes optional for an attacker.

### 2.3 Firewall

Nothing inbound. If you run a firewall, the correct rule set for this service is
*no rule*, because there is no port to open.

Outbound, `cloudflared` needs:

| direction | destination | port | protocol |
|---|---|---|---|
| outbound | `region1.v2.argotunnel.com`, `region2.v2.argotunnel.com` | 7844 | UDP (QUIC), preferred |
| outbound | the same hosts | 7844 | TCP, fallback |
| outbound | Cloudflare API | 443 | TCP, for registration and updates |

If UDP/7844 is blocked, `cloudflared` falls back to HTTP/2 over TCP with a
performance cost. Force it with `--protocol http2` rather than leaving it to
retry.

---

## 3. Deploying content

Normally you do not. Push to `main` and the origin rebuilds itself within ten
minutes — see [3.2](#32-the-timer-that-does-it-for-you). The manual path below
still exists for a first deploy, for a rollback, and for the times you want to
watch it happen.

### 3.1 By hand

```bash
npm run site:test                    # build + 199 assertions; do not skip
./site/deploy/deploy.sh user@vps
```

The script refuses to run from a dirty working tree, uploads into a new
timestamped release directory, and swaps the `current` symlink with an atomic
rename. No request is served from a half-copied directory.

**`cloudflared` is not restarted, and neither is the web server.** The local
port and the tunnel route never change; only where a symlink points does. That
is the whole reason the layout has a symlink in it.

Rolling back is the same rename in reverse:

```bash
ssh user@vps
ls -1t /srv/leastgrant/releases          # five kept
ln -sfn /srv/leastgrant/releases/<previous> /srv/leastgrant/.next
mv -T /srv/leastgrant/.next /srv/leastgrant/current
curl -sI http://127.0.0.1:8787/ | head -1
```

### 3.2 The timer that does it for you

`main` moving is the only trigger. The origin fetches the public repository over
HTTPS, builds, and swaps the same symlink the manual script does.

**Pull, not push.** GitHub is never given a way into this machine: no deploy
key, no SSH credential in Actions, no inbound port. The version number on the
site comes from `package.json` in the commit being built, so a release that
bumps the version updates the website by virtue of having been pushed.

```bash
sudo useradd --system --home-dir /srv/leastgrant --shell /usr/sbin/nologin leastgrant-deploy
sudo install -o leastgrant-deploy -g leastgrant-deploy -m 0755 \
     site/deploy/update.sh /srv/leastgrant/update.sh
sudo mkdir -p /srv/leastgrant/.home
sudo chown -R leastgrant-deploy:leastgrant-deploy /srv/leastgrant

sudo cp site/deploy/leastgrant-site-update.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now leastgrant-site-update.timer
```

Then watch one cycle rather than trusting it:

```bash
systemctl list-timers leastgrant-site-update.timer
sudo systemctl start leastgrant-site-update.service     # don't wait for the tick
journalctl -u leastgrant-site-update.service -n 30 --no-pager
basename "$(readlink /srv/leastgrant/current)"          # <stamp>-<commit>
```

Every ten minutes, jittered. Almost every run is a `git fetch` and a string
comparison and exits having done nothing.

**It decides from what is deployed, not from what the checkout says.** The live
commit is read off the release directory name, which is `<stamp>-<sha8>`. This
is not incidental. The first version compared `git rev-parse HEAD` against
`origin/main`, and the first time a build failed — `npm ci`, out of a missing
`HOME` — the checkout had already advanced. From then on every run reported
"unchanged, nothing to do" and exited zero while the live site sat a commit
behind. A green timer over a stale site is the worst way for a deploy to break,
and comparing against the artifact makes a failed build simply retry on the next
tick.

Three other things it will refuse to do:

- **Deploy a non-fast-forward.** A force-push upstream stops the deploy and
  waits for a person. A rewritten history should not reach the live site
  quietly.
- **Build from the wrong repository.** The remote URL is checked against a
  literal before anything is fetched.
- **Leave a broken site up.** After the swap it curls the origin, and a
  non-200 fails the unit with the previous release still on disk.

Rollback is unchanged, and needs no network — but the next tick will roll you
forward again. Revert the commit rather than the symlink, or `systemctl stop
leastgrant-site-update.timer` first.

**The deployer does not deploy itself.** `/srv/leastgrant/update.sh` and the two
unit files are copies; editing them in the repository changes nothing on the
origin until you reinstall them with the commands above. This is deliberate — a
script that rewrites itself mid-run is a bad way to find out about a typo — but
it does mean a change to `site/deploy/` is the one change that still needs an
`ssh`.

The Cloudflare Tunnel token stays on this machine and is not involved. It is not
needed to deploy content, and a token that can register as your tunnel is a far
larger credential than "may upload files" — which is the other reason this is a
pull.

---

## 4. Verifying production

Run these against the real domain, not against the origin. A config file that
says the right thing and a response that carries it are different claims.

```bash
# headers
curl -sI https://leastgrant.xyz | grep -iE 'content-security-policy|x-content-type|referrer-policy|permissions-policy|x-frame-options|cross-origin'

# HTTP is redirected, not served
curl -sI http://leastgrant.xyz | head -3

# www redirects to the apex, once, with a 301
curl -sIL https://www.leastgrant.xyz | grep -iE '^HTTP|^location'

# the canonical URL agrees with the address that served it
curl -s https://leastgrant.xyz | grep -o '<link rel="canonical"[^>]*>'

# caching: HTML revalidates, hashed assets are immutable
curl -sI https://leastgrant.xyz | grep -i cache-control
curl -sI "https://leastgrant.xyz/$(curl -s https://leastgrant.xyz | grep -o 'app\.[0-9a-f]*\.css')" | grep -i cache-control

# the page really does fetch nothing from anywhere else
curl -s https://leastgrant.xyz | grep -oE '(src|href)="https?://[^"]+"' | sort -u
```

That last one should print only `github.com` and `www.npmjs.com` links — which
are anchors, not loads. If any other origin appears, something changed.

A quick external opinion, for the parts a curl cannot judge:

- <https://securityheaders.com/?q=https://leastgrant.xyz>
- <https://csp-evaluator.withgoogle.com/> (paste the policy)
- <https://cards-dev.twitter.com/validator> and Discord/Slack, for the share image

### If it does not work

| symptom | cause |
|---|---|
| Error 1033, or "Tunnel not found" | `cloudflared` is not connected. `systemctl status cloudflared`, then check outbound 7844. |
| Error 502 from Cloudflare | The tunnel is up but the origin is not. `systemctl status leastgrant-web`, then `curl http://127.0.0.1:8787/`. |
| The apex resolves but `www` does not | The `www` A record is missing or grey-clouded. It must be proxied for the redirect rule to run. |
| An old page keeps coming back | Cloudflare cache. Purge it, then check `cache-control` on the HTML — it should say `must-revalidate`. |
| The site loads unstyled | The stylesheet is content-hashed. An HTML page cached longer than the asset it references will point at a hash that no longer exists. Purge, and check the HTML is not being cached. |

---

## 5. What is deliberately not here

**No `_headers` file.** That is a Cloudflare Pages mechanism and this is not
Pages. Headers are set by the process that produces the response — `serve.mjs` —
which is also the only place that can guarantee they are on *every* response,
including 404s.

**No Cloudflare Access in front of the site.** It is a public website.

**No health-check endpoint.** `GET /` is the health check.

**No secrets anywhere in this repository.** The only credential in this
architecture is the tunnel token, it lives on the VPS in the `cloudflared`
service's environment, and nothing in `site/` reads it or needs it.

**No deploy credential in GitHub.** Automatic deploys are a pull from a timer on
the origin (§3.2), so there is no deploy key, no SSH secret in Actions, and
nothing to rotate if a workflow is compromised. CI can build the site and fail
the merge; it cannot reach the machine that serves it.
