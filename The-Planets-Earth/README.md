# The Planets: Earth — Walkthrough

> A VulnHub boot2root box built around a custom XOR-encrypted messaging app. Goal: find the user and root flags.

**Category:** Web Enumeration → Crypto (XOR) → Command Injection → Privilege Escalation
**Tools:** `arp-scan`, `nmap`, `dirb`, CyberChef, `netcat`, `ltrace`
**Author:** Khalid Abdullahi ([@Khalid-devsec](https://github.com/Khalid-devsec))

---

## Target Overview

| Field | Value |
|---|---|
| Machine | The Planets: Earth |
| Platform | [VulnHub](https://www.vulnhub.com/) |
| Author | SirFlash |
| Open Ports | 22 (SSH), 80 (HTTP), 443 (SSL/HTTP) |

## 1. Host Discovery & Reconnaissance

Found the target on the local network:

```bash
arp-scan -l
```

![arp-scan](./images/01-arp-scan.png)

Target identified at `192.168.226.152`. Ran a full port/version scan:

```bash
nmap -sC -sV 192.168.226.152 -p-
```

![nmap scan](./images/02-nmap-scan.png)

Three ports open: 22, 80, 443. The SSL certificate on 443 was the key detail — its Subject Alternative Name leaked two internal hostnames not visible anywhere else:

```
Subject Alternative Name: DNS:earth.local, DNS:terratest.earth.local
```

## 2. Web Enumeration & Virtual Host Discovery

Visiting the IP directly returned generic Apache "Bad Request" pages — the server expects a Host header matching a real vhost. A directory brute-force against the bare IP only found `cgi-bin`:

```bash
dirb https://192.168.226.152 /usr/share/wordlists/dirb/common.txt
```

![dirb against IP](./images/03-dirb-ip-direct.png)

Added both discovered hostnames to `/etc/hosts`:

![etc hosts](./images/04-etc-hosts.png)

With proper Host headers going out, both vhosts rendered an "Earth Secure Messaging Service" app, identical on the surface:

![earth.local site](./images/05-earth-local-site.png)
![terratest.earth.local site](./images/06-terratest-site.png)

Re-ran dirb against each vhost by name. `earth.local` exposed an `/admin` path:

```bash
dirb http://earth.local /usr/share/wordlists/dirb/common.txt
```

![dirb earth.local](./images/07-dirb-earth-local.png)

...and `terratest.earth.local` exposed a live `robots.txt`:

```bash
dirb https://terratest.earth.local /usr/share/wordlists/dirb/common.txt
```

![dirb terratest](./images/08-dirb-terratest.png)

`robots.txt` disallowed a long list of extensions, but one entry stood out:

![robots.txt](./images/09-robots-txt.png)

The disallowed path `/testingnotes.*` led straight to a developer's notes file:

![testingnotes.txt](./images/10-testingnotes.png)

Three critical facts here: the messaging app uses **XOR "encryption"**, a file called `testdata.txt` was used to test it, and the admin portal username is **`terra`**. Grabbed the referenced test file:

![testdata.txt](./images/11-testdata.png)

That plaintext is the crib needed to attack the XOR cipher — since the same key encrypts every message, having one known plaintext/ciphertext pair makes key recovery possible.

## 3. Breaking the XOR Encryption

The `earth.local` messaging page stores a history of previously sent, XOR-encrypted messages (as hex). Because `testdata.txt` was encrypted through the exact same system with the exact same key, XOR-ing its known plaintext against its own ciphertext (and sliding it across the other stored ciphertexts) recovers fragments of the repeating key — a classic **known-plaintext / crib-dragging attack against reused-key XOR**.

Used CyberChef (`From Hex` → `XOR`) to do this interactively:

![CyberChef XOR crack](./images/13-cyberchef-xor-crack.png)

The output repeats a readable fragment across multiple blocks — the tell-tale sign of a correctly-aligned key in a reused-key XOR cipher. Extending and cleaning up that recovered key made it possible to decrypt the admin's stored messages, which contained the actual admin portal password.

Logged into `earth.local/admin` as **terra** with the recovered credentials:

![admin login](./images/12-admin-login-page.png)

## 4. Admin Panel RCE → Reverse Shell

The admin panel is a raw "CLI command" box that runs whatever is typed directly on the server:

![admin command tool](./images/14-admin-command-tool.png)

A direct reverse shell one-liner was blocked by an outbound filter:

![nc forbidden](./images/15-nc-forbidden.png)

Worked around the filter by base64-encoding the payload and decoding/executing it server-side with `base64 -d | bash`, which doesn't match the blocked pattern:

![base64 shell command](./images/16-base64-shell-cmd.png)

Caught the callback on a listener:

```bash
nc -lvnp 4444
```

![nc listener connect](./images/17-nc-listener-connect.png)

Shell landed as `apache` on host `earth`. The Django project directory under `/var/earth_web` held the first flag:

![user flag](./images/18-user-flag.png)

```
user_flag_3353b67d6437f07ba7d34afd7d2fc27d
```

## 5. Privilege Escalation

Upgraded the dumb shell to a proper interactive TTY:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

![python pty upgrade](./images/19-python-pty-upgrade.png)

Searched for SUID binaries — files that run with their owner's privileges regardless of who executes them:

```bash
find / -perm -u=s -type f 2>/dev/null
```

![SUID find](./images/20-suid-find.png)

`/usr/bin/reset_root` immediately stood out as non-standard. Running it wasn't enough on its own:

![reset_root fail](./images/21-reset-root-fail.png)

Rather than guess blindly, pulled the binary back to the attacking machine to analyze it properly. Set up a listener and streamed the binary's bytes out over `netcat`:

![nc listener file transfer](./images/22-nc-listener-filetransfer.png)

The target's shell didn't support `/dev/tcp` redirection the way bash normally does, so the first several attempts to stream the file out failed before landing on a working transfer method:

![/dev/tcp attempts](./images/23-devtcp-attempts.png)

Once the binary was local, made it executable and reached for `ltrace` to trace its library calls, since it's a compiled binary and can't just be read with `cat`:

![chmod + ltrace install](./images/24-chmod-ltrace-install.png)

The trace revealed exactly what `reset_root` checks for before it'll act — three specific "trigger" file paths that must all exist first:

![ltrace triggers](./images/25-ltrace-triggers.png)

```bash
touch /dev/shm/kHgTFI5G
touch /dev/shm/Zw7bV9U5
touch /tmp/kcM0Wewe
```

Created all three trigger files on the target, then ran `reset_root` again:

![trigger files success](./images/26-touch-triggers-success.png)

Root's password was reset to a known value on the spot. Switched user and grabbed the final flag:

![root flag](./images/27-root-flag.png)

```
root_flag_b0da9554d29db2117b02aa8b66ec492e
```

## Summary

| Flag | Value | How obtained |
|---|---|---|
| User flag | `user_flag_3353b67d6437f07ba7d34afd7d2fc27d` | RCE via admin CLI tool → reverse shell → `/var/earth_web/user_flag.txt` |
| Root flag | `root_flag_b0da9554d29db2117b02aa8b66ec492e` | Reverse-engineered `reset_root` SUID binary with `ltrace` → created its trigger files → reset root password |

### Skills demonstrated
- Host & service discovery (`arp-scan`, `nmap`) and reading SSL certificate metadata for recon (SAN field leaking internal hostnames)
- Virtual host enumeration — brute-forcing content per-hostname instead of per-IP
- Source-hunting via `robots.txt` and developer-note disclosure
- Known-plaintext / crib-dragging attack against reused-key XOR encryption using CyberChef
- Filter evasion via base64-encoded payload execution
- Linux privilege escalation via SUID binary reverse engineering (`ltrace`) rather than guesswork
- Cross-host file transfer techniques and troubleshooting when standard methods (e.g. `/dev/tcp`) aren't available

---
*Educational writeup — completed in an isolated lab environment for VAPT skill-building.*
