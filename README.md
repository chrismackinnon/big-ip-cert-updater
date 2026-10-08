# BIG-IP Certificate Rotation — Setup and Operations Guide

> Community-provided scripts, not an official F5 product and not supported by F5. Test in a lab (use the `-n` dry run and `-t` test mode) before using them in production. MIT licensed: see [LICENSE](LICENSE).

This guide walks you through renewing SSL/TLS certificates from DigiCert and loading them onto an F5 BIG-IP HA pair (Active/Standby), into an existing client-ssl or server-ssl profile, without interrupting traffic.

Do the one-time setup (Part 2) once. After that, each renewal (Part 3) takes about 15 minutes of hands-on work: generate a key and CSR, order from DigiCert, run one command to prepare and upload, then do a dry run and apply.

> **Renewals are now frequent.** Under the CA/Browser Forum rules (ballot SC-081), public TLS certificates issued from 15 March 2026 are valid for at most **200 days**. From 15 March 2027 the limit drops to **100 days**, and from 15 March 2029 to **47 days**. Expect to run Part 3 at least twice a year per certificate, and more often after that. That is the main reason to have a repeatable, low-risk process like this one.

---

## Contents

1. How it works, and service impact
2. One-time setup
3. Each renewal: step by step
4. Verify, and roll back if needed
5. Troubleshooting
6. Reference
7. Renewal checklist (printable)

---

## 1. How it works, and service impact

### The moving parts

```
 YOUR WORKSTATION (Linux/macOS)                 ACTIVE BIG-IP                      STANDBY BIG-IP
 ─────────────────────────────                  ─────────────                      ──────────────
 1. make-csr.sh  -> key + CSR
 2. submit CSR to DigiCert, download cert
 3. prepare-cert.sh -> checks + uploads  ──────> /shared/certrotate/inbox/<job>/
                                                 4. certrotate.sh (manually or on
                                                    a 15-minute schedule):
                                                    validate -> import -> swap
                                                    profile -> verify -> save
                                                 5. config-sync ─────────────────> receives the new
                                                                                   cert/key/profile
```

There are three scripts:

| Script | Runs on | What it does |
|---|---|---|
| `workstation/make-csr.sh` | your workstation | Creates a new private key and a CSR to give to DigiCert |
| `workstation/prepare-cert.sh` | your workstation | Takes whatever DigiCert gave you (zip, .crt, .pem, .p7b), finds your certificate, builds the correct intermediate chain, runs every check, and optionally uploads the files to the Active BIG-IP |
| `bigip/certrotate.sh` | both BIG-IPs | Validates the files again, imports them as new objects, re-points the profile in one atomic step, verifies the result, rolls back automatically on any problem, saves the config and syncs to the standby unit |

### Will this cause an outage?

**No.** Replacing the certificate on an existing profile this way does not interrupt traffic:

- **Existing connections** are not touched. They keep the TLS session they already have.
- **New connections** get the new certificate immediately.
- **The virtual server never goes down.** At no point does the profile hold a certificate without its matching key.
- **The only side effect:** some returning clients can't resume their cached TLS session and do a normal full handshake instead. Users don't notice this.

The script never overwrites the certificate that is currently in use. It imports the new certificate, key and chain under new, timestamped names (for example `www.example.com_20261008142233.crt`). It then switches the profile to them in a single command, which the BIG-IP applies completely or rejects completely. The previous certificate stays on the box, so rolling back is one command.

**The real risk is loading the wrong certificate**, not the mechanics of the swap. Typical mistakes are a key that doesn't match, a missing intermediate, the wrong hostname, or a certificate that's about to expire. Both `prepare-cert.sh` and `certrotate.sh` check for every one of these, and they refuse to make the change if any check fails.

### Things to know before you start

- **Keep the same key type.** If the current certificate is RSA, order RSA again. Switching between RSA and ECDSA can break handshakes if the profile's cipher settings only allow one type.
- **Profiles managed by AS3, BIG-IQ or an iApp** must have their certificates updated through that tool, not this process. Otherwise your change will be silently undone the next time that tool deploys.
- **Parent profiles.** If other profiles inherit from the profile you update, they change too. Point the job at the specific profile your virtual server uses.
- **Certificate pinning.** Any client or partner that pins the old certificate will break on every renewal, by design. Coordinate with them separately.
- **server-ssl (back-end mTLS).** The back-end servers must trust the new certificate's issuer *before* you rotate.

---

## 2. One-time setup

You need:
- Access to both BIG-IPs as a user whose shell is **bash**. `root` works, as does an admin account with `shell bash`.
- A Linux or macOS workstation with `openssl`, `ssh`, `scp` and `unzip` installed. All are standard on macOS. On Linux, install them with the package manager if any are missing.
- The name of your sync-failover device group. To find it:
  ```bash
  tmsh list cm device-group one-line | grep sync-failover
  ```

### 2.1 Copy the scripts to BOTH BIG-IPs

`/shared` is not synced between HA units, and it survives software upgrades. So do this on **each** unit.

From your workstation, in the folder where you unpacked this package:

```bash
ssh <user>@<bigip-1> 'rm -rf /var/tmp/certrotate-install'
scp -r bigip  <user>@<bigip-1>:/var/tmp/certrotate-install
ssh <user>@<bigip-2> 'rm -rf /var/tmp/certrotate-install'
scp -r bigip  <user>@<bigip-2>:/var/tmp/certrotate-install
```

If `scp` fails with an SFTP or "subsystem" error, add `-O` (for example `scp -O -r bigip …`). Newer OpenSSH versions use SFTP by default, and some BIG-IP accounts don't allow it.

Then on **each** BIG-IP, in bash:

```bash
mkdir -p /shared/certrotate/jobs.d /shared/certrotate/inbox
cp /var/tmp/certrotate-install/certrotate.sh   /shared/certrotate/
cp /var/tmp/certrotate-install/certrotate.conf /shared/certrotate/
cp /var/tmp/certrotate-install/jobs.d/*.example /shared/certrotate/jobs.d/
chmod 700 /shared/certrotate /shared/certrotate/certrotate.sh
chmod 600 /shared/certrotate/certrotate.conf
rm -rf /var/tmp/certrotate-install
bash -n /shared/certrotate/certrotate.sh && echo "SCRIPT OK"
```

It should print `SCRIPT OK`.

### 2.2 Set the device group (both units)

Edit `/shared/certrotate/certrotate.conf` on **each** unit and set your device group:

```bash
vi /shared/certrotate/certrotate.conf
```
```
SYNC_GROUP="<your-sync-failover-device-group>"
```

Leave the other settings at their defaults. With these settings the script:
- only makes changes on the **Active** unit, so the copy on the standby does nothing;
- syncs to the standby after a successful change;
- **won't** sync if the pair was already out of sync before it ran, so it never pushes someone else's unfinished changes.

### 2.3 Create a job for each certificate (both units)

A **job** is one small file that says "this certificate goes into that profile". Create one per certificate or profile.

1. Find the profile your virtual server uses:
   ```bash
   tmsh list ltm virtual <virtual-server-name> profiles
   tmsh list ltm profile client-ssl <profile-name> cert-key-chain
   ```
   Note the profile name. If the second command shows **more than one** entry inside `cert-key-chain` (for example both RSA and ECDSA certificates), also note the entry name you want to replace.

2. Pick a job name made of letters, digits and underscores, for example `www_example_com`. Create the job from the template:
   ```bash
   cd /shared/certrotate/jobs.d
   cp TEMPLATE-client-ssl.conf.example www_example_com.conf
   vi www_example_com.conf
   ```

3. Change the lines marked `<-- CHANGE`:
   ```
   SOURCE_DIR=/shared/certrotate/inbox/www_example_com
   OBJ_PREFIX=www.example.com
   PROFILE_NAME=/Common/clientssl_www_example_com
   EXPECT_NAME=www.example.com
   ```
   Add `CKC_ENTRY=<entry name>` only if the profile had more than one entry.

4. **Copy the same job file to the other BIG-IP.** Run this on the unit where you created it:
   ```bash
   scp /shared/certrotate/jobs.d/www_example_com.conf <user>@<other-bigip>:/shared/certrotate/jobs.d/
   ```

5. Test the job. On **each** unit:
   ```bash
   /shared/certrotate/certrotate.sh -t -j www_example_com
   ```
   `-t` only checks the job file and the profile. It doesn't need any certificate files and changes nothing. You should see:
   ```
   ... [NOTICE] [www_example_com] TEST OK: client-ssl /Common/clientssl_www_example_com found; certificate entry to be replaced: cert=/Common/... key=/Common/... chain=/Common/... (entry ...)
   ```
   Check that the `cert=` shown is the certificate you expect to replace. If you see `TEST FAILED` or `set CKC_ENTRY`, fix the job file on both units and test again.

For a **server-ssl** profile, use `TEMPLATE-server-ssl.conf.example` instead, and find the profile with `tmsh list ltm profile server-ssl <profile-name> cert key chain`.

### 2.4 Schedule it (optional but recommended)

With a schedule, the BIG-IP checks each job's inbox every 15 minutes and applies anything new automatically. Without one, you run the script by hand in step 3.5.

On the **Active** unit:

```bash
tmsh create sys icall script certrotate definition { catch { exec /shared/certrotate/certrotate.sh } }
tmsh create sys icall handler periodic certrotate interval 900 script certrotate
tmsh save sys config
tmsh run cm config-sync to-group <your-device-group>
```

The iCall schedule is part of the configuration, so it syncs to the standby and survives upgrades. It runs on both units, and the standby simply does nothing.

**With the schedule on, uploaded files can be applied within 15 minutes, before you've done a dry run.** That's safe, because every check in the dry run also runs before a real change, and a failed check means nothing changes. If you want to approve each change by hand, choose one of these:
- Leave the schedule out and run the script by hand, as in step 3.5.
- Add `READY_MARKER=GO` to the job file on both units. The scheduled run then ignores the inbox until a file called `GO` is also there. After your dry run, approve the change with `touch /shared/certrotate/inbox/<job>/GO`.

To keep changes inside a maintenance window, upload the files (or create the `GO` file) only during the window.

### 2.5 Set up your workstation

Copy the `workstation/` folder into your home directory on the Linux or macOS machine where you'll handle certificates. The commands in this guide assume `~/workstation/`. Then run:

```bash
chmod +x ~/workstation/make-csr.sh ~/workstation/prepare-cert.sh
mkdir -p ~/certs && chmod 700 ~/certs
```

Keep private keys in `~/certs` or another protected location. Never email them or put them on a shared drive.

Optional: if you set up SSH key login to both BIG-IPs, `prepare-cert.sh` can upload without asking for a password each time.

---

## 3. Each renewal: step by step

Start **at least 2–3 weeks before** the current certificate expires. DigiCert validation can take time, and you want room to fix any problem.

### 3.1 Create a new key and CSR (workstation)

```bash
cd ~/certs
~/workstation/make-csr.sh -n www.example.com -a example.com -o "Example Corp" -c US
```

- `-n` is the main name (required). Add `-a` once for each extra name that should be on the certificate.
- `-o` and `-c` (organisation, country) are optional. DigiCert takes those details from your account for OV and EV orders.
- **Always create a new key for each renewal.** Reusing the old key is possible but not recommended.

It creates a folder such as `./www.example.com-20261008/` containing:
- `www.example.com.key`: the private key. **Keep it secret and don't lose it.** Without it, the certificate DigiCert issues is useless.
- `www.example.com.csr`: the CSR, which you give to DigiCert.

The script also prints the CSR to the screen.

### 3.2 Order or renew in DigiCert CertCentral

1. In CertCentral, open the existing order and choose **Renew**, or start a new order.
2. Paste the **entire** contents of the `.csr` file, including the `-----BEGIN CERTIFICATE REQUEST-----` and `-----END…-----` lines.
3. **Server platform:** choose **F5 BIG-IP** if it's offered, otherwise **Apache**. Either works, because the next step accepts any DigiCert format.
4. Complete domain and organisation validation as usual.

### 3.3 Download the certificate

When DigiCert issues the certificate:

- **Easiest:** download the **zip file** for **Apache**, or "Individual .crt files". It contains your certificate and the DigiCert intermediate.
- These also work: a `.pem` bundle (with or without the root), a `.p7b` file, or separate `.crt` or `.cer` files.

Save the download into the same folder as your key, for example `~/certs/www.example.com-20261008/`. **Don't** edit, rename or combine the files.

### 3.4 Prepare, check and upload (workstation)

Run one command, giving it your key, the expected name, the **Active** BIG-IP, the job name and the DigiCert download:

```bash
cd ~/certs/www.example.com-20261008
~/workstation/prepare-cert.sh \
    -k www.example.com.key \
    -e www.example.com \
    -u <user>@<ACTIVE-bigip> -j www_example_com \
    www_example_com.zip
```

The script:
- reads everything DigiCert gave you;
- finds the certificate that matches your key;
- puts the intermediate(s) in the right order and leaves the root out, which is correct (the BIG-IP should not send the root);
- checks the expiry dates, the names and the key type;
- uploads `cert.pem`, `chain.pem` and `key.pem` to `/shared/certrotate/inbox/www_example_com/` on the BIG-IP.

It also refuses to upload to a unit that isn't **Active**.

A good run looks like this:

```
== Checking private key
  [ OK ] private key readable
  [ OK ] your certificate: CN = www.example.com
== Building chain
  [ OK ] intermediate: CN = DigiCert Global G2 TLS RSA SHA256 2020 CA1
  [ OK ] chain ends at an intermediate issued by: CN = DigiCert Global Root G2 (root not included - correct)
== Validating
  [ OK ] valid from Oct  8 00:00:00 2026 GMT to Apr 25 23:59:59 2027 GMT
  [ OK ] names on certificate: DNS:www.example.com, DNS:example.com
  [ OK ] key type: RSA 2048
  [ OK ] expected name 'www.example.com' is on the certificate
== Uploading to admin@10.1.1.245 (job www_example_com)
  [ OK ] admin@10.1.1.245 is Active
  [ OK ] uploaded to admin@10.1.1.245:/shared/certrotate/inbox/www_example_com/
```

Small formatting differences are normal. For example, on macOS names may print as `/CN=www.example.com` instead of `CN = www.example.com`. What matters is that every line says `[ OK ]`.

After a successful upload, the script deletes its own temporary copy of the key (`ready-…/key.pem`). Your original `.key` file is not touched.

If you see `ERROR`, nothing has been uploaded. See section 5.

To prepare the files without uploading, leave out `-u` and `-j`. The script then prints the exact `scp` commands to copy them yourself. In that case, the `ready-…/` folder contains an **unencrypted copy of the private key** (`key.pem`). Delete it once you've copied the files.

### 3.5 Dry run, then apply (on the Active BIG-IP)

Wait about 10 seconds after the upload. The script ignores files that changed in the last few seconds, in case a copy is still in progress. If you run it too soon, it prints `waiting for upload to settle`; just run it again.

Even if the schedule is on, run a dry run first. It shows exactly what will change and changes nothing:

```bash
/shared/certrotate/certrotate.sh -n -j www_example_com
```

If the dry run prints nothing, the schedule may already have applied the certificate. Check `tail -20 /var/log/certrotate.log` and section 4.1.

Look for these lines. Real lines also start with a timestamp and the job name, for example `2026-10-08 14:22:33 [NOTICE] [www_example_com] …`:

```
[NOTICE] DRY-RUN would have profile /Common/clientssl_www_example_com switched: /Common/www_2025.crt -> /Common/www.example.com_20261008142233.crt
[NOTICE] DRY-RUN OK: validation passed; ... Nothing was changed.
```

Then apply it:

```bash
/shared/certrotate/certrotate.sh -j www_example_com
```

Or leave it, and the 15-minute schedule will apply it. A successful run ends with:

```
[NOTICE] profile /Common/clientssl_www_example_com switched: ... -> /Common/www.example.com_20261008142240.crt
[NOTICE] SUCCESS: /Common/clientssl_www_example_com now uses /Common/www.example.com_20261008142240.crt (expires Apr 25 23:59:59 2027 GMT)
[INFO]   tmsh ok: save sys config
[NOTICE] config-sync to <group> requested
```

Once it succeeds, the files are removed from the inbox automatically, and the key file is securely deleted. The key now lives only in the BIG-IP's certificate store, as an SSL key object, protected by the BIG-IP's normal admin access controls.

**Delete your workstation copy of the key** once you've confirmed the new certificate is live, or move it into your organisation's key vault if policy requires you to keep it.

---

## 4. Verify, and roll back if needed

### 4.1 Verify

On the BIG-IP:

```bash
tmsh list ltm profile client-ssl <profile-name> cert-key-chain
tmsh show cm sync-status
```

For a server-ssl profile, use `tmsh list ltm profile server-ssl <profile-name> cert key chain` instead.

The profile should show the new `..._<timestamp>.crt` objects, and sync status should be **In Sync**.

From any machine that can reach the virtual server:

```bash
echo | openssl s_client -connect <VIP-address>:443 -servername www.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate
```

This should show the new expiry date and a DigiCert issuer. You can also check in a browser by clicking the padlock and viewing the certificate's expiry date.

### 4.2 Roll back

Every successful run records what the profile used before. This record is kept **only on the unit that made the change**, which was the Active unit at the time. If the pair has failed over since, read it on the other unit. To see it:

```bash
cat /shared/certrotate/state/www_example_com.applied
```

```
cert=/Common/www.example.com_20261008142240.crt         <- now in use
previous_cert=/Common/www_2025.crt                      <- what it used before
previous_key=/Common/www_2025.key
previous_chain=/Common/int_2025.crt
ckc_entry=www_2025
```

To switch back, use the `previous_*` values in one command. It's the same atomic, hitless swap the script uses.

For a **client-ssl** profile:

```bash
tmsh modify ltm profile client-ssl /Common/clientssl_www_example_com \
     cert-key-chain modify { www_2025 { cert /Common/www_2025.crt key /Common/www_2025.key chain /Common/int_2025.crt } }
tmsh save sys config
tmsh run cm config-sync to-group <your-device-group>
```

Replace `www_2025` after `modify {` with the `ckc_entry` value from the state file.

For a **server-ssl** profile:

```bash
tmsh modify ltm profile server-ssl <profile> cert <previous_cert> key <previous_key> chain <previous_chain>
tmsh save sys config
tmsh run cm config-sync to-group <your-device-group>
```

The script keeps the current and the previous certificate objects (`RETAIN_VERSIONS=2`), so the previous one is always available for rollback.

If you later upload the **same** new certificate again (for example after fixing whatever caused the rollback), the script sees that the profile no longer uses it and applies it again. You don't need `-f`.

---

## 5. Troubleshooting

### Errors from `prepare-cert.sh` (workstation)

| Message | What it means / what to do |
|---|---|
| `none of these certificates match the private key` | You used a different key from the one whose CSR was submitted. Find the right `.key` file. If it's lost, re-key the order in DigiCert with a new CSR. |
| `the intermediate certificate is missing` | You only passed the server certificate. Download the full zip ("Apache" or "Individual .crt files") and pass that. |
| `expected name '…' is NOT on the certificate` | The certificate was issued for different names. Check the order in DigiCert. |
| `certificate has EXPIRED` | You have an old download. Get the newly issued certificate. |
| `… reports 'Standby', not Active` | You pointed `-u` at the standby unit. Use the Active one; check with `tmsh show cm failover-status`. |
| `job '…' does not exist` | The job name is wrong, or the job file wasn't created on that unit (step 2.3). |
| `cannot ssh to …` | Network, credentials or SSH access issue. Test with `ssh <user>@<bigip>`. |
| `unexpected response … is the login shell bash?` | The account's shell is tmsh. Use a user whose shell is bash, or run `tmsh modify auth user <user> shell bash`. |
| `scp failed` | Try again. If it keeps failing, upload by hand with `scp -O …`, as printed when you run the script without `-u`. |

### Errors from `certrotate.sh` (BIG-IP)

| Message | What it means / what to do |
|---|---|
| `private key does NOT match certificate` | Wrong key uploaded. Re-run `prepare-cert.sh`, which catches this before uploading. |
| `chain does not validate the leaf certificate` | Wrong intermediate. Re-run `prepare-cert.sh` with the full DigiCert download. |
| `EXPECT_NAME … not found in SAN` | The certificate doesn't cover the name in the job file. Check the order, or fix `EXPECT_NAME`. |
| `profile has 2 cert-key-chain entries … set CKC_ENTRY` | Add `CKC_ENTRY=<entry name>` to the job file on both units (step 2.3), then upload the same files again. Because the job file has changed, the script retries automatically. |
| `SKIPPED: this exact certificate already failed …` | The same certificate was uploaded again without anything changing. Fix the cause shown in the message and upload again. If the fix was outside the job file (for example on the profile), run once with `-f -j <job>`. |
| `already applied to … - nothing to do` | The profile already uses this certificate. No action is needed. |
| `profile … does not exist` | Check `PROFILE_NAME`, including the partition, e.g. `/Common/...`. |
| `device group was '…' BEFORE this run - NOT auto-syncing` | The pair was already out of sync before the run, so the change was made on the Active unit only. Review the pending changes, then sync manually: `tmsh run cm config-sync to-group <group>`. |
| `tmsh failed … ` / `profile update rejected` | The BIG-IP rejected the change, and nothing was changed. The `tmsh said:` line has the reason. |
| Nothing happens at all | The files aren't in the right inbox folder, they were uploaded less than `STABLE_SECONDS` ago (10s in the templates), the unit is Standby, or `READY_MARKER` is set and the marker file isn't there yet. Run `certrotate.sh -n -v -j <job>` to see why. |

**When a run fails, nothing is changed.** The rejected files are moved to `/shared/certrotate/failed/<job>/<time>/` so you can inspect them. Delete that folder afterwards, because it contains a private key.

If you upload the same certificate again without changing anything, the script reports `SKIPPED` rather than failing the same way again. If you changed the job file, it retries automatically. Otherwise use `-f`.

### Logs

```bash
tail -50 /var/log/certrotate.log           # full detail
grep certrotate /var/log/ltm               # summary (also goes to your remote syslog / SIEM)
```

---

## 6. Reference

### `certrotate.sh` options

| Option | Meaning |
|---|---|
| `-n` | Dry run: check everything, show what would change, change nothing |
| `-j <job>` | Run only this job (default: all jobs) |
| `-f` | Force: re-apply even if this certificate was already applied, or failed before |
| `-v` | Print the log to the screen even when not run from a terminal |
| `-t` | Test the job configuration only (profile found? which entry?). Needs no files and changes nothing |

### Files on each BIG-IP

| Path | Contents |
|---|---|
| `/shared/certrotate/certrotate.sh` | The script |
| `/shared/certrotate/certrotate.conf` | Global settings (device group, etc.) |
| `/shared/certrotate/jobs.d/<job>.conf` | One file per certificate/profile |
| `/shared/certrotate/inbox/<job>/` | Drop `cert.pem`, `chain.pem` and `key.pem` here |
| `/shared/certrotate/state/<job>.applied` | What was last applied, and what was in use before (for rollback) |
| `/shared/certrotate/archive/<job>/` | Copies of applied certificates and chains (no keys) |
| `/shared/certrotate/failed/<job>/` | Rejected uploads, for troubleshooting (contains keys; delete after review) |
| `/var/log/certrotate.log` | Detailed log |

### Job file settings

| Setting | Meaning | Default |
|---|---|---|
| `SOURCE_DIR` | Inbox folder for this job | — |
| `OBJ_PREFIX` | Name prefix for imported BIG-IP objects | — |
| `PROFILE_TYPE` | `client-ssl` or `server-ssl` | client-ssl |
| `PROFILE_NAME` | Full profile path, e.g. `/Common/clientssl_www` | — |
| `CKC_ENTRY` | Which cert-key-chain entry to replace (only if the profile has more than one) | auto |
| `EXPECT_NAME` | Name that must appear on the certificate | — |
| `MIN_DAYS_VALID` | Refuse certificates expiring sooner than this | 7 |
| `REQUIRE_CHAIN` | Refuse a CA-issued certificate without an intermediate | yes |
| `VERIFY_HOST` / `VERIFY_PORT` / `VERIFY_SNI` | Optional live check after the change; auto-rollback if it fails | off |
| `RETAIN_VERSIONS` | How many versions of the objects to keep | 2 |
| `STABLE_SECONDS` | Ignore inbox files changed within this many seconds (upload still in progress) | 60 (templates: 10) |
| `READY_MARKER` | Only process the inbox once this file also exists (manual approval with the schedule on) | off |
| `CREATE_IF_MISSING`, `PARENT_PROFILE`, `ATTACH_VIRTUAL` | Create a new profile on first run (see `TEMPLATE-new-profile`) | no |

### Stop the schedule

```bash
tmsh delete sys icall handler periodic certrotate
tmsh delete sys icall script certrotate
tmsh save sys config
tmsh run cm config-sync to-group <your-device-group>
```

---

## 7. Renewal checklist (printable)

**Certificate:** ____________________  **Job name:** ____________________  **Profile:** ____________________

| ☐ | Step | Where | Command / action |
|---|---|---|---|
| ☐ | 1. Create key + CSR | Workstation | `make-csr.sh -n <name> [-a <extra name>]` |
| ☐ | 2. Submit CSR to DigiCert, complete validation | CertCentral | Paste the `.csr`; platform F5 BIG-IP or Apache |
| ☐ | 3. Download issued certificate (zip) | CertCentral | Save next to the `.key` |
| ☐ | 4. Confirm which unit is Active | BIG-IP | `tmsh show cm failover-status` |
| ☐ | 5. Prepare + upload | Workstation | `prepare-cert.sh -k <key> -e <name> -u <user>@<ACTIVE> -j <job> <download.zip>`; all lines `[ OK ]` |
| ☐ | 6. Dry run | Active BIG-IP | `certrotate.sh -n -j <job>`; ends with `DRY-RUN OK` |
| ☐ | 7. Apply (or wait for the schedule) | Active BIG-IP | `certrotate.sh -j <job>`; ends with `SUCCESS` |
| ☐ | 8. Verify profile + sync | Active BIG-IP | `tmsh list ltm profile client-ssl <profile> cert-key-chain` (server-ssl: `… server-ssl <profile> cert key chain`); `tmsh show cm sync-status` is In Sync |
| ☐ | 9. Verify from a client | Any | `openssl s_client …` or browser shows the new expiry date |
| ☐ | 10. Delete the workstation key and any `ready-*/` folders, or store the key per policy | Workstation | |
| ☐ | 11. Record the new expiry date and set a reminder 30 days before it (certificates now last 200 days or less) | Calendar/ticket | |

Date: __________  Performed by: __________  Change ticket: __________
