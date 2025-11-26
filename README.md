# **npm-dewormer**

**npm-dewormer** is a local security tool that scans your workstation for known indicators associated with the active npm / JavaScript supply-chain worm (Shai-Hulud 2.0) and quarantines suspicious files on demand.
It is designed for developers, bug-bounty hunters, and incident-response teams who need a fast, local triage tool.

This script is non-destructive by design. It does not delete files, run wipe commands, or modify your system outside of moving flagged files into a safe quarantine folder.

---

## **Features**

* Scans your filesystem for known malicious npm worm IOCs:

  * Suspicious JS loaders (`setup_bun.js`, `bun_environment.js`)
  * TruffleHog credential-harvesting artifacts
  * Worm metadata and staging files
  * Known malicious directories (`.truffler-cache/...`)
* Checks:

  * Running processes for suspicious command patterns
  * Shell history for worm activity
* On every run:

  * Creates a full text-based scan report under `./reports/`
* If IOCs are found:

  * Prompts the user to quarantine them
  * Moves files instead of deleting them for safe review
* No arguments required. Fully interactive.

---

## **Installation **

```bash
git clone https://github.com/ekomsSavior/npm-dewormer.git
cd npm-dewormer
```

---

## **Usage**

### **1. Run the scanner**

```bash
python3 npm_worm_helper.py
```

This will:

1. Scan your filesystem
2. Scan your process list
3. Scan shell history
4. Save a full report into:

```
reports/npm_worm_scan_<timestamp>.txt
```

5. Display results in the terminal

### **2. If indicators are found**

You will see:

```
Indicators were found. This script CANNOT guarantee full cleanup.

[?] Do you want to MOVE the IOC files/dirs into a quarantine folder now? [y/N]:
```

Press **y** to proceed.

You will then be asked to type:

```
CLEAN
```

to confirm.
Once confirmed, the script moves suspicious files into:

```
~/npm_worm_quarantine/scan_<timestamp>/
```

This lets you inspect them safely.

---

## **Quarantine Behavior**

* Files are **moved**, not deleted
* Directory structure is preserved
* Nothing is executed
* Nothing destructive is used

Once reviewed, you may safely delete the quarantine directory.

---

## **Reports**

Every scan produces a standalone report:

```
reports/npm_worm_scan_<timestamp>.txt
```

Reports include:

* Hostname
* Timestamp (UTC)
* Filesystem IOCs
* Process IOCs
* Shell History IOCs
* Assessment notes

Useful for:

* Bug bounty reports
* IR hand-off
* Long-term tracking of suspicious activity

---

## **Important Notes**

* This tool checks for **known indicators only**.
* A clean result does **not guarantee** a clean system.
* If anything is found, you should also:

  * Rotate all API tokens, npm tokens, GitHub/GitLab PATs
  * Rotate cloud credentials (AWS/GCP/Azure keys)
  * Audit repositories for malicious `preinstall/postinstall` scripts
  * Rebuild compromised CI runners or development machines when possible


![Screenshot 2025-10-14 111008](https://github.com/user-attachments/assets/fd03b0fd-d94e-4ba5-84f8-51475794a979)
