# DMARC Aggregate Report Analyzer

A single-file, dependency-free Python tool that analyzes the DMARC aggregate
(RUA) reports mailbox providers email you, and tells you when it's safe to
move your DMARC policy from `p=none` → `p=quarantine` → `p=reject`.

## Why

You can't safely publish `p=reject` until you know that all your *legitimate*
mail passes DMARC alignment — otherwise receivers will start rejecting your
own email. The aggregate XML reports contain that answer, but they're
unreadable by hand. This tool turns them into:

- **sender intelligence** — sources are grouped into the services actually
  sending your mail (Google Workspace, Microsoft 365, SendGrid, Mailchimp,
  Amazon SES, ...), identified from IP ranges, rDNS, and DKIM/SPF domains,
- a per-source pass/fail breakdown (which IPs send as your domain, and whether
  they authenticate),
- hints about *why* a source fails (forwarder vs. misconfigured third-party
  sender vs. spoofing),
- a **suspected spoofing** panel — sources failing with no valid DKIM or SPF
  at all, i.e. the traffic `p=reject` exists to stop,
- a **daily volume/compliance timeline** in the HTML dashboard,
- a concrete recommendation for your next DNS policy step.

## Requirements

Python 3.9+. No packages to install.

## Quick start

### 0. Make sure you're receiving reports

Your DMARC DNS record (TXT at `_dmarc.yourdomain`) must include a `rua=` tag:

```
_dmarc.companyfiles.zip.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@companyfiles.zip"
```

Within a day or two, providers like Google and Microsoft will start emailing
compressed XML reports to that address (subject line "Report domain: ...").

### 1. Analyze reports

Save the report attachments (or whole `.eml` messages) into a folder and run:

```sh
python3 dmarc_analyzer.py reports/
```

Handles `.xml`, `.xml.gz`, `.zip`, and `.eml` files, including nested
zip/gzip inside email attachments. Duplicate reports are de-duplicated.

Optional outputs:

```sh
python3 dmarc_analyzer.py reports/ --html dmarc.html --json dmarc.json --resolve-dns
```

- `--html` writes a self-contained dashboard you can open in a browser.
- `--json` writes machine-readable results (`-` for stdout).
- `--resolve-dns` reverse-resolves source IPs to hostnames (needs network).

### 2. Or fetch reports straight from your mailbox (IMAP)

```sh
export DMARC_IMAP_PASSWORD='your-app-password'
python3 dmarc_analyzer.py \
    --imap-server imap.gmail.com \
    --imap-user you@gmail.com \
    --save-dir reports/
```

For Gmail, create an [app password](https://myaccount.google.com/apppasswords)
(requires 2FA) and make sure IMAP is enabled. Attachments are saved into
`--save-dir` and analyzed in the same run, so re-running is incremental.
Use `--imap-folder` to target a Gmail label (e.g. `--imap-folder dmarc`).

### Try it on the included sample

```sh
python3 dmarc_analyzer.py sample-reports/
```

## Reading the output

```
Total messages:   45
DMARC pass:       42 (93.33%)
...
198.51.100.7      3   0   3   0.0%
    -> DKIM signature valid but domain unaligned — likely a forwarder ...
```

A message **passes DMARC** when DKIM *or* SPF passes **in alignment** (the
authenticated domain matches your From: domain). Common failure hints:

| Hint | Meaning | Fix |
|---|---|---|
| DKIM valid but unaligned | Forwarder, or a service (newsletter, CRM, helpdesk) signing with its own domain | Configure the service's "custom DKIM domain" feature |
| SPF passed for unaligned domain | Third-party sender using its own envelope/bounce domain | Enable custom return-path, or add aligned DKIM |
| No aligned authentication | Unauthenticated legitimate sender — or spoofing | Add the sender to SPF + set up DKIM; if it's not yours, reject will block it (that's the point) |

## The path to p=reject

1. **`p=none`** (monitor) — collect ≥ 2 weeks of reports. Fix every
   legitimate source that fails until the pass rate is ≥ 98%.
2. **`p=quarantine` with a ramp** — `p=quarantine; pct=25`, then raise
   `pct` to 50 → 100 over 2–4 weeks while watching reports for regressions.
3. **`p=reject`** — once quarantine at `pct=100` shows no legitimate
   failures: `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain`.

The tool's RECOMMENDATIONS section automates this judgement: it looks at
your currently published policy, the observed pass rate, and how many days
of data you have, and prints the exact next record to publish.

## Tests

```sh
python3 -m unittest discover tests
```
