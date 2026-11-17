# M365 Investigator Suite

<p align="center">
  <img src="static/assets/gg-mark.png" width="112" alt="M365 Investigator Suite logo">
</p>

<p align="center">
  A local, case-based workbench for Microsoft 365 audit logs, Message Trace investigations, enrichment, email collection, and analyst-ready exports.
</p>

<p align="center">
  <a href="https://medium.com/@gyw765419384/introducing-m365-investigator-suite-a-local-first-workbench-for-microsoft-365-investigations-952093aef4ca">Read the introduction on Medium</a>
</p>

<p align="center">
  <a href="https://buymeacoffee.com/gilbertguo"><img src="https://img.shields.io/badge/Buy%20me%20a%20coffee-Support%20the%20project-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=000000" alt="Buy Me a Coffee"></a>
</p>

> [!IMPORTANT]
> Hunting results are investigation leads, not final determinations. Validate findings against the original evidence and surrounding context.

## Key features

| Area | Capabilities |
| --- | --- |
| Case management | Independent local cases with multiple UAL and Message Trace datasets |
| UAL Review | Parse Purview CSV, Excel, JSON, and JSONL exports; flatten `AuditData`; normalize Exchange `ActorInfoString`, user-agent, and client metadata; categorize Logon, Inbox Rules, Transport Rules, Mailbox Permissions, Email Access, File Access, and Other operations |
| MTL Review | Parse Exchange Message Trace CSV files, including common UTF-16 exports; manage multiple traces per case |
| Sign-in Review | Prepare exported login CSVs for client review using 17 focused columns, User second, field fallbacks, custom filenames, streaming progress, and CSV downloads |
| Search and review | Field queries, wildcards, `AND`/`OR`, exclusions, empty values, time ranges, Excel-style header filters with searchable multi-select values, sorting, paging, draggable/frozen columns, and full-value inspection |
| Investigation workflow | Persistent row tags, bulk tagging of filtered results, message-ID, subject, and available email-size extraction, plus a filter-scoped MessageIds/Subjects CSV with a custom filename and optional `SizeInBytes` column, Microsoft app-ID mapping, and tracker-ready Event narratives including recorded search-query text |
| Enrichment | Filter-scoped IP intelligence and domain-registration enrichment with persistent results and in-drawer progress indicators |
| Hunts | Suspicious logins, impossible travel, newly registered domains, suspicious subjects, and review-worthy third-party mail services |
| Collection and export | Authorized Microsoft Graph email collection, customizable filtered CSV export, and client-shareable XLSX preparation |

## Screenshots

All screenshots use synthetic identities and reserved documentation IP ranges.

### Case intake

![Case intake](docs/screenshots/case-intake.png)

### UAL Review

![UAL Review](docs/screenshots/ual-review.png)

### MTL Review

![MTL Review](docs/screenshots/mtl-review.png)

### Configurable hunts

#### Suspicious Login

![Configurable suspicious-login hunt](docs/screenshots/hunt-suspicious-logins.png)

#### Impossible Travel

![Configurable impossible-travel hunt](docs/screenshots/hunt-impossible-travel.png)

#### Suspicious Mail

![Configurable suspicious-mail hunt](docs/screenshots/hunt-suspicious-mail.png)

## Quick start

Requirements: Python 3.9 or newer, including Python 3.13, and a modern browser.

```bash
git clone https://github.com/GilbertGuo/M365-Investigator-Suite.git
cd M365-Investigator-Suite
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 app.py
```

Open <http://127.0.0.1:8765>, create a case, then add one or more UAL or Message Trace CSV exports from inside that case.

Windows activation:

```powershell
.venv\Scripts\Activate.ps1
python app.py
```

Case evidence and derived analysis are stored under `cases/`. This directory is excluded from Git except for its placeholder.

### Large UAL exports

In **UAL Review → Add UAL export**, select a CSV or JSONL file as usual. CSV/TXT/JSONL/NDJSON files stream to disk and import into SQLite in batches, up to **8 GiB per file**, including a 1.8 GB export as one dataset. The form shows upload progress followed by the imported-record count. Keep the server running until the dataset is ready. No additional database service or dependency is required.

Paging, query filtering, chronological sorting, unique values, metrics, and filtered CSV export use disk-backed processing. The original file and its SHA-256 are retained with the dataset. Existing datasets remain compatible. Excel and JSON-array imports retain the 250 MB limit; convert larger files to CSV or JSONL.

Allow several times the source-file size in free disk space for the original, parsed database, and temporary sort/export files. Imports run one at a time. Large query scans may take time; enrichment and hunts still depend on the number of indicators/findings and may require additional memory. An interrupted import is not published as a dataset; re-upload after restarting the server. Interrupted staging files may remain under the case's `ual/.imports/` directory.

## Typical workflow

1. Create a case.
2. Add UAL exports in **UAL Review** and Message Trace files in **MTL Review**.
3. Filter, inspect full values, review unique values, sort columns, and tag records of interest.
4. Enrich only the filtered IPs or domains needed for the investigation.
5. Run the relevant hunt and inspect its reason, risk, and score columns.
6. Generate concise Event narratives for a tracker.
7. Export the complete filtered result as CSV or create a client XLSX workbook.

## Prepare a client sign-in CSV

1. In **UAL Review**, select **Logon**, apply the intended filters, optionally enrich IPs/run a login hunt, and choose **Export CSV**.
2. Open **Sign-in Review** in the sidebar, upload that UTF-8 CSV, and optionally enter an output filename.
3. Click **Prepare sign-in CSV**, wait for the processed-row count to finish, then download the result. You can feed it into **Client XLSX** afterward, subject to Excel's worksheet limit.

The processor uses the supplied `prepare_client_signin_review.py` field mappings. It produces Time (UTC), User, IP Address, Location, ISP, Operation, Result, Result Detail, Application, Request Type, OS, Browser, Device Compliant, Risk (Heuristic), Risk Reasons (Heuristic), Session ID, and Record ID, in that order. It requires `UserId` or `AuditData.UserId`, leaves missing values blank, and retains every uploaded row in order. It does not calculate new risk or drop non-login rows, so export the intended Logon view first. CSVs up to 8 GiB and more than one million records stream through disk; source files and results are kept separately inside the local case.

## Query examples

```text
user:alex@example.com
ip:64.*
operation:*Login*
result:failed
Login.DeviceName:=""
ip:=1.2.3.4 OR ip:=5.6.7.8
user:alex@example.com AND result:Success
time:>=2026-07-21T12:00:00Z AND time:<2026-07-22T00:00:00Z
```

- `*` matches any number of characters.
- `:=` performs an exact match; `Field:=""` matches blank or missing values.
- Prefix a condition with `-` to exclude it.
- `AND` binds more tightly than `OR`; parentheses can group expressions.
- Timestamp columns support `>`, `>=`, `<`, and `<=`.
- Right-click values and timestamps to build filters without typing the query.

## IP and domain enrichment

IP enrichment adds Country, Region, City, ISP, AS, Mobile, VPN/TOR, and Hosting fields to the filtered rows.

- **Anonymous free IP-API:** non-commercial use only and transmitted over HTTP after the analyst accepts the notice.
- **Commercial IP-API:** enter a Pro key in the password field; requests use HTTPS. The key is used only for the active request and is not saved, returned, or placed in browser storage.
- Private, loopback, link-local, and invalid addresses are classified locally.
- Domain enrichment sends extracted domain names—not complete email addresses—to public RDAP services over HTTPS.

Review [Third-Party Notices](THIRD_PARTY_NOTICES.md) before enabling external enrichment.

## Email collection

**Email Collection** can retrieve authorized messages by mailbox UPN and InternetMessageId through Microsoft Graph. It supports manual targets or a CSV containing:

```text
MailboxOwnerUPN,InternetMessageId
analyst@example.com,<message-id@example.net>
```

The analyst supplies the tenant ID, client ID, client-secret value, and an absolute output folder. Microsoft Graph application permission `Mail.Read` requires administrator consent and can provide broad mailbox access. Use written authorization, restrict the application where possible, and revoke temporary secrets or permissions after collection.

## Local-first security model

- The server listens on `127.0.0.1` by default.
- It has no built-in user authentication, TLS termination, or multi-user isolation.
- Do not expose the built-in server directly to the internet or an untrusted network.
- Protect `cases/` and collection output folders as evidence repositories.
- Source evidence, common deliverables, credentials, caches, and local environment files are excluded through `.gitignore`.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

## License

Copyright © 2026 Gilbert Guo.

The source code is licensed under the [MIT License](LICENSE). Third-party services, reference data, product names, and trademarks remain subject to their respective owners and terms. See [Third-Party Notices](THIRD_PARTY_NOTICES.md).
