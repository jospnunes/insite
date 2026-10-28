#!/usr/bin/env python3
"""Regenerates crates/core/data/intermediates.tsv from the CCADB.

The CCADB "All Certificate Information" report (CDLA-Permissive-2.0, attribution
to the Common CA Database) lists every root and intermediate CA certificate
disclosed to the root programs. We keep only what the TLS analyzer needs to tell
an incomplete chain from an untrusted certificate: the key identifier, the kind,
the trust state and the name. No certificates are embedded.

Usage: scripts/update-intermediates.py [path-or-url-of-the-csv]
Only the Python standard library is needed.
"""

import base64
import csv
import datetime
import io
import sys
import urllib.request

SOURCE = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV5"
OUT = "crates/core/data/intermediates.tsv"


def load(source):
    if source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=120) as response:
            return response.read().decode("utf-8")
    with open(source, encoding="utf-8") as f:
        return f.read()


def clean(text):
    return " ".join(text.replace("\t", " ").split())


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else SOURCE
    rows = list(csv.DictReader(io.StringIO(load(source))))
    today = datetime.date.today().strftime("%Y.%m.%d")
    out = []
    for row in rows:
        ski = row["Subject Key Identifier"].strip()
        if not ski or row["Valid To (GMT)"] < today:
            continue
        ski = base64.b64decode(ski).hex()
        name, owner = clean(row["Certificate Name"]), clean(row["CA Owner"])
        if row["Certificate Record Type"] == "Root Certificate":
            statuses = (row["Mozilla Status"], row["Chrome Status"])
            if "Included" in statuses:
                state = "trusted"
            elif any(s in ("Removed", "Blocked") for s in statuses):
                state = "removed"
            else:
                state = "not_included"
            out.append((ski, "R", state, name, owner))
        else:
            tls = "Server Authentication" in row["Derived Trust Bits"] or row["TLS Capable"] == "True"
            revoked = row["Revocation Status"] != "Not Revoked"
            if not (tls or revoked):
                continue
            if revoked:
                state = "revoked"
            elif "Trusted" in (row["Mozilla Status"], row["Chrome Status"]):
                state = "trusted"
            else:
                state = "untrusted"
            out.append((ski, "I", state, name, owner))
    # Cross-signed CAs appear once per certificate, sometimes as a root and as an
    # intermediate, but share the key identifier. A client can complete the chain
    # with any of them, so the best state wins, and a trusted intermediate beats a
    # root because that is what a server forgets to send.
    rank = {"trusted": 0, "untrusted": 1, "not_included": 1, "removed": 2, "revoked": 2}
    best = {}
    for entry in out:
        score = (rank[entry[2]], entry[1] != "I")
        if entry[0] not in best or score < (rank[best[entry[0]][2]], best[entry[0]][1] != "I"):
            best[entry[0]] = entry
    out = sorted(best.values())
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(f"# Derived from the CCADB All Certificate Information report on {today}.\n")
        f.write("# Data: Common CA Database (CCADB), CDLA-Permissive-2.0.\n")
        f.write("# subject_key_id(hex)\tkind\tstate\tname\towner\n")
        for line in out:
            f.write("\t".join(line) + "\n")
    print(f"{len(out)} entries written to {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
