#!/usr/bin/env python3
"""Download the PSL and BGP data, then generate all reports."""

# Standard Python Libraries
import csv
import logging
import os
from pathlib import Path
from urllib.error import URLError

# Third-Party Libraries
import publicsuffix

HOME_DIR = "/home/cisa"
SHARED_DATA_DIR = HOME_DIR + "/shared/"
PUBLIC_SUFFIX_LIST_FILENAME = "psl.txt"


def main():
    """Download the PSL and BGP data, then generate all reports."""
    # Download the public suffix list
    logging.info("Downloading the public suffix list...")
    try:
        psl = publicsuffix.fetch()
    except URLError:
        logging.critical(
            "Unable to download the Public Suffix List", exc_info=True, stack_info=True
        )
        return
    with open(PUBLIC_SUFFIX_LIST_FILENAME, "w", encoding="utf-8") as psl_file:
        psl_file.write(psl.read())

    # Download and preprocess some BGP data for later use by pyasn
    # inside of generate_trustymail_report.py
    logging.info("Downloading BGP data for pyasn...")
    # pyasn_util_download.py isn't written in a way that easily allows
    # it to be run in any other way.  Hence the nosec.
    download_cmd = "/usr/local/bin/pyasn_util_download.py --latestv46"
    os.system(download_cmd)  # nosec B605
    logging.info("Preprocessing BGP data for pyasn...")
    # pyasn_util_convert.py isn't written in a way that easily allows
    # it to be run in any other way.  Hence the nosec.
    convert_cmd = "/usr/local/bin/pyasn_util_convert.py --single rib.*.bz2 ipasn.dat"
    os.system(convert_cmd)  # nosec 605
    logging.info("Cleaning up...")
    for p in Path.cwd().glob("rib.*.bz2"):
        p.unlink()

    agency_csv = open(SHARED_DATA_DIR + "artifacts/unique-agencies.csv")
    for row in sorted(csv.reader(agency_csv)):
        bashCommand = (
            HOME_DIR + "/report/generate_trustymail_report.py " + '"' + row[0] + '"'
        )
        # generate_trustymail_report.py isn't written in a way that
        # easily allows it to be run in any other way.  Hence the
        # nosec.
        os.system(bashCommand)  # nosec B605

    logging.info("Cleaning up...")
    (Path.cwd() / "ipasn.dat").unlink()
    (Path.cwd() / "psl.txt").unlink()


if __name__ == "__main__":
    main()
