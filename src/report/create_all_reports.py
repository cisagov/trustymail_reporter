#!/usr/bin/env python3
"""Download the PSL and BGP data, then generate all reports."""

# Standard Python Libraries
import csv
import logging
import os
from pathlib import Path

# Third-Party Libraries
from publicsuffixlist.update import updatePSL
from requests.exceptions import RequestException

HOME_DIR = "/home/cisa"
SHARED_DATA_DIR = HOME_DIR + "/shared/"
PUBLIC_SUFFIX_LIST_FILENAME = "psl.txt"


def main():
    """Download the PSL and BGP data, then generate all reports."""
    # Download the public suffix list
    logging.info("Downloading the public suffix list...")
    try:
        updatePSL(PUBLIC_SUFFIX_LIST_FILENAME)
    # RequestException is the base class for all exceptions raised by
    # the requests library, which is what is used by
    # publicsuffixlist.update.updatePSL to make the actual HTTP request
    # to download the PSL.
    except RequestException:
        logging.critical(
            "Unable to download the Public Suffix List", exc_info=True, stack_info=True
        )
        return

    # Download and preprocess some BGP data for later use by pyasn
    # inside of generate_trustymail_report.py
    logging.info("Downloading BGP data for pyasn...")
    # pyasn_util_download.py isn't written in a way that easily allows
    # it to be run in any other way.  Hence the nosec.
    download_cmd = "pyasn_util_download.py --latestv46"
    os.system(download_cmd)  # nosec B605 # noqa: DUO106
    logging.info("Preprocessing BGP data for pyasn...")
    # pyasn_util_convert.py isn't written in a way that easily allows
    # it to be run in any other way.  Hence the nosec.
    convert_cmd = "pyasn_util_convert.py --single rib.*.bz2 ipasn.dat"
    os.system(convert_cmd)  # nosec 605 # noqa: DUO106
    logging.info("Cleaning up...")
    for p in Path.cwd().glob("rib.*.bz2"):
        p.unlink()

    agency_csv = open(SHARED_DATA_DIR + "artifacts/unique-agencies.csv")
    for row in sorted(csv.reader(agency_csv)):
        bash_command = (
            HOME_DIR + "/report/generate_trustymail_report.py " + '"' + row[0] + '"'
        )
        # generate_trustymail_report.py isn't written in a way that
        # easily allows it to be run in any other way.  Hence the
        # nosec.
        os.system(bash_command)  # nosec B605 # noqa: DUO106

    logging.info("Cleaning up...")
    (Path.cwd() / "ipasn.dat").unlink()
    (Path.cwd() / "psl.txt").unlink()


if __name__ == "__main__":
    main()
