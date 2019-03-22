#!/usr/bin/env python3

import csv
import logging
import os
from urllib.error import URLError

import publicsuffix

HOME_DIR = '/home/reporter'
SHARED_DATA_DIR = HOME_DIR + '/shared/'
PUBLIC_SUFFIX_LIST_FILENAME = 'psl.txt'


def main():
    # Download the public suffix list
    logging.info('Downloading the public suffix list...')
    try:
        psl = publicsuffix.fetch()
    except URLError as e:
        logging.critical('Unable to download the Public Suffix List',
                         exc_info=True, stack_info=True)
        return
    with open(PUBLIC_SUFFIX_LIST_FILENAME, 'w', encoding='utf-8') as psl_file:
        psl_file.write(psl.read())

    # Download and preprocess some BGP data for later use by pyasn
    # inside of generate_trustymail_report.py
    logging.info('Downloading BGP data for pyasn...')
    os.system('pyasn_util_download.py --latestv46')
    logging.info('Preprocessing BGP data for pyasn...')
    os.system('pyasn_util_convert.py --single rib.*.bz2 ipasn.dat')
    logging.info('Cleaning up...')
    os.system('rm rib.*.bz2')

    agency_csv = open(SHARED_DATA_DIR + 'artifacts/unique-agencies.csv')
    for row in sorted(csv.reader(agency_csv)):
        bashCommand = HOME_DIR + '/report/generate_trustymail_report.py ' + \
            '"' + row[0] + '"'
        os.system(bashCommand)

    logging.info('Cleaning up...')
    os.system('rm ipasn.dat')
    os.system('rm psl.txt')


if __name__ == '__main__':
    main()
