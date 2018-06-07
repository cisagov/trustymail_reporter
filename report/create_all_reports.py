#!/usr/bin/env python3

import os
import csv

import pyasn

HOME_DIR = '/home/reporter'
SHARED_DATA_DIR = HOME_DIR + '/shared/'

def main():
    # Download and preprocess some BGP data for later use by pyasn
    # inside of generate_trustymail_report.py
    print('Downloading BGP data for pyasn...')
    os.system('pyasn_util_download.py --latestv46')
    print('Preprocessing BGP data for pyasn...')
    os.system('pyasn_util_convert.py --single rib.*.bz2 ipasn.dat')
    print('Cleaning up...')
    os.system('rm rib.*.bz2')

    agency_csv = open(SHARED_DATA_DIR + 'artifacts/unique-agencies.csv')
    for row in sorted(csv.reader(agency_csv)):
        bashCommand = HOME_DIR + '/report/generate_trustymail_report.py ' + '"' + row[0] + '"'
        os.system(bashCommand)

    print('Cleaning up...')
    os.system('rm ipasn.dat')

if __name__ == '__main__':
    main()
