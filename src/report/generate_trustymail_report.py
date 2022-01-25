#!/usr/bin/env python3

"""Create Trustworthy Email Agency Report PDF.

Usage:
  generate_trustymail_report [options] "AGENCY"
  generate_trustymail_report (-h | --help)
  generate_trustymail_report --version

Options:
  -d --debug                     Keep intermediate files for debugging.
  -h --help                      Show this screen.
  --version                      Show version.
"""
# Standard Python Libraries
import codecs
import csv
from datetime import datetime, time, timedelta, timezone
import json
import logging
import os
import re
import shutil

# The subprocess module is frowned upon by Bandit, but we need it
# here.
import subprocess  # nosec B404
import sys
import tempfile

# Third-Party Libraries
import boto3

# intra-project modules
import chevron
import dns.resolver
import dns.reversename
from docopt import docopt
import graphs
from mongo_db_from_config import db_from_config
import publicsuffix
import pyasn
import requests
from requests_aws4auth import AWS4Auth

# constants
DB_CONFIG_FILE = "/run/secrets/scan_read_creds.yml"
TRUSTYMAIL_RESULTS_CSV_FILE = "trustymail_results.csv"
TRUSTYMAIL_DMARC_FAILURES_CSV_FILE = "dmarc_failures.csv"
DMARC_RESULTS_CSV_FILE = "dmarc_aggregate_report.csv"
MUSTACHE_FILE = "trustymail_report.mustache"
REPORT_JSON = "trustymail_report.json"
REPORT_PDF = "trustymail_report.pdf"
REPORT_TEX = "trustymail_report.tex"
ASSETS_DIR_SRC = "../assets"
ASSETS_DIR_DST = "assets"
LATEX_ESCAPE_MAP = {
    "$": "\\$",
    "%": "\\%",
    "&": "\\&",
    "#": "\\#",
    "_": "\\_",
    "{": "\\{",
    "}": "\\}",
    "[": "{[}",
    "]": "{]}",
    "'": "{'}",
    "\\": "\\textbackslash{}",
    "~": "\\textasciitilde{}",
    "<": "\\textless{}",
    ">": "\\textgreater{}",
    "^": "\\textasciicircum{}",
    "`": "{}`",
    "\n": "\\newline{}",
}
BOD1801_DMARC_RUA_URI = "mailto:reports@dmarc.cyber.dhs.gov"
ES_REGION = "us-east-1"
ES_URL = (
    "https://search-dmarc-import-elasticsearch-"
    "ekc3pdnqzcuifgu4qssctvq4v4.us-east-1.es.amazonaws.com"
    "/dmarc_aggregate_reports"
)
ES_URL_NO_INDEX = re.sub("/[^/]*$", "", ES_URL)
ES_RETRIEVE_SIZE = 10000
PREPROCESSED_BGP_DATA_FILE = "ipasn.dat"
PUBLIC_SUFFIX_LIST_FILENAME = "psl.txt"


class ReportGenerator(object):
    """Class for generating a Trustworthy Email report."""

    def __init__(self, db, agency, debug=False):
        """Initialize the instance."""
        self.__db = db
        self.__agency = agency
        self.__agency_id = None
        self.__debug = debug
        self.__generated_time = datetime.utcnow()
        self.__results = dict()  # reusable query results
        self.__mail_domains = set()
        self.__dmarc_results = dict()
        self.__requests = None
        self.__report_doc = {"scores": []}
        self.__all_domains = []
        self.__base_domains = []
        # responsive second-level/base-domains
        self.__eligible_domains_count = 0
        self.__eligible_subdomains_count = 0  # responsive subdomains
        self.__all_eligible_domains_count = 0  # responsive base+subs
        self.__ineligible_domains = []  # NOT CURRENTLY USED
        self.__domain_count = 0
        self.__base_domain_count = 0
        self.__subdomain_count = 0
        self.__mx_record_count = 0
        self.__valid_spf_count = 0
        self.__spf_covered_count = 0
        self.__valid_dmarc_count = 0
        self.__valid_dmarc_reject_count = 0
        self.__valid_dmarc_subdomain_reject_count = 0
        self.__valid_dmarc_pct_count = 0
        self.__valid_dmarc_policy_of_reject_count = 0
        self.__valid_dmarc_bod1801_rua_uri_count = 0
        self.__base_domain_supports_smtp_count = 0
        self.__domain_supports_smtp_count = 0
        self.__base_domain_plus_smtp_subdomain_count = 0
        self.__supports_starttls_count = 0
        self.__has_no_weak_crypto_count = 0
        self.__bod_1801_compliant_count = 0
        # self.__report_oid = ObjectId()     # For future use
        # The pyasn database mapping IPs to ASNs and vice versa
        self.__asndb = pyasn.pyasn(PREPROCESSED_BGP_DATA_FILE)
        # The public suffix list
        self.__psl = publicsuffix.PublicSuffixList(PUBLIC_SUFFIX_LIST_FILENAME)

        #
        # Configure the dnspython library
        #

        # Our resolver
        #
        # Note that it will use the system configuration in
        # /etc/resolv.conf.
        self.__resolver = dns.resolver.Resolver()
        # Retry DNS servers if we receive a SERVFAIL response from them.  We
        # set this to False because, unless the reason for the SERVFAIL is
        # truly temporary and resolves before trustymail finishes scanning the
        # domain, this obscures the potentially informative SERVFAIL error as a
        # DNS timeout because of the way dns.resolver.query() is written.  See
        # http://www.dnspython.org/docs/1.14.0/dns.resolver-pysrc.html#query.
        self.__resolver.retry_servfail = False
        # Add a least-recently used cache with the default of 100000
        # entries.  This only slightly speeds up the retrieval of PTR
        # records corresponding to DMARC aggregate reports, since the
        # IPs in separate reports are rarely the same.
        self.__resolver.cache = dns.resolver.LRUCache()
        # Allow DNS queries 2.5 seconds to complete before timing out.
        # The default is 30s, but such a long lifetime can cause the
        # reporting to take forever since the PTR record lookups for
        # many of the IPs in DMARC aggregate reports hang and consume
        # the entire lifetime.
        self.__resolver.lifetime = 2.5

        # Get weak crypto data for this agency's domains from the
        # sslyze-scan collection
        #
        # TODO: Consider using aggregation $lookup with uncorrelated
        # subquery to fetch trustymail and sslyze_scan data in one
        # query (MongoDB server 3.6 and later)
        sslyze_data_all_domains = dict()
        for host in self.__db.sslyze_scan.find(
            {
                "latest": True,
                "agency.name": agency,
                "scanned_port": {"$in": [25, 587, 465]},
            },
            {
                "_id": 0,
                "domain": 1,
                "scanned_port": 1,
                "scanned_hostname": 1,
                "sslv2": 1,
                "sslv3": 1,
                "any_3des": 1,
                "any_rc4": 1,
            },
        ):
            current_host_dict = {
                "scanned_hostname": host["scanned_hostname"],
                "scanned_port": host["scanned_port"],
                "sslv2": host["sslv2"],
                "sslv3": host["sslv3"],
                "any_3des": host["any_3des"],
                "any_rc4": host["any_rc4"],
            }

            if not sslyze_data_all_domains.get(host["domain"]):
                sslyze_data_all_domains[host["domain"]] = [current_host_dict]
            else:
                sslyze_data_all_domains[host["domain"]].append(current_host_dict)

        def add_weak_crypto_data_to_domain(domain_doc, sslyze_data_all_domains):
            # Look for weak crypto data in sslyze_data_all_domains and
            # add hosts with weak crypto to
            # domain_doc['hosts_with_weak_crypto']
            domain_doc["domain_has_weak_crypto"] = False
            domain_doc["hosts_with_weak_crypto"] = []

            if sslyze_data_all_domains.get(domain_doc["domain"]):
                for host in sslyze_data_all_domains[domain_doc["domain"]]:
                    if (
                        host["sslv2"]
                        or host["sslv3"]
                        or host["any_3des"]
                        or host["any_rc4"]
                    ):
                        domain_doc["domain_has_weak_crypto"] = True
                        domain_doc["hosts_with_weak_crypto"].append(host)
            return domain_doc

        # Get list of all domains from the database
        all_domains_cursor = self.__db.trustymail.find(
            {"latest": True, "agency.name": agency}, no_cursor_timeout=True
        )

        for domain_doc in all_domains_cursor:
            self.__domain_count += 1
            domain_doc = add_weak_crypto_data_to_domain(
                domain_doc, sslyze_data_all_domains
            )
            self.__all_domains.append(domain_doc)
            if domain_doc["is_base_domain"]:
                domain_doc["subdomains"] = list(
                    self.__db.trustymail.find(
                        {
                            "latest": True,
                            "base_domain": domain_doc["base_domain"],
                            "is_base_domain": False,
                        }
                    ).sort([("domain", 1)])
                )
                self.__subdomain_count += len(domain_doc["subdomains"])
                for subdomain_doc in domain_doc["subdomains"]:
                    add_weak_crypto_data_to_domain(
                        subdomain_doc, sslyze_data_all_domains
                    )
                self.__base_domains.append(domain_doc)
            self.__agency_id = domain_doc["agency"]["id"]

        # We instantiated this cursor without a timeout, so we have to
        # close it manually.
        all_domains_cursor.close()

        # Get count of second-level domains an agency owns
        self.__base_domain_count = self.__db.trustymail.count_documents(
            {"latest": True, "agency.name": agency, "is_base_domain": True}
        )

        # Get a list of all domains with DMARC records that are
        # associated with this agency's email servers.  The domain
        # associated with an aggregate report will be the domain
        # corresponding to the DMARC record that applies (whether this
        # is the domain itself or the base domain), so clearly we only
        # need to concern ourselves with domains for which there is a
        # DMARC record.
        #
        # See here for details:
        # https://tools.ietf.org/html/rfc7489#section-6.6.3
        self.__mail_domains = {
            x["domain"]
            for x in self.__db.trustymail.find(
                {"latest": True, "agency.name": agency, "dmarc_record": True},
                {"_id": False, "domain": True},
            )
        }
        logging.info(
            "Retrieved {} mail domains for agency {}: {}".format(
                len(self.__mail_domains), agency, self.__mail_domains
            )
        )

        # Grab the AWS credentials, since we will need them to query
        # elasticsearch
        self.__aws_credentials = boto3.Session().get_credentials()

        # Get all DMARC aggregate reports associated with these domains
        for domain in self.__mail_domains:
            try:
                self.__query_elasticsearch(domain)
            except requests.exceptions.RequestException:
                logging.exception("Unable to perform Elasticsearch query")

            logging.info(
                "Retrieved {} DMARC reports for domain {}".format(
                    len(self.__dmarc_results[domain]), domain
                )
            )

    def __query_elasticsearch(self, domain):
        """Query for all aggregate reports in the past week.

        Query Elasticsearch for all DMARC aggregate reports
        received for this agency in the past seven days.

        Parameters
        ----------
        domain : str
            The domain for which DMARC aggregate reports are to be
            queried from the Elasticsearch database.

        Throws
        ------
        requests.exceptions.RequestException: If an error is returned
        by Elasticsearch.
        """
        # Construct the auth from the AWS credentials
        awsauth = AWS4Auth(
            self.__aws_credentials.access_key,
            self.__aws_credentials.secret_key,
            ES_REGION,
            "es",
            session_token=self.__aws_credentials.token,
        )
        # Now construct the query.  We want all DMARC aggregrate reports since
        # midnight UTC seven days ago.
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        last_date = datetime.combine(
            seven_days_ago.date(), time(tzinfo=timezone.utc)
        ).timestamp()
        query = {
            "size": ES_RETRIEVE_SIZE,
            "query": {
                "constant_score": {
                    "filter": {
                        "bool": {
                            "filter": [
                                {"term": {"policy_published.domain": domain}},
                                {
                                    "range": {
                                        "report_metadata.date_range.begin": {
                                            "gte": last_date
                                        }
                                    }
                                },
                            ]
                        }
                    }
                }
            },
        }

        # Now perform the query.  We have to do a little finagling with the
        # scroll API in order to get past the 10000 document limit.  (I
        # verified that we do run into that limit on occasion.)
        scroll_again = True
        scroll_id = None
        response = requests.get(
            "{}/_search?scroll=1m".format(ES_URL),
            auth=awsauth,
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=300,
        )
        # Raises an exception if we didn't get back a 200 code
        response.raise_for_status()

        hits = response.json()["hits"]["hits"]
        scroll_id = response.json()["_scroll_id"]
        if domain in self.__dmarc_results:
            self.__dmarc_results[domain].extend(hits)
        else:
            self.__dmarc_results[domain] = hits

        # If there were fewer hits than ES_RETRIEVE_SIZE then there is no need
        # to keep scrolling
        if len(hits) < ES_RETRIEVE_SIZE:
            scroll_again = False

        while scroll_again:
            scroll_json = {"scroll": "1m", "scroll_id": scroll_id}
            url = "{}/_search/scroll".format(ES_URL_NO_INDEX)
            response = requests.get(
                url,
                auth=awsauth,
                json=scroll_json,
                headers={"Content-Type": "application/json"},
                timeout=300,
            )
            # Raises an exception if we didn't get back a 200 code
            response.raise_for_status()

            hits = response.json()["hits"]["hits"]
            self.__dmarc_results[domain].extend(hits)

            # If there were fewer hits than ES_RETRIEVE_SIZE then there is no
            # need to keep scrolling
            if len(hits) < ES_RETRIEVE_SIZE:
                scroll_again = False

        # Delete the scroll context.  These are expensive resources,
        # so there is a limit on the number that can be kept around.
        # The default limit is 500, and we have bumped into that limit
        # before.
        response = requests.delete(
            "{}/_search/scroll".format(ES_URL_NO_INDEX),
            auth=awsauth,
            json={"scroll_id": scroll_id},
            headers={"Content-Type": "application/json"},
            timeout=300,
        )
        # Raise an exception if we don't get back a 200 code
        response.raise_for_status()

    def __score_domain(self, domain):
        score = {
            "subdomain_scores": list(),
            "live": domain["live"],
            "has_live_smtp_subdomains": False,
        }

        # Take care of the DMARC agggregate report stuff
        #
        # Count up the number of DMARC failures from the DMARC aggregate
        # reports for this base domain.
        num_dmarc_failures = 0
        dmarc_results = self.__dmarc_results.get(domain["domain"])
        if dmarc_results is not None:
            for report in self.__dmarc_results[domain["domain"]]:
                records = report["_source"]["record"]
                if isinstance(records, list):
                    for record in records:
                        if ReportGenerator.is_failure(record):
                            num_dmarc_failures += record["row"]["count"]
                elif isinstance(records, dict):
                    if ReportGenerator.is_failure(records):
                        num_dmarc_failures += records["row"]["count"]

        score["num_dmarc_failures"] = num_dmarc_failures

        if domain["live"]:
            score["is_base_domain"] = domain["is_base_domain"]
            # Check if the current domain is the base domian.
            if domain["is_base_domain"]:
                self.__eligible_domains_count += 1
                self.__all_eligible_domains_count += 1

                # Count the base domains that support SMTP
                if domain["domain_supports_smtp"]:
                    self.__base_domain_supports_smtp_count += 1
            else:
                self.__eligible_subdomains_count += 1
                self.__all_eligible_domains_count += 1

            score["domain"] = domain["domain"]

            # Does the given domain have a DMARC record
            score["dmarc_record"] = domain["dmarc_record"]

            # Is the DMARC record syntactically and logically correct,
            # either at the domain or its base domain
            score["valid_dmarc"] = (
                domain["valid_dmarc"] or domain["valid_dmarc_base_domain"]
            )
            if score["valid_dmarc"]:
                self.__valid_dmarc_count += 1

            # Placeholder for future use in reports.
            if domain["dmarc_results"] is None or len(domain["dmarc_results"]) == 0:
                score["dmarc_results"] = "None"
            else:
                score["dmarc_results"] = domain["dmarc_results"]

            # dmarc_policy is adjudicated by trustymail, but it doesn't factor
            # in whether or not the DMARC record is valid, so we check here
            score["dmarc_policy"] = domain["dmarc_policy"]
            score["valid_dmarc_policy_reject"] = False
            if score["valid_dmarc"] and domain["dmarc_policy"] == "reject":
                self.__valid_dmarc_reject_count += 1
                score["valid_dmarc_policy_reject"] = True

            score["dmarc_subdomain_policy"] = domain["dmarc_subdomain_policy"]
            score["valid_dmarc_subdomain_policy_reject"] = False
            # According to RFC7489, "'sp' will be ignored for DMARC
            # records published on subdomains of Organizational
            # Domains due to the effect of the DMARC policy discovery
            # mechanism."  Therefore we have chosen not to penalize
            # for sp!=reject when considering subdomains.
            #
            # See here for more details:
            # https://tools.ietf.org/html/rfc7489#section-6.3
            if score["valid_dmarc"] and (
                not domain["is_base_domain"]
                or domain["dmarc_subdomain_policy"] == "reject"
            ):
                self.__valid_dmarc_subdomain_reject_count += 1
                score["valid_dmarc_subdomain_policy_reject"] = True

            score["dmarc_policy_percentage"] = domain["dmarc_policy_percentage"]
            score["valid_dmarc_policy_pct"] = False
            if score["valid_dmarc"] and domain["dmarc_policy_percentage"] == 100:
                self.__valid_dmarc_pct_count += 1
                score["valid_dmarc_policy_pct"] = True

            # valid_dmarc_policy_of_reject means that the DMARC record is:
            #  - valid
            #  - policy is 'reject' (p=reject)
            #  - subdomain policy is 'reject' (sp=reject, if specified)
            #  - policy percentage is 100 (pct=100, if specified)
            score["valid_dmarc_policy_of_reject"] = False
            if (
                score["valid_dmarc_policy_reject"]
                and score["valid_dmarc_subdomain_policy_reject"]
                and score["valid_dmarc_policy_pct"]
            ):
                self.__valid_dmarc_policy_of_reject_count += 1
                score["valid_dmarc_policy_of_reject"] = True

            # Does the domain have a valid DMARC record that includes
            # the correct BOD 18-01 rua URI
            score["valid_dmarc_bod1801_rua_uri"] = False
            if score["valid_dmarc"]:
                for uri_dict in domain["aggregate_report_uris"]:
                    if uri_dict["uri"].lower() == BOD1801_DMARC_RUA_URI.lower():
                        self.__valid_dmarc_bod1801_rua_uri_count += 1
                        score["valid_dmarc_bod1801_rua_uri"] = True
                        break

            # If the server has any valid MX record it is considered
            # as sending mail
            score["mx_record"] = domain["mx_record"]
            if domain["mx_record"]:
                self.__mx_record_count += 1

            # Probably not used in the report for now, but go ahead
            # and include it.
            if domain["mail_servers"] is None or len(domain["mail_servers"]) == 0:
                score["mail_servers"] = "None"
            else:
                score["mail_servers"] = domain["mail_servers"]

            # Does the given domain have a SPF record
            score["spf_record"] = domain["spf_record"]

            # Is the record syntactically and logically correct
            score["valid_spf"] = domain["valid_spf"]

            # For base domains, "SPF covered" is simply the value of
            # domain['valid_spf'].
            # For non-base domains, "SPF covered" means that the domain either
            # has valid SPF or has no SPF record and is covered by a
            # DMARC "policy of reject"
            if domain["is_base_domain"]:
                score["spf_covered"] = domain["valid_spf"]
            else:
                score["spf_covered"] = domain["valid_spf"] or (
                    domain["spf_record"] is False
                    and score["valid_dmarc_policy_of_reject"]
                )

            # Placeholder for future use in reports.
            if domain["spf_results"] is None or len(domain["spf_results"]) == 0:
                score["spf_results"] = "None"
            else:
                score["spf_results"] = domain["spf_results"]

            # Does the domain support SMTP?
            score["domain_supports_smtp"] = domain["domain_supports_smtp"]
            score["smtp_servers"] = list()
            if domain["domain_supports_smtp"]:
                score["smtp_servers"] = [
                    s.strip() for s in domain["domain_supports_smtp_results"].split(",")
                ]
                self.__domain_supports_smtp_count += 1

            # Does the domain support STARTTLS?
            score["domain_supports_starttls"] = domain["domain_supports_starttls"]
            if not domain["domain_supports_starttls"]:
                starttls_servers = [
                    s.strip()
                    for s in domain["domain_supports_starttls_results"].split(",")
                ]
                score["smtp_servers_without_starttls"] = list(
                    set(score["smtp_servers"]) - set(starttls_servers)
                )

            # Does the domain have weak crypto?
            score["domain_has_weak_crypto"] = domain["domain_has_weak_crypto"]
            score["hosts_with_weak_crypto"] = list()
            for host in domain["hosts_with_weak_crypto"]:
                weak_crypto_list = list()
                for (wc_key, wc_text) in [
                    ("sslv2", "SSLv2"),
                    ("sslv3", "SSLv3"),
                    ("any_3des", "3DES"),
                    ("any_rc4", "RC4"),
                ]:
                    if host[wc_key]:
                        weak_crypto_list.append(wc_text)
                score["hosts_with_weak_crypto"].append(
                    {
                        "hostname": host["scanned_hostname"],
                        "port": host["scanned_port"],
                        "weak_crypto_list_str": ",".join(weak_crypto_list),
                    }
                )

            score["bod_1801_compliant"] = False
            # For SPF, STARTTLS, Weak Crypto and BOD 18-01 Compliance,
            # we only count base domains and subdomains that support
            # SMTP
            if domain["is_base_domain"] or (
                not domain["is_base_domain"] and domain["domain_supports_smtp"]
            ):
                self.__base_domain_plus_smtp_subdomain_count += 1
                if domain["valid_spf"]:
                    self.__valid_spf_count += 1
                if score["spf_covered"]:
                    self.__spf_covered_count += 1
                if not domain["domain_has_weak_crypto"]:
                    self.__has_no_weak_crypto_count += 1
                if (
                    domain["domain_supports_smtp"]
                    and domain["domain_supports_starttls"]
                ) or not domain["domain_supports_smtp"]:
                    # If you don't support SMTP, you still get credit
                    # here for supporting STARTTLS
                    self.__supports_starttls_count += 1
                    # Is the domain compliant with BOD 18-01?
                    #  * Uses STARTTLS on all SMTP servers OR does not
                    #    support SMTP
                    #  * Has "SPF covered" (see comment above for definition)
                    #  * Has no weak crypto (SSLv2, SSLv3, 3DES, RC4)
                    #  * Has valid DMARC record with p=reject,
                    #    sp=reject, pct=100, and
                    #    rua=mailto:reports@dmarc.cyber.dhs.gov
                    if (
                        score["spf_covered"]
                        and not domain["domain_has_weak_crypto"]
                        and score["valid_dmarc_policy_reject"]
                        and score["valid_dmarc_subdomain_policy_reject"]
                        and score["valid_dmarc_policy_pct"]
                        and score["valid_dmarc_bod1801_rua_uri"]
                    ):
                        score["bod_1801_compliant"] = True
                        self.__bod_1801_compliant_count += 1

            if domain.get("subdomains"):  # if this domain has any subdomains
                for subdomain in domain["subdomains"]:
                    subdomain_score = self.__score_domain(subdomain)
                    # if the subdomain has its own dmarc record or if the
                    # base domain doesn't have a valid dmarc record,
                    # add subdomain to the subdomain_scores list
                    if subdomain_score and (
                        subdomain["dmarc_record"] or not domain["valid_dmarc"]
                    ):
                        # add subdomain score to domain's list of
                        # subdomain_scores
                        score["subdomain_scores"].append(subdomain_score)
            return score

        else:  # domain['live'] == "False"
            # Check if any subdomains of non-live domains support
            # SMTP; if so, we want to include them in our results, per
            # CYHY-554)
            if domain.get("subdomains"):  # if this domain has any subdomains
                for subdomain in domain["subdomains"]:
                    if subdomain["domain_supports_smtp"]:
                        score["has_live_smtp_subdomains"] = True
                        subdomain_score = self.__score_domain(subdomain)
                        # If the subdomain has it's own dmarc record,
                        # add subdomain to the subdomain_scores list.
                        # No need to check if base domain doesn't have
                        # a valid DMARC record because base domain is
                        # not live.
                        if subdomain_score and subdomain["dmarc_record"]:
                            # add subdomain score to domain's list of
                            # subdomain_scores
                            score["subdomain_scores"].append(subdomain_score)
            if score["has_live_smtp_subdomains"]:
                return score
            else:
                # only include base domains in the ineligible count;
                # otherwise lots of non-existent subs will show in the
                # report
                if domain["is_base_domain"]:
                    # NOT CURRENTLY USED?
                    self.__ineligible_domains.append({"domain": domain["domain"]})
                return None

    def __populate_report_doc(self):
        # sort list of all domains
        self.__all_domains.sort(key=lambda x: x["domain"])
        # sort list of base domains
        self.__base_domains.sort(key=lambda x: x["domain"])

        # Go through each base domain and score the attributes
        for domain in self.__base_domains:
            score = self.__score_domain(domain)
            if score:
                # Add domain's score to master list of scores
                self.__report_doc["scores"].append(score)

        if not self.__all_eligible_domains_count:
            print(
                'WARNING: "{}" has no live domains - exiting without generating report!'.format(
                    self.__agency
                )
            )
            sys.exit(-1)

        self.__supports_starttls_percentage = round(
            self.__supports_starttls_count
            / self.__base_domain_plus_smtp_subdomain_count
            * 100.0,
            1,
        )
        self.__spf_coverered_percentage = round(
            self.__spf_covered_count
            / self.__base_domain_plus_smtp_subdomain_count
            * 100.0,
            1,
        )
        self.__has_no_weak_crypto_percentage = round(
            self.__has_no_weak_crypto_count
            / self.__base_domain_plus_smtp_subdomain_count
            * 100.0,
            1,
        )
        self.__valid_dmarc_percentage = round(
            self.__valid_dmarc_count / self.__all_eligible_domains_count * 100.0, 1
        )
        self.__valid_dmarc_reject_percentage = round(
            self.__valid_dmarc_policy_of_reject_count
            / self.__all_eligible_domains_count
            * 100.0,
            1,
        )
        self.__valid_dmarc_bod1801_rua_uri_percentage = round(
            self.__valid_dmarc_bod1801_rua_uri_count
            / self.__all_eligible_domains_count
            * 100.0,
            1,
        )
        self.__bod_1801_compliant_percentage = round(
            self.__bod_1801_compliant_count
            / self.__base_domain_plus_smtp_subdomain_count
            * 100.0,
            1,
        )

        print(
            self.__agency_id,
            self.__agency,
            self.__base_domain_count,
            self.__subdomain_count,
            self.__all_eligible_domains_count,
            self.__spf_covered_count,
            self.__valid_dmarc_count,
            self.__valid_dmarc_policy_of_reject_count,
            self.__valid_dmarc_reject_percentage,
        )

    def __latex_escape(self, to_escape):
        return "".join([LATEX_ESCAPE_MAP.get(i, i) for i in to_escape])

    def __latex_escape_structure(self, data):
        """Escape data for LaTeX.

        Note that this method assumes that all sequences contain
        dicts.
        """
        if isinstance(data, dict):
            for k, v in data.items():
                if k.endswith("_tex"):  # skip special tex values
                    continue
                if isinstance(v, str):
                    data[k] = self.__latex_escape(v)
                else:
                    self.__latex_escape_structure(v)
        elif isinstance(data, (list, tuple)):
            for i in data:
                self.__latex_escape_structure(i)

    def generate_trustymail_report(self):
        """Generate the Trustworthy Email report."""
        print("\tparsing data")
        # build up the report_doc from the query results
        self.__populate_report_doc()

        # create a working directory
        original_working_dir = os.getcwd()
        if self.__debug:
            temp_working_dir = tempfile.mkdtemp(dir=original_working_dir)
        else:
            temp_working_dir = tempfile.mkdtemp()
        os.chdir(temp_working_dir)

        # setup the working directory
        self.__setup_work_directory(temp_working_dir)

        print("\tgenerating attachments")
        # generate attachments
        self.__generate_attachments()

        print("\tgenerating charts")
        # generate charts
        self.__generate_charts()

        # generate json input to mustache
        self.__generate_mustache_json(REPORT_JSON)

        # generate latex json + mustache
        self.__generate_latex(MUSTACHE_FILE, REPORT_JSON, REPORT_TEX)

        print("\tassembling PDF")
        # generate report figures + latex
        self.__generate_final_pdf()

        # revert working directory
        os.chdir(original_working_dir)

        # copy report to original working directory
        # and delete working directory
        if not self.__debug:
            src_filename = os.path.join(temp_working_dir, REPORT_PDF)
            datestamp = self.__generated_time.strftime("%Y-%m-%d")
            dest_filename = "cyhy-{}-{}-tmail-report.pdf".format(
                self.__agency_id, datestamp
            )
            shutil.move(src_filename, dest_filename)
        return self.__results

    def __setup_work_directory(self, work_dir):
        me = os.path.realpath(__file__)
        my_dir = os.path.dirname(me)
        for n in [MUSTACHE_FILE]:  # add other files as needed
            file_src = os.path.join(my_dir, n)
            file_dst = os.path.join(work_dir, n)
            shutil.copyfile(file_src, file_dst)
        # copy static assets
        dir_src = os.path.join(my_dir, ASSETS_DIR_SRC)
        dir_dst = os.path.join(work_dir, ASSETS_DIR_DST)
        shutil.copytree(dir_src, dir_dst)

    ###########################################################################
    #  Attachment Generation
    ###########################################################################
    def __generate_attachments(self):
        self.__generate_trustymail_attachment()
        self.__generate_dmarc_failures_attachment()

    def __generate_trustymail_attachment(self):
        header_fields = (
            "Domain",
            "Base Domain",
            "Domain Is Base Domain",
            "Live",
            "MX Record",
            "Mail Servers",
            "Mail Server Ports Tested",
            "Domain Supports SMTP",
            "Domain Supports SMTP Results",
            "Domain Supports STARTTLS",
            "Domain Supports STARTTLS Results",
            "SPF Record",
            "Valid SPF",
            "SPF Results",
            "DMARC Record",
            "Valid DMARC",
            "DMARC Results",
            "DMARC Record on Base Domain",
            "Valid DMARC Record on Base Domain",
            "DMARC Results on Base Domain",
            "DMARC Policy",
            "DMARC Policy Percentage",
            "DMARC Subdomain Policy",
            "DMARC Aggregate Report URIs",
            "DMARC Forensic Report URIs",
            "DMARC Has Aggregate Report URI",
            "DMARC Has Forensic Report URI",
            "Syntax Errors",
            "Debug Info",
            "Domain Supports Weak Crypto",
            "Mail-Sending Hosts with Weak Crypto",
        )
        data_fields = (
            "domain",
            "base_domain",
            "is_base_domain",
            "live",
            "mx_record",
            "mail_servers",
            "mail_server_ports_tested",
            "domain_supports_smtp",
            "domain_supports_smtp_results",
            "domain_supports_starttls",
            "domain_supports_starttls_results",
            "spf_record",
            "valid_spf",
            "spf_results",
            "dmarc_record",
            "valid_dmarc",
            "dmarc_results",
            "dmarc_record_base_domain",
            "valid_dmarc_base_domain",
            "dmarc_results_base_domain",
            "dmarc_policy",
            "dmarc_policy_percentage",
            "dmarc_subdomain_policy",
            "aggregate_report_uris",
            "forensic_report_uris",
            "has_aggregate_report_uri",
            "has_forensic_report_uri",
            "syntax_errors",
            "debug_info",
            "domain_has_weak_crypto",
            "hosts_with_weak_crypto_str",
        )
        with open(TRUSTYMAIL_RESULTS_CSV_FILE, "w") as out_file:
            header_writer = csv.DictWriter(
                out_file, header_fields, extrasaction="ignore"
            )
            header_writer.writeheader()
            data_writer = csv.DictWriter(out_file, data_fields, extrasaction="ignore")

            def rehydrate_rua_or_ruf(d):
                """Reconstitute the rua or ruf string.

                Reconstitute the rua or ruf string from the dictionary
                that was retrieved from the database.

                Parameters
                ----------
                d : dict
                    The rua or ruf dictionary to be reconstituted.

                Returns
                -------
                str: The reconstituted rua or ruf string.
                """
                uri = d["uri"]
                modifier = d["modifier"]
                if not modifier:
                    result = uri
                else:
                    result = "{}!{}".format(uri, modifier)

                return result

            def rehydrate_hosts_with_weak_crypto(d):
                """Build string from dictionary.

                Build a string suitable for output from the dictionary
                that was retrieved from the database.

                Parameters
                ----------
                d : dict
                    The hosts_with_weak_crypto dictionary

                Returns
                -------
                str: The string with weak crypto host details.
                """
                hostname = d["scanned_hostname"]
                port = d["scanned_port"]

                weak_crypto_list = list()
                for (wc_key, wc_text) in [
                    ("sslv2", "SSLv2"),
                    ("sslv3", "SSLv3"),
                    ("any_3des", "3DES"),
                    ("any_rc4", "RC4"),
                ]:
                    if d[wc_key]:
                        weak_crypto_list.append(wc_text)
                result = "{}:{} [supports: {}]".format(
                    hostname, port, ",".join(weak_crypto_list)
                )

                return result

            def format_list(record_list):
                """Format a list into a string to increase readability."""
                # record_list should only be a list, not an integer, None, or
                # anything else.  Thus this if clause handles only empty lists.
                # This makes a "null" appear in the JSON output for empty
                # lists, as expected.
                if not record_list:
                    return None

                return ", ".join(record_list)

            for domain in self.__all_domains:
                ruas = [
                    rehydrate_rua_or_ruf(d) for d in domain["aggregate_report_uris"]
                ]
                rufs = [rehydrate_rua_or_ruf(d) for d in domain["forensic_report_uris"]]
                domain["aggregate_report_uris"] = format_list(ruas)
                domain["forensic_report_uris"] = format_list(rufs)
                hosts_with_weak_crypto = [
                    rehydrate_hosts_with_weak_crypto(d)
                    for d in domain["hosts_with_weak_crypto"]
                ]
                domain["hosts_with_weak_crypto_str"] = format_list(
                    hosts_with_weak_crypto
                )
                data_writer.writerow(domain)

    @staticmethod
    def is_failure(record):
        """Determine if the record represents a failure.

        Parameters
        ----------
        record : dict
            The DMARC aggregate report record to be checked.

        Returns
        -------
        bool: True if the record represents a DMARC failure and
        otherwise false.
        """
        policy_evaluated = record["row"]["policy_evaluated"]
        dkim_and_alignment = policy_evaluated["dkim"].lower() == "pass"
        spf_and_alignment = policy_evaluated["spf"].lower() == "pass"
        return not (dkim_and_alignment or spf_and_alignment)

    def __generate_dmarc_failures_attachment(self):
        """Generate the DMARC failures CSV attachment."""

        def process_record(domain, record, policy_published):
            """Process a DMARC aggregate report record.

            Process a DMARC aggregate report record, returning a
            dictionary containing the data of interest.

            Parameters
            ----------
            domain : str
                The domain corresponding to this DMARC aggregate report.

            record : dict
                The DMARC aggregate report record to be processed.

            policy_published : dict
                The published DMARC policy.

            Returns
            -------
            dict: A dictionary containing the data of interest.

            """
            x = {}
            x["DMARC Domain"] = domain
            ip = record["row"]["source_ip"]
            x["Source IP"] = ip
            # x['IP Owner'] = None

            # Try to find a PTR record
            x["PTR"] = None
            try:
                # Use UDP to hopefully avoid triggering DNS throttling
                # in AWS.
                ans = self.__resolver.resolve(
                    dns.reversename.from_address(ip),
                    "PTR",
                    tcp=False,
                    raise_on_no_answer=True,
                )
                # There is a trailing period that we don't want
                x["PTR"] = ans[0].to_text()[:-1]
            except (
                dns.resolver.NoNameservers,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout,
            ):
                # If we fail for any reason then there is no PTR
                # record
                pass

            # Grab some values
            x["ASN"] = self.__asndb.lookup(ip)[0]
            x["Count"] = record["row"]["count"]
            policy_evaluated = record["row"]["policy_evaluated"]
            x["Policy Applied"] = policy_evaluated["disposition"]

            # SPF and DKIM alignment modes.  The default is 'r' for both.
            spf_alignment_mode = "r"
            if "aspf" in policy_published:
                spf_alignment_mode = policy_published["aspf"]
            dkim_alignment_mode = "r"
            if "adkim" in policy_published:
                dkim_alignment_mode = policy_published["adkim"]

            # Override reason
            x["Override Reason"] = None
            if "reason" in policy_evaluated:
                reason = policy_evaluated["reason"]
                if isinstance(reason, list):
                    x["Override Reason"] = " ".join([rsn["type"] for rsn in reason])
                else:
                    x["Override Reason"] = reason["type"]

            # This field is required in the XSD
            header_from = record["identifiers"]["header_from"]

            # DKIM
            auth_results = record["auth_results"]
            x["DKIM Alignment Result"] = None
            x["DKIM Result"] = None
            x["DKIM Domain"] = None
            if auth_results is not None and "dkim" in auth_results:
                dkim = auth_results["dkim"]
                dkim_and_alignment = policy_evaluated["dkim"]
                if isinstance(dkim, list):
                    x["DKIM Result"] = " ".join([y["result"] for y in dkim])
                    x["DKIM Domain"] = " ".join([y["domain"] for y in dkim])
                    results = []
                    for y in dkim:
                        if y["result"].lower() == "pass":
                            if dkim_alignment_mode.lower() == "s":
                                # DKIM alignment mode is strict, so the from
                                # header has to match the domain exactly
                                if y["domain"].lower() == header_from.lower():
                                    results.append("aligned")
                                else:
                                    results.append("unaligned")
                            else:
                                # DKIM alignment is relaxed, so the header and
                                # the domain just need to come from the same
                                # base domain
                                domain = y["domain"]
                                base_domain = self.__psl.get_public_suffix(domain)
                                if base_domain is None:
                                    logging.warning(
                                        "Unable to determine public suffix for domain %s",
                                        domain,
                                    )
                                    results.append("unaligned")
                                    continue

                                header_base_domain = self.__psl.get_public_suffix(
                                    header_from
                                )
                                if header_base_domain is None:
                                    logging.warning(
                                        "Unable to determine public suffix for header domain %s",
                                        header_from,
                                    )
                                    results.append("unaligned")
                                    continue

                                if base_domain.lower() == header_base_domain.lower():
                                    results.append("aligned")
                                else:
                                    results.append("unaligned")
                        else:
                            results.append("fail")
                    x["DKIM Alignment Result"] = " ".join(results)
                else:
                    x["DKIM Result"] = dkim["result"]
                    x["DKIM Domain"] = dkim["domain"]
                    if x["DKIM Result"].lower() == "pass":
                        if dkim_and_alignment.lower() == "pass":
                            x["DKIM Alignment Result"] = "aligned"
                        else:
                            x["DKIM Alignment Result"] = "unaligned"
                    else:
                        x["DKIM Alignment Result"] = "fail"

            # SPF
            #
            # This field is required in the XSD, but occassionally it isn't
            # actually present.
            x["SPF Alignment Result"] = None
            x["SPF Result"] = None
            x["SPF Domain"] = None
            if auth_results is not None and "spf" in auth_results:
                spf = auth_results["spf"]
                spf_and_alignment = policy_evaluated["spf"]
                if isinstance(spf, list):
                    x["SPF Result"] = " ".join([y["result"] for y in spf])
                    x["SPF Domain"] = " ".join([y["domain"] for y in spf])
                    results = []
                    for y in spf:
                        if y["result"].lower() == "pass":
                            if spf_alignment_mode.lower() == "s":
                                # SPF alignment mode is strict, so the from
                                # header has to match the domain exactly
                                if y["domain"].lower() == header_from.lower():
                                    results.append("aligned")
                                else:
                                    results.append("unaligned")
                            else:
                                # SPF alignment is relaxed, so the header and
                                # the domain just need to come from the same
                                # base domain
                                domain = y["domain"]
                                base_domain = self.__psl.get_public_suffix(domain)
                                if base_domain is None:
                                    logging.warning(
                                        "Unable to determine public suffix for domain %s",
                                        domain,
                                    )
                                    results.append("unaligned")
                                    continue

                                header_base_domain = self.__psl.get_public_suffix(
                                    header_from
                                )
                                if header_base_domain is None:
                                    logging.warning(
                                        "Unable to determine public suffix for header domain %s",
                                        header_from,
                                    )
                                    results.append("unaligned")
                                    continue

                                if base_domain.lower() == header_base_domain.lower():
                                    results.append("aligned")
                                else:
                                    results.append("unaligned")
                        else:
                            results.append("fail")
                    x["SPF Alignment Result"] = " ".join(results)
                else:
                    x["SPF Result"] = spf["result"]
                    x["SPF Domain"] = spf["domain"]
                    if x["SPF Result"].lower() == "pass":
                        if spf_and_alignment.lower() == "pass":
                            x["SPF Alignment Result"] = "aligned"
                        else:
                            x["SPF Alignment Result"] = "unaligned"
                    else:
                        x["SPF Alignment Result"] = "fail"

            return x

        records_to_save = []
        for domain in self.__mail_domains:
            for report in self.__dmarc_results[domain]:
                records = report["_source"]["record"]
                policy_published = report["_source"]["policy_published"]
                if isinstance(records, list):
                    failure_records = [
                        process_record(domain, x, policy_published)
                        for x in records
                        if ReportGenerator.is_failure(x)
                    ]
                    records_to_save.extend(failure_records)
                elif isinstance(records, dict):
                    if ReportGenerator.is_failure(records):
                        records_to_save.append(
                            process_record(domain, records, policy_published)
                        )

        records_to_save.sort(key=lambda x: x["Count"], reverse=True)

        fields = (
            "DMARC Domain",
            "Policy Applied",
            "Override Reason",
            "Count",
            "DKIM Alignment Result",
            "DKIM Result",
            "DKIM Domain",
            "SPF Alignment Result",
            "SPF Result",
            "SPF Domain",
            "Source IP",
            "PTR",
            "ASN",
        )
        with open(TRUSTYMAIL_DMARC_FAILURES_CSV_FILE, "w") as out_file:
            writer = csv.DictWriter(out_file, fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records_to_save)

    ###########################################################################
    #  Chart Generation
    ###########################################################################
    def __generate_charts(self):
        graphs.setup()
        self.__generate_dmarc_bar_chart()
        self.__generate_bod_1801_email_components_bar_chart()
        self.__generate_donut_charts()

    def __generate_dmarc_bar_chart(self):
        dmarc_bar = graphs.MyTrustyBar(
            percentage_list=[
                self.__valid_dmarc_percentage,
                self.__valid_dmarc_reject_percentage,
                self.__valid_dmarc_bod1801_rua_uri_percentage,
            ],
            label_list=[
                "Valid\nDMARC",
                "DMARC\nPolicy of Reject",
                "Reports DMARC\nto CISA",
            ],
            fill_color=graphs.DARK_BLUE,
        )
        dmarc_bar.plot(filename="dmarc-compliance")

    def __generate_bod_1801_email_components_bar_chart(self):
        bod_1801_email_bar = graphs.MyTrustyBar(
            percentage_list=[
                self.__supports_starttls_percentage,
                self.__spf_coverered_percentage,
                self.__has_no_weak_crypto_percentage,
            ],
            label_list=["Supports\nSTARTTLS", "SPF\nCovered", "No SSLv2/v3,\n3DES,RC4"],
            fill_color=graphs.DARK_BLUE,
        )
        bod_1801_email_bar.plot(filename="bod-1801-email-components")

    def __generate_donut_charts(self):
        bod_1801_compliance_donut = graphs.MyDonutPie(
            percentage_full=round(self.__bod_1801_compliant_percentage),
            label="BOD 18-01\nCompliant\n(Email)",
            fill_color=graphs.DARK_BLUE,
        )
        bod_1801_compliance_donut.plot(filename="bod-18-01-compliance")

    ###########################################################################
    # Final Document Generation and Assembly
    ###########################################################################
    def __generate_mustache_json(self, filename):
        result = {"report_doc": self.__report_doc}
        # NOT CURRENTLY USED?
        result["ineligible_domains"] = self.__ineligible_domains
        result["domain_count"] = int(self.__domain_count)
        result["subdomain_count"] = int(self.__subdomain_count)
        result["base_domain_count"] = int(self.__base_domain_count)
        result["eligible_domains_count"] = self.__eligible_domains_count
        result["eligible_subdomains_count"] = self.__eligible_subdomains_count
        result["all_eligible_domains_count"] = self.__all_eligible_domains_count
        result["title_date_tex"] = self.__generated_time.strftime("{%d}{%m}{%Y}")
        result["agency"] = self.__agency
        result["agency_id"] = self.__agency_id
        result["spf_covered_count"] = self.__spf_covered_count
        result["spf_coverered_percentage"] = self.__spf_coverered_percentage
        result["has_no_weak_crypto_count"] = self.__has_no_weak_crypto_count
        result["has_no_weak_crypto_percentage"] = self.__has_no_weak_crypto_percentage
        result["valid_dmarc_count"] = self.__valid_dmarc_count
        result["valid_dmarc_percentage"] = self.__valid_dmarc_percentage
        result["valid_dmarc_reject_count"] = self.__valid_dmarc_policy_of_reject_count
        result["valid_dmarc_reject_percentage"] = self.__valid_dmarc_reject_percentage
        result[
            "valid_dmarc_bod1801_rua_uri_count"
        ] = self.__valid_dmarc_bod1801_rua_uri_count
        result[
            "valid_dmarc_bod1801_rua_uri_percentage"
        ] = self.__valid_dmarc_bod1801_rua_uri_percentage
        result["domain_supports_smtp_count"] = self.__domain_supports_smtp_count
        result[
            "base_domain_supports_smtp_count"
        ] = self.__base_domain_supports_smtp_count
        result["subdomain_supports_smtp_count"] = (
            self.__domain_supports_smtp_count - self.__base_domain_supports_smtp_count
        )
        result[
            "base_domain_plus_smtp_subdomain_count"
        ] = self.__base_domain_plus_smtp_subdomain_count
        result["supports_starttls_count"] = self.__supports_starttls_count
        result["supports_starttls_percentage"] = self.__supports_starttls_percentage
        result["bod_1801_compliant_count"] = self.__bod_1801_compliant_count
        result["bod_1801_compliant_percentage"] = self.__bod_1801_compliant_percentage

        self.__latex_escape_structure(result["report_doc"])

        with open(filename, "w") as out:
            out.write(json.dumps(result))

    def __generate_latex(self, mustache_file, json_file, latex_file):
        with codecs.open(mustache_file, "r", encoding="utf-8") as template, codecs.open(
            json_file, "r", encoding="utf-8"
        ) as data_file, codecs.open(latex_file, "w", encoding="utf-8") as output:
            output.write(chevron.render(template, json.load(data_file)))

    def __generate_final_pdf(self):
        xelatex = ["/usr/bin/xelatex", REPORT_TEX]
        # Bandit frowns upon the use of subprocess, but we need it
        # here.  Hence the nosec.
        subprocess.run(xelatex)  # nosec B603
        subprocess.run(xelatex)  # nosec B603


def main():
    """Create Trustworthy Email Agency Report PDF."""
    args = docopt(__doc__, version="v0.0.1")

    # Set up logging
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s", level=logging.INFO
    )

    db = db_from_config(DB_CONFIG_FILE)

    print("Generating Trustymail Report...")
    # TODO: Use agency ID instead of full agency name.  See issue #46
    # for more details.
    generator = ReportGenerator(db, args['"AGENCY"'], debug=args["--debug"])
    generator.generate_trustymail_report()
    print("Done")
    sys.exit(0)

    # import IPython; IPython.embed()
    # sys.exit(0)


if __name__ == "__main__":
    main()
