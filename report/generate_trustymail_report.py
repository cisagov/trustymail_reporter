#!/usr/bin/env python3

'''Create Trustworthy Email Agency Report PDF.

Usage:
  generate_trustymail_report [options] "AGENCY"
  generate_trustymail_report (-h | --help)
  generate_trustymail_report --version

Options:
  -d --debug                     Keep intermediate files for debugging.
  -h --help                      Show this screen.
  --version                      Show version.
'''
# standard python libraries
import codecs
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime

# third-party libraries (install with pip)
import pystache
from bson import ObjectId
from docopt import docopt
from pymongo import MongoClient
import yaml

# intra-project modules
import graphs

# constants
DB_CONFIG_FILE = '/run/secrets/trustymail_read_creds.yml'
TRUSTYMAIL_RESULTS_CSV_FILE = 'trustymail_results.csv'
MUSTACHE_FILE = 'trustymail_report.mustache'
REPORT_JSON = 'trustymail_report.json'
REPORT_PDF = 'trustymail_report.pdf'
REPORT_TEX = 'trustymail_report.tex'
ASSETS_DIR_SRC = '../assets'
ASSETS_DIR_DST = 'assets'
LATEX_ESCAPE_MAP = {
    '$':'\\$',
    '%':'\\%',
    '&':'\\&',
    '#':'\\#',
    '_':'\\_',
    '{':'\\{',
    '}':'\\}',
    '[':'{[}',
    ']':'{]}',
    "'":"{'}",
    '\\':'\\textbackslash{}',
    '~':'\\textasciitilde{}',
    '<':'\\textless{}',
    '>':'\\textgreater{}',
    '^':'\\textasciicircum{}',
    '`':'{}`',
    '\n': '\\newline{}',
}

class ReportGenerator(object):
    #initiate variables
    def __init__(self, db, agency, debug=False):
        self.__db = db
        self.__agency = agency
        self.__agency_id = None
        self.__debug = debug
        self.__generated_time = datetime.utcnow()
        self.__results = dict() # reusable query results
        self.__requests = None
        self.__report_doc = {'scores':[]}
        self.__all_domains = []
        self.__base_domains = []
        self.__eligible_domains_count = 0     # responsive second-level/base-domains
        self.__eligible_subdomains_count = 0  # responsive subdomains
        self.__all_eligible_domains_count = 0 # responsive base+subs
        self.__ineligible_domains = []        # NOT CURRENTLY USED
        self.__domain_count = 0
        self.__base_domain_count = 0
        self.__subdomain_count = 0
        self.__mx_record_count = 0
        # self.__domain_spf_record_count = 0
        self.__valid_spf_count = 0
        self.__dmarc_not_covered_count = 0
        # self.__domain_dmarc_record_count = 0
        self.__domain_valid_dmarc_count = 0
        self.__dmarc_reject_count = 0
        # self.__base_domain_dmarc_reject_count = 0
        self.__base_domain_supports_smtp_count = 0
        self.__domain_supports_smtp_count = 0
        self.__base_domain_plus_smtp_subdomain_count = 0
        self.__supports_starttls_count = 0
        self.__bod_1801_compliant_count = 0
        #self.__report_oid = ObjectId()     # For future use

        # Get list of all domains from the database
        all_domains_cursor = self.__db.trustymail.find({'latest':True, 'agency.name': agency})
        self.__domain_count = all_domains_cursor.count()

        for domain_doc in all_domains_cursor:
            self.__all_domains.append(domain_doc)
            if domain_doc['base_domain'] == domain_doc['domain']:
                domain_doc['subdomains'] = list(self.__db.trustymail.find({'latest':True, 'base_domain': domain_doc['base_domain'], 'domain': {'$ne': domain_doc['domain']}}).sort([('domain', 1)]))
                self.__subdomain_count += len(domain_doc['subdomains'])
                self.__base_domains.append(domain_doc)
            self.__agency_id = domain_doc['agency']['id']

        # Get list of all second-level domains an agency owns
        second_cursor = self.__db.trustymail.find({'latest':True, 'agency.name': agency}).distinct('base_domain')
        for document in second_cursor:
            self.__base_domain_count += 1

    def __score_domain(self, domain):
        score = {'subdomain_scores': list(), 'live': domain['live'], 'has_live_smtp_subdomains': False}
        if domain['live']:
            # Check if the current domain is the base domian.
            if domain['domain'] == domain['base_domain']:
                self.__eligible_domains_count += 1
                self.__all_eligible_domains_count += 1

                # Count the base domains that are p=reject
                # if domain['dmarc_policy'] == "reject":
                #     self.__base_domain_dmarc_reject_count += 1

                # Count the base domains that support SMTP
                if domain['domain_supports_smtp']:
                    self.__base_domain_supports_smtp_count += 1
            else:
                self.__eligible_subdomains_count += 1
                self.__all_eligible_domains_count += 1

            score['domain'] = domain['domain']
            score['dmarc_policy'] = domain['dmarc_policy']
            score['dmarc_policy_reject'] = False
            if domain['dmarc_policy'] == "reject":
                self.__dmarc_reject_count += 1
                score['dmarc_policy_reject'] = True

            if domain['dmarc_policy'] == "":
                self.__dmarc_not_covered_count += 1

            # If the server has any valid MX record it is considered as sending mail
            score['mx_record'] = domain['mx_record']
            if domain['mx_record']:
                self.__mx_record_count += 1

            # Probably not used in the report for now, but go ahead and include it.
            if domain['mail_servers'] is None or len(domain['mail_servers']) == 0:
                score['mail_servers'] = "None"
            else:
                score['mail_servers'] = domain['mail_servers']

            # Does the given domain have a SPF record
            score['spf_record'] = domain['spf_record']

            # Is the record syntactically and logically correct
            score['valid_spf'] = domain['valid_spf']

            # Placeholder for future use in reports.
            if domain['spf_results'] is None or len(domain['spf_results']) == 0:
                score['spf_results'] = "None"
            else:
                score['spf_results'] = domain['spf_results']

            # Does the given domain have a DMARC record
            score['dmarc_record'] = domain['dmarc_record']
            # if domain['dmarc_record']:
            #     self.__domain_dmarc_record_count += 1

            # Is the DMARC record syntactically and logically correct
            score['valid_dmarc'] = domain['valid_dmarc']
            if domain['valid_dmarc']:
                self.__domain_valid_dmarc_count += 1

            # Placeholder for future use in reports.
            if domain['dmarc_results'] is None or len(domain['dmarc_results']) == 0:
                score['dmarc_results'] = "None"
            else:
                score['dmarc_results'] = domain['dmarc_results']

            # Does the domain support SMTP?
            score['domain_supports_smtp'] = domain['domain_supports_smtp']
            score['smtp_servers'] = list()
            if domain['domain_supports_smtp']:
                score['smtp_servers'] = [s.strip() for s in domain['domain_supports_smtp_results'].split(',')]
                self.__domain_supports_smtp_count += 1

            # Does the domain support STARTTLS?
            score['domain_supports_starttls'] = domain['domain_supports_starttls']
            if not domain['domain_supports_starttls']:
                starttls_servers = [s.strip() for s in domain['domain_supports_starttls_results'].split(',')]
                score['smtp_servers_without_starttls'] = list(set(score['smtp_servers']) - set(starttls_servers))

            score['bod_1801_compliant'] = False
            # For SPF, STARTTLS and BOD 18-01 Compliance, we only count base domains and subdomains that support SMTP
            if domain['domain'] == domain['base_domain'] or (domain['domain'] != domain['base_domain'] and domain['domain_supports_smtp']):
                self.__base_domain_plus_smtp_subdomain_count += 1
                if domain['valid_spf']:
                    self.__valid_spf_count += 1
                if ((domain['domain_supports_smtp'] and domain['domain_supports_starttls']) or not domain['domain_supports_smtp']):
                    self.__supports_starttls_count += 1   # If you don't support SMTP, you still get credit here for supporting STARTTLS
                    # Is the domain compliant with BOD 18-01?
                    #  * Uses STARTTLS on all SMTP servers OR does not support SMTP
                    #  * Has valid SPF Record
                    #  * Has valid DMARC record with p=reject (and rua=mailto:reports@dmarc.cyber.dhs.gov if available in data)
                    #TODO add check for rua=mailto:reports@dmarc.cyber.dhs.gov when available in trustymail data
                    if domain['valid_spf'] and domain['dmarc_policy'] == "reject":
                        score['bod_1801_compliant'] = True
                        self.__bod_1801_compliant_count += 1

            if domain.get('subdomains'):    # if this domain has any subdomains
                for subdomain in domain['subdomains']:
                    subdomain_score = self.__score_domain(subdomain)
                    # if the subdomain has a dmarc record or the base domain doesn't have a dmarc record, add subdomain to the subdomain_scores list
                    if subdomain_score and (subdomain_score['dmarc_record'] or not domain['dmarc_record']):
                        score['subdomain_scores'].append(subdomain_score)   # add subdomain score to domain's list of subdomain_scores
            return score

        else:   # domain['live'] == "False"
            # Check if any subdomains of non-live domains support SMTP; if so, we want to include them in our results, per CYHY-554)
            if domain.get('subdomains'):    # if this domain has any subdomains
                for subdomain in domain['subdomains']:
                    if subdomain['domain_supports_smtp']:
                        score['has_live_smtp_subdomains'] = True
                        subdomain_score = self.__score_domain(subdomain)
                        # if the subdomain has a dmarc record, add subdomain to the subdomain_scores list
                        # no need to check if base domain doesn't have a dmarc_record because base domain is not live
                        if subdomain_score and subdomain_score['dmarc_record']:
                            score['subdomain_scores'].append(subdomain_score)   # add subdomain score to domain's list of subdomain_scores
            if score['has_live_smtp_subdomains']:
                return score
            else:
                # only include base domains in the ineligible count; otherwise lots of non-existent subs will show in the report
                if domain['domain'] == domain['base_domain']:
                    self.__ineligible_domains.append({'domain' : domain['domain']})     # NOT CURRENTLY USED?
                return None

    def __populate_report_doc(self):
        self.__all_domains.sort(key=lambda x:x['domain'])   # sort list of all domains
        self.__base_domains.sort(key=lambda x:x['domain'])   # sort list of base domains

        # Go through each base domain and score the attributes
        for domain in self.__base_domains:
            score  = self.__score_domain(domain)
            if score:
                self.__report_doc['scores'].append(score)    # Add domain's score to master list of scores

        if not self.__all_eligible_domains_count:
            #TODO Decide if we want to generate an empty report in this case
            print('ERROR: "{}" has no live domains - exiting without generating report!'.format(self.__agency))
            sys.exit(-1)

        self.__supports_starttls_percentage = round((((self.__supports_starttls_count)/float(self.__base_domain_plus_smtp_subdomain_count)) * 100), 1)
        # self.__has_spf_percentage = round((((self.__domain_spf_record_count)/float(self.__all_eligible_domains_count)) * 100), 1)
        self.__valid_spf_percentage = round((((self.__valid_spf_count)/float(self.__base_domain_plus_smtp_subdomain_count)) * 100), 1)
        # self.__has_dmarc_percentage = round((((self.__domain_dmarc_record_count)/float(self.__all_eligible_domains_count)) * 100), 1)
        self.__valid_dmarc_percentage = round((((self.__domain_valid_dmarc_count)/float(self.__all_eligible_domains_count)) * 100), 1)
        self.__dmarc_reject_percentage = round((((self.__dmarc_reject_count)/float(self.__all_eligible_domains_count)) * 100), 1)
        # self.__base_domain_dmarc_reject_percentage = round((((self.__base_domain_dmarc_reject_count)/float(self.__eligible_domains_count)) * 100), 1)
        self.__dmarc_coverage_percentage = round((((self.__all_eligible_domains_count - self.__dmarc_not_covered_count)/float(self.__all_eligible_domains_count)) * 100), 1)
        self.__bod_1801_compliant_percentage = round((((self.__bod_1801_compliant_count)/float(self.__base_domain_plus_smtp_subdomain_count)) * 100), 1)

        # print('Agency,Base Domains,Found Subdomains,Live,Valid SPF Record,Valid DMARC Record,Base Domain DMARC Reject,All Domains DMARC Reject Count,All Domains DMARC Reject Percentage)
        print(self.__agency_id, self.__agency, self.__base_domain_count, self.__subdomain_count, self.__all_eligible_domains_count, self.__valid_spf_count, self.__domain_valid_dmarc_count, self.__dmarc_reject_count, self.__dmarc_reject_percentage)

    def __latex_escape(self, to_escape):
        return ''.join([LATEX_ESCAPE_MAP.get(i,i) for i in to_escape])

    def __latex_escape_structure(self, data):
        '''assumes that all sequences contain dicts'''
        if isinstance(data, dict):
            for k,v in data.items():
                if k.endswith('_tex'): # skip special tex values
                    continue
                if isinstance(v, str):
                    data[k] = self.__latex_escape(v)
                else:
                    self.__latex_escape_structure(v)
        elif isinstance(data, (list, tuple)):
            for i in data:
                self.__latex_escape_structure(i)

    def generate_trustymail_report(self):
        print('\tparsing data')
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

        print('\tgenerating attachments')
        # generate attachments
        self.__generate_attachments()

        print('\tgenerating charts')
        # generate charts
        self.__generate_charts()

        # generate json input to mustache
        self.__generate_mustache_json(REPORT_JSON)

        # generate latex json + mustache
        self.__generate_latex(MUSTACHE_FILE, REPORT_JSON, REPORT_TEX)

        print('\tassembling PDF')
        # generate report figures + latex
        self.__generate_final_pdf()

        # revert working directory
        os.chdir(original_working_dir)

        # copy report to original working directory
        # and delete working directory
        if not self.__debug:
            src_filename = os.path.join(temp_working_dir, REPORT_PDF)
            datestamp = self.__generated_time.strftime('%Y-%m-%d')
            dest_filename = 'cyhy-{}-{}-tmail-report.pdf'.format(self.__agency_id, datestamp)
            shutil.move(src_filename, dest_filename)
            src_filename = os.path.join(temp_working_dir, REPORT_JSON)
        return self.__results

    def __setup_work_directory(self, work_dir):
        me = os.path.realpath(__file__)
        my_dir = os.path.dirname(me)
        for n in [MUSTACHE_FILE]:       # add other files as needed
            file_src = os.path.join(my_dir, n)
            file_dst = os.path.join(work_dir, n)
            shutil.copyfile(file_src, file_dst)
        # copy static assets
        dir_src = os.path.join(my_dir, ASSETS_DIR_SRC)
        dir_dst = os.path.join(work_dir, ASSETS_DIR_DST)
        shutil.copytree(dir_src,dir_dst)

    ###############################################################################
    #  Attachment Generation
    ###############################################################################
    def __generate_attachments(self):
        self.__generate_trustymail_attachment()

    def __generate_trustymail_attachment(self):
        header_fields = ('Domain', 'Base Domain', 'Live', 'MX Record', 'Mail Servers', 'Mail Server Ports Tested', 'Domain Supports SMTP', 'Domain Supports SMTP Results', 'Domain Supports STARTTLS', 'Domain Supports STARTTLS Results', 'SPF Record', 'Valid SPF', 'SPF Results', 'DMARC Record', 'Valid DMARC', 'DMARC Results', 'DMARC Record on Base Domain', 'Valid DMARC Record on Base Domain', 'DMARC Results on Base Domain', 'DMARC Policy', 'Syntax Errors', 'Debug Info')
        data_fields = ('domain', 'base_domain', 'live', 'mx_record', 'mail_servers', 'mail_server_ports_tested', 'domain_supports_smtp', 'domain_supports_smtp_results', 'domain_supports_starttls', 'domain_supports_starttls_results', 'spf_record', 'valid_spf', 'spf_results', 'dmarc_record', 'valid_dmarc', 'dmarc_results', 'dmarc_record_base_domain', 'valid_dmarc_base_domain', 'dmarc_results_base_domain', 'dmarc_policy', 'syntax_errors', 'debug_info')
        with open(TRUSTYMAIL_RESULTS_CSV_FILE, 'w') as out_file:
            header_writer = csv.DictWriter(out_file, header_fields, extrasaction='ignore')
            header_writer.writeheader()
            data_writer = csv.DictWriter(out_file, data_fields, extrasaction='ignore')
            for domain in self.__all_domains:
                data_writer.writerow(domain)

    ###############################################################################
    #  Chart Generation
    ###############################################################################
    def __generate_charts(self):
        graphs.setup()
        self.__generate_dmarc_bar_chart()
        self.__generate_donut_charts()

    def __generate_dmarc_bar_chart(self):
        dmarc_bar = graphs.MyTrustyBar(percentage_list=[self.__dmarc_coverage_percentage, self.__dmarc_reject_percentage],
                                          label_list=['Subject to DMARC', 'DMARC p=reject'], fill_color=graphs.DARK_BLUE)
        dmarc_bar.plot(filename='dmarc-compliance')

    def __generate_donut_charts(self):
        starttls_donut = graphs.MyDonutPie(percentage_full=self.__supports_starttls_percentage,
                                           label='Support\nSTARTTLS', fill_color=graphs.DARK_BLUE)
        starttls_donut.plot(filename='supports-starttls')

        spf_donut = graphs.MyDonutPie(percentage_full=self.__valid_spf_percentage,
                                      label='Valid\nSPF', fill_color=graphs.DARK_BLUE)
        spf_donut.plot(filename='valid-spf')

        bod_1801_compliance_donut = graphs.MyDonutPie(percentage_full=self.__bod_1801_compliant_percentage,
                                                      label='BOD 18-01\nCompliant', fill_color=graphs.DARK_BLUE)
        bod_1801_compliance_donut.plot(filename='bod-18-01-compliance')

    ###############################################################################
    # Final Document Generation and Assembly
    ###############################################################################
    def __generate_mustache_json(self, filename):
        result = {'report_doc':self.__report_doc}
        result['ineligible_domains'] = self.__ineligible_domains    # NOT CURRENTLY USED?
        result['domain_count'] = int(self.__domain_count)
        result['subdomain_count'] = int(self.__subdomain_count)
        result['base_domain_count'] = int(self.__base_domain_count)
        result['eligible_domains_count'] = self.__eligible_domains_count
        result['eligible_subdomains_count'] = self.__eligible_subdomains_count
        result['all_eligible_domains_count'] = self.__all_eligible_domains_count
        result['title_date_tex'] = self.__generated_time.strftime('{%d}{%m}{%Y}')
        result['agency'] = self.__agency
        result['agency_id'] = self.__agency_id
        # result['domain_spf_record_count'] = self.__domain_spf_record_count
        result['valid_spf_count'] = self.__valid_spf_count
        # result['domain_dmarc_record_count'] = self.__domain_dmarc_record_count
        result['domain_valid_dmarc_count'] = self.__domain_valid_dmarc_count
        # result['has_spf_percentage'] = self.__has_spf_percentage
        # result['has_dmarc_percentage'] = self.__has_dmarc_percentage
        result['valid_spf_percentage'] = self.__valid_spf_percentage
        result['valid_dmarc_percentage'] = self.__valid_dmarc_percentage
        result['dmarc_reject_percentage'] = self.__dmarc_reject_percentage
        result['dmarc_reject_count'] = self.__dmarc_reject_count
        # result['base_domain_dmarc_reject_percentage'] = self.__base_domain_dmarc_reject_percentage
        # result['base_domain_dmarc_reject_count'] = self.__base_domain_dmarc_reject_count
        result['dmarc_coverage_count'] = self.__all_eligible_domains_count - self.__dmarc_not_covered_count
        result['dmarc_coverage_percentage'] = self.__dmarc_coverage_percentage
        result['domain_supports_smtp_count'] = self.__domain_supports_smtp_count
        result['base_domain_supports_smtp_count'] = self.__base_domain_supports_smtp_count
        result['subdomain_supports_smtp_count'] = self.__domain_supports_smtp_count - self.__base_domain_supports_smtp_count
        result['base_domain_plus_smtp_subdomain_count'] = self.__base_domain_plus_smtp_subdomain_count
        result['supports_starttls_count'] = self.__supports_starttls_count
        result['supports_starttls_percentage'] = self.__supports_starttls_percentage
        result['bod_1801_compliant_count'] = self.__bod_1801_compliant_count
        result['bod_1801_compliant_percentage'] = self.__bod_1801_compliant_percentage

        self.__latex_escape_structure(result['report_doc'])

        with open(filename, 'w') as out:
            out.write(json.dumps(result))

    def __generate_latex(self, mustache_file, json_file, latex_file):
        renderer = pystache.Renderer()
        template = codecs.open(mustache_file,'r', encoding='utf-8').read()

        with codecs.open(json_file,'r', encoding='utf-8') as data_file:
            data = json.load(data_file)

        r = pystache.render(template, data)
        with codecs.open(latex_file,'w', encoding='utf-8') as output:
            output.write(r)

    def __generate_final_pdf(self):
        if self.__debug:
            output = sys.stdout
        else:
            output = open(os.devnull, 'w')

        return_code = subprocess.call(['xelatex', REPORT_TEX], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'xelatex pass 1 of 2 return code was %s' % return_code

        return_code = subprocess.call(['xelatex', REPORT_TEX], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'xelatex pass 2 of 2 return code was %s' % return_code

# connection to database
def db_from_config(config_filename):
    with open(config_filename, 'r') as stream:
        config = yaml.load(stream)

    try:
        db_uri = config['database']['uri']
        db_name = config['database']['name']
    except:
        print('Incorrect database config file format: {}'.format(config_filename))

    db_connection = MongoClient(host=db_uri, tz_aware=True)
    db = db_connection[db_name]
    return db

def main():
    args = docopt(__doc__, version='v0.0.1')
    db = db_from_config(DB_CONFIG_FILE)

    print('Generating Trustymail Report...')
    # TODO: Use agency ID instead of full agency name
    generator = ReportGenerator(db, args['"AGENCY"'], debug=args['--debug'])
    results = generator.generate_trustymail_report()
    print('Done')
    sys.exit(0)

    # import IPython; IPython.embed()
    # sys.exit(0)

if __name__=='__main__':
    main()
