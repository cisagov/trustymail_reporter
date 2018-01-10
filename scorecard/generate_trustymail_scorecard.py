#!/usr/bin/env python3

'''Create Trustworthy Email Scorecard PDF.

Usage:
  trustymail-scorecard --generate-empty-scorecard-json
  trustymail-scorecard [options] AGENCIES_CSV_FILE
  trustymail-scorecard (-h | --help)
  trustymail-scorecard --version

Options:
  -a --anonymize                 Make a sample anonymous scorecard.  ** NOT IMPLEMENTED YET **
  -d --debug                     Keep intermediate files for debugging.
  -f --final                     Remove draft watermark.
  -h --help                      Show this screen.
  -n --nolog                     Do not log that this report was created. ** NOT IMPLEMENTED YET **
  -s SECTION --section=SECTION   Configuration section to use. ** NOT IMPLEMENTED YET **
  --version                      Show version.
'''

# standard python libraries
import sys
import os
import copy
from datetime import datetime, timedelta
from dateutil import parser, tz
import time
import json
import codecs
import tempfile
import shutil
import subprocess
import re
import csv
import random
import yaml

# third-party libraries (install with pip)
import pystache
from bson import ObjectId, json_util
from docopt import docopt
from pymongo import MongoClient

# intra-project modules
import graphs

# constants
DB_CONFIG_FILE = '/run/secrets/trustymail_read_creds.yml'
# SCORING_ENGINE_VERSION = '1.0'    # Not implemented
# TODO Pull CFO_ACT_ORGS from CyHy (db.RequestDoc.find_one({'_id':'FED_CFO_ACT'})['children'])
CFO_ACT_ORGS = ['DHS','DOC','DOD','DOE','DOI','DOJ','DOL','DOS','DOT','ED','EPA','GSA','HHS','HUD','NASA','NRC','NSF','OPM','SBA','SSA','Treasury','USAID','USDA','VA']

TRUSTYMAIL_SCORECARD_DETAILS_CSV_FILE = 'trustworthy_email_scorecard.csv'
MUSTACHE_FILE = 'trustymail_scorecard.mustache'
SCORECARD_JSON = 'trustymail_scorecard.json'
SCORECARD_PDF = 'trustymail_scorecard.pdf'
SCORECARD_TEX = 'trustymail_scorecard.tex'
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

class ScorecardGenerator(object):
    def __init__(self, db, agencies_csv_file, debug=False, final=False, log_scorecard=True, anonymize=False):
        self.__db = db
        self.__agencies_csv_file = agencies_csv_file
        self.__debug = debug
        self.__draft = not final
        self.__generated_time = datetime.now(tz.tzutc())
        self.__results = dict() # reusable query results
        self.__cyhy_agencies = list()
        self.__scores = list()
        self.__cfo_orgs_dmarc_reject_all = list()
        self.__cfo_orgs_dmarc_reject_some = list()
        self.__cfo_orgs_dmarc_reject_none = list()
        self.__all_orgs_dmarc_reject_all = list()
        self.__all_orgs_dmarc_reject_some = list()
        self.__all_orgs_dmarc_reject_none = list()
        #TODO Implement historical trending via previous_scorecard_data or via DB?
        #self.__previous_scorecard_data = json.load(codecs.open(previous_scorecard_json_file,'r', encoding='utf-8'))
        self.__scorecard_oid = ObjectId()
        self.__log_scorecard_to_db = log_scorecard
        self.__anonymize = anonymize

    def __run_queries(self):
        # TODO Use include/noncyhy.csv to determine non-CyHy orgs, rather than method below
        # TODO (longer term) Check CyHy DB to determine CyHy orgs and get rid of reporting/include/noncyhy.csv
        # Build list of CyHy agencies, based on agencies in AGENCIES_CSV_FILE where agency long name != agency acronym
        for row in csv.reader(open(self.__agencies_csv_file)):
            if row[0] != row[1]:    #row[0] = agency long name      row[1] = agency acronym
                self.__cyhy_agencies.append(row[1])

        self.__scores = list(self.__db.trustymail.aggregate([
                    {'$match': {'latest':True,
                                'agency.id': {'$in':self.__cyhy_agencies}}},
                    {'$group': {'_id': '$agency.id',
                                'agency_name': {'$first': '$agency.name'},
                                'domain_count': {'$sum': 1},
                                'live_domain_count': {'$sum': {'$cond': [ {'$eq': ['$live', True]},1,0 ] }},
                                'live_valid_spf_count': {'$sum': {'$cond': [ {'$and': [{'$eq': ['$live', True]}, {'$eq': ['$valid_spf', True]}] },1,0] }},
                                'live_valid_dmarc_count': {'$sum': {'$cond': [ {'$and': [{'$eq': ['$live', True]}, {'$eq': ['$valid_dmarc', True]}] },1,0] }},
                                'live_dmarc_reject_count': {'$sum': {'$cond': [ {'$and': [{'$eq': ['$live', True]}, {'$eq': ['$dmarc_policy', 'reject']}] },1,0] }}}},
                    {'$sort':{'_id':1}}
                    ]))

        summary_metrics = list(self.__db.trustymail.aggregate([
                {'$match': {'latest':True,
                            'agency.id': {'$in':self.__cyhy_agencies}}},
                {'$group': {
                  '_id': 'summary_metrics',
                  'domain_count': {'$sum': 1},
                  'live_domain_count': {'$sum': {'$cond': [{'$eq': ['$live', True] },1,0] }},
                  'live_valid_spf_count': {'$sum': {'$cond': [ {'$and': [{'$eq': ['$live', True]}, {'$eq': ['$valid_spf', True]}] },1,0] }},
                  'live_valid_dmarc_count': {'$sum': {'$cond': [ {'$and': [{'$eq': ['$live', True]}, {'$eq': ['$valid_dmarc', True]}] },1,0] }},
                  'live_dmarc_reject_count': {'$sum': {'$cond': [ {'$and': [{'$eq': ['$live', True]}, {'$eq': ['$dmarc_policy', 'reject']}] },1,0] }}
                  }}]))[0]

        # store summary metrics for later
        for metric in ('domain_count', 'live_domain_count', 'live_valid_spf_count', 'live_valid_dmarc_count', 'live_dmarc_reject_count'):
            self.__results[metric] = summary_metrics[metric]

        # store integer versions of summary percentages for later
        for metric in ('live_valid_spf', 'live_valid_dmarc', 'live_dmarc_reject'):
            self.__results[metric + '_pct_int'] = round(self.__results[metric + '_count'] / self.__results['live_domain_count'] * 100)

    def __calculate_scores(self):
        # Build dictionary of scores
        score_dict = dict()
        for org_score in self.__scores:
            org_score['cfo_act_org'] = org_score['_id'] in CFO_ACT_ORGS
            score_dict[org_score['_id']] = org_score

        # Check each CyHy agency and determine which DMARC reject bucket it belongs in (None, Some, All)
        for cyhy_agency in self.__cyhy_agencies:
            if score_dict.get(cyhy_agency):
                current_score = score_dict[cyhy_agency]
                if current_score['live_dmarc_reject_count'] == 0:
                    self.__all_orgs_dmarc_reject_none.append({'org_id':cyhy_agency})
                    if cyhy_agency in CFO_ACT_ORGS:
                        self.__cfo_orgs_dmarc_reject_none.append({'org_id':cyhy_agency})
                elif current_score['live_dmarc_reject_count'] == current_score['live_domain_count']:
                    self.__all_orgs_dmarc_reject_all.append({'org_id':cyhy_agency})
                    if cyhy_agency in CFO_ACT_ORGS:
                        self.__cfo_orgs_dmarc_reject_all.append({'org_id':cyhy_agency})
                else:
                    self.__all_orgs_dmarc_reject_some.append({'org_id':cyhy_agency})
                    if cyhy_agency in CFO_ACT_ORGS:
                        self.__cfo_orgs_dmarc_reject_some.append({'org_id':cyhy_agency})

                # Calculate percentages for results
                if current_score['live_domain_count'] == 0:
                    current_score['live_valid_spf_pct'] = current_score['live_valid_dmarc_pct'] = current_score['live_dmarc_reject_pct'] = 0.0
                    current_score['live_valid_spf_pct_str'] = current_score['live_valid_dmarc_pct_str'] = current_score['live_dmarc_reject_pct_str'] = '0.00%'
                else:
                    current_score['live_valid_spf_pct'] = current_score['live_valid_spf_count'] / current_score['live_domain_count']
                    current_score['live_valid_spf_pct_str'] = '{0:.2%}'.format(current_score['live_valid_spf_pct'])
                    current_score['live_valid_dmarc_pct'] = current_score['live_valid_dmarc_count'] / current_score['live_domain_count']
                    current_score['live_valid_dmarc_pct_str'] = '{0:.2%}'.format(current_score['live_valid_dmarc_pct'])
                    current_score['live_dmarc_reject_pct'] = current_score['live_dmarc_reject_count'] / current_score['live_domain_count']
                    current_score['live_dmarc_reject_pct_str'] = '{0:.2%}'.format(current_score['live_dmarc_reject_pct'])

                # Check for perfect scores in each category
                current_score['all_live_spf_valid'] = current_score['all_live_dmarc_valid'] = current_score['all_live_dmarc_reject'] = False
                if current_score['live_valid_spf_pct'] == 1.0:
                    current_score['all_live_spf_valid'] = True
                if current_score['live_valid_dmarc_pct'] == 1.0:
                    current_score['all_live_dmarc_valid'] = True
                if current_score['live_dmarc_reject_pct'] == 1.0:
                    current_score['all_live_dmarc_reject'] = True
            else:
                # We have no scan summary info for this agency...
                pass
                # TODO Decide how to handle these...
                # Option 1: Put them in the "None" buckets?
                # self.__all_orgs_dmarc_reject_none.append(cyhy_agency)
                # if cyhy_agency in CFO_ACT_ORGS:
                #     self.__cfo_orgs_dmarc_reject_none.append(cyhy_agency)
                # Option 2: Put them in different buckets?  e.g. all_orgs_no_known_domains and cfo_orgs_no_known_domains

        # Recreate self.__scores list (a.k.a. scan summary for each cyhy agency) with updated score data
        self.__scores = list()
        for agency in score_dict.keys():
            self.__scores.append(score_dict[agency])

        # Sort scores, first by _id (alphabetical), then by dmarc_reject_pct (descending)
        self.__scores = sorted(self.__scores, key=lambda x:x.get('_id'), reverse=False)
        self.__scores = sorted(self.__scores, key=lambda x:x.get('live_dmarc_reject_pct'), reverse=True)

        #     self.__results[total_id]['open_criticals_delta_since_last_scorecard'] = (self.__results[total_id]['open_criticals'] - self.__results[total_id]['open_criticals_on_previous_scorecard'])
        #     self.__results[total_id]['open_highs_delta_since_last_scorecard'] = (self.__results[total_id]['open_highs'] - self.__results[total_id]['open_highs_on_previous_scorecard'])

    def __make_fake_agency(self, real_agencies, real_acronyms, fake_agencies, fake_acronyms):
        FIRST = ['American', 'Atlantic', 'Central', 'Civil', 'Eastern American', 'Executive', 'Federal', 'Foreign', 'General', 'Government', 'Interstate', 'International', 'Midwest', 'National', 'North American', 'Overseas', 'Pacific', 'Regional', 'State', 'Western American', 'United States']
        SECOND = ['Agriculture', 'Art', 'Airport', 'Business', 'Commerce', 'Communication', 'Development', 'Economic', 'Education', 'Election', 'Energy', 'Environment', 'Finance', 'Gaming', 'Health', 'Housing', 'Infrastructure', 'Industrial', 'Insurance', 'Justice', 'Labor', 'Land', 'Maritime', 'Management', 'Natural Resources', 'Nuclear', 'Planning', 'Policy', 'Protection', 'Records', 'Resource', 'Regulatory', 'Retirement', 'Safety', 'Science', 'Security', 'Space', 'Trade', 'Transportation', 'Water']
        THIRD = ['Administration', 'Advisory Council', 'Agency', 'Authority', 'Bureau', 'Board', 'Center', 'Commission', 'Corporation', 'Corps', 'Council', 'Department', 'Enforcement', 'Foundation', 'Inquisition', 'Institute', 'Institutes', 'Laboratories', 'Office', 'Program', 'Regulatory Commission', 'Review Board', 'Service', 'Services', 'Trust']
        bad_acronyms = ['ASS']

        acceptableName = False
        while not acceptableName:
            fakeName = random.choice(FIRST) + ' ' + random.choice(SECOND) + ' ' + random.choice(THIRD)
            fakeAcronym = "".join(c[0] for c in fakeName.split())
            if (fakeName not in real_agencies + fake_agencies) and (fakeAcronym not in real_acronyms + fake_acronyms + bad_acronyms):
                acceptableName = True
        return fakeName, fakeAcronym

    def __anonymize_scorecard(self):
        realAgencyNames = []
        realAgencyAcronyms = []
        fakeAgencyNames = []
        fakeAgencyAcronyms = []

        for s in self.__scores:
            realAgencyNames.append(s['agency_name'])
            realAgencyAcronyms.append(s['_id'])

        for s in self.__scores:
            fakeAgencyName, fakeAgencyAcronym = self.__make_fake_agency(realAgencyNames, realAgencyAcronyms, fakeAgencyNames, fakeAgencyAcronyms)
            fakeAgencyNames.append(fakeAgencyName)
            fakeAgencyAcronyms.append(fakeAgencyAcronym)
            for score_list in (self.__cfo_orgs_dmarc_reject_all, self.__cfo_orgs_dmarc_reject_some, self.__cfo_orgs_dmarc_reject_none, self.__all_orgs_dmarc_reject_all, self.__all_orgs_dmarc_reject_some, self.__all_orgs_dmarc_reject_none):
                for score in score_list:
                    if score['org_id'] == s['_id']:
                        score['org_id'] = fakeAgencyAcronym
                        break
            s['_id'] = fakeAgencyAcronym
            s['agency_name'] = fakeAgencyName

    def generate_trustymail_scorecard(self):
        print(' running DB queries')
        # access database and cache results
        self.__run_queries()

        print(' parsing data')
        # calculate each org's score details from the query results
        self.__calculate_scores()

        # anonymize data if requested
        if self.__anonymize:
            self.__anonymize_scorecard()
            self.__log_scorecard_to_db = False  # Don't log creation of anonymous scorecards to the DB
            self.__results['scorecard_name'] = 'SAMPLE'
            self.__results['scorecard_subset_name'] = 'Subset XYZ'
        else:
            self.__results['scorecard_name'] = 'Federal'
            self.__results['scorecard_subset_name'] = 'CFO Act'

        # create a working directory
        original_working_dir = os.getcwd()
        if self.__debug:
            temp_working_dir = tempfile.mkdtemp(dir=original_working_dir)
        else:
            temp_working_dir = tempfile.mkdtemp()
        os.chdir(temp_working_dir)

        # setup the working directory
        self.__setup_work_directory(temp_working_dir)

        print(' generating attachments')
        # generate attachments
        self.__generate_attachments()

        print(' generating charts')
        # generate chart PDFs
        self.__generate_charts()

        # generate json input to mustache
        self.__generate_mustache_json(SCORECARD_JSON)

        # generate latex json + mustache
        self.__generate_latex(MUSTACHE_FILE, SCORECARD_JSON, SCORECARD_TEX)

        print(' assembling PDF')
        # generate report figures + latex
        self.__generate_final_pdf()

        # revert working directory
        os.chdir(original_working_dir)

        # copy report (and json file - see TODO below) to original working directory
        # and delete working directory
        if not self.__debug:
            src_filename = os.path.join(temp_working_dir, SCORECARD_PDF)
            timestamp = self.__generated_time.isoformat().replace(':','').split('.')[0]
            dest_filename = self.__results['scorecard_name'] + '_Trustworthy_Email_Scorecard-%s.pdf' % (timestamp)
            shutil.move(src_filename, dest_filename)
            # TODO enable stuff below if we end up requiring a "previous_scorecard_data" json file
            # src_filename = os.path.join(temp_working_dir, SCORECARD_JSON)
            # timestamp = self.__generated_time.isoformat().replace(':','').split('.')[0]
            # dest_filename = 'trustworthy_email_scorecard_%s.json' % (timestamp)
            # shutil.move(src_filename, dest_filename)
            shutil.rmtree(temp_working_dir)

        if self.__log_scorecard_to_db:
            # add a doc to reports collection to log that this scorecard was generated
            self.__log_scorecard_report()

        return self.__results

    def __setup_work_directory(self, work_dir):
        me = os.path.realpath(__file__)
        my_dir = os.path.dirname(me)
        for n in [MUSTACHE_FILE]:
            file_src = os.path.join(my_dir, n)
            file_dst = os.path.join(work_dir, n)
            shutil.copyfile(file_src, file_dst)
        # copy static assets
        dir_src = os.path.join(my_dir, ASSETS_DIR_SRC)
        dir_dst = os.path.join(work_dir, ASSETS_DIR_DST)
        shutil.copytree(dir_src,dir_dst)

    ###############################################################################
    # Utilities
    ###############################################################################

    def __latex_escape(self, to_escape):
        return ''.join([LATEX_ESCAPE_MAP.get(i,i) for i in to_escape])

    def __latex_escape_structure(self, data):
        '''assumes that all sequences contain dicts'''
        if isinstance(data, dict):
            for k,v in list(data.items()):
                if k.endswith('_tex'): # skip special tex values
                    continue
                if isinstance(v, str):
                    data[k] = self.__latex_escape(v)
                else:
                    self.__latex_escape_structure(v)
        elif isinstance(data, (list, tuple)):
            for i in data:
                self.__latex_escape_structure(i)

    def led(self, data):
        self.__latex_escape_dict(data)

    ###############################################################################
    #  Attachment Generation
    ###############################################################################
    def __generate_attachments(self):
        self.__generate_trustymail_attachment()

    def __generate_trustymail_attachment(self):
        header_fields = ('acronym', 'name', 'cfo_act_agency', 'live_domains', 'base_domains', 'valid_spf_live_domains', 'valid_spf_live_domains_percentage', 'valid_dmarc_live_domains', 'valid_dmarc_live_domains_percentage', 'dmarc_reject_live_domains', 'dmarc_reject_live_domains_percentage')
        data_fields = ('_id', 'agency_name', 'cfo_act_org', 'live_domain_count', 'domain_count', 'live_valid_spf_count', 'live_valid_spf_pct', 'live_valid_dmarc_count', 'live_valid_dmarc_pct', 'live_dmarc_reject_count', 'live_dmarc_reject_pct')
        with open(TRUSTYMAIL_SCORECARD_DETAILS_CSV_FILE, 'w') as out_file:
            header_writer = csv.DictWriter(out_file, header_fields, extrasaction='ignore')
            data_writer = csv.DictWriter(out_file, data_fields, extrasaction='ignore')
            header_writer.writeheader()
            for score in self.__scores:
                data_writer.writerow(score)

    ###############################################################################
    # Chart PDF Generation
    ###############################################################################
    def __figure_valid_spf(self):
        donut = graphs.MyDonutPie(percentage_full=self.__results['live_valid_spf_pct_int'], label='have SPF', fill_color=graphs.GREY_MID)
        donut.plot(filename='figure_valid_spf')

    def __figure_valid_dmarc(self):
        donut = graphs.MyDonutPie(percentage_full=self.__results['live_valid_dmarc_pct_int'], label='have DMARC', fill_color=graphs.GREY_MID)
        donut.plot(filename='figure_valid_dmarc')

    def __figure_dmarc_reject(self):
        donut = graphs.MyDonutPie(percentage_full=self.__results['live_dmarc_reject_pct_int'], label='have DMARC\np=reject', fill_color=graphs.DARK_BLUE)
        donut.plot(filename='figure_dmarc_reject')

    def __generate_charts(self):
        if self.__debug:
            output = sys.stdout
        else:
            output = open(os.devnull, 'w')

        graphs.setup()
        self.__figure_valid_spf()
        self.__figure_valid_dmarc()
        self.__figure_dmarc_reject()

    ###############################################################################
    # Final Document Generation and Assembly
    ###############################################################################
    def __generate_mustache_json(self, filename):
        result = {'scorecard_name':self.__results['scorecard_name']}
        result['scorecard_subset_name'] = self.__results['scorecard_subset_name']
        result['generated_time'] = self.__generated_time
        result['title_date_tex'] = self.__generated_time.strftime('{%d}{%m}{%Y}')
        result['draft'] = self.__draft
        result['overall_domain_count'] = self.__results['domain_count']
        result['overall_live_domain_count'] = self.__results['live_domain_count']
        result['overall_live_valid_spf_count'] = self.__results['live_valid_spf_count']
        result['overall_live_valid_spf_pct_int'] = self.__results['live_valid_spf_pct_int']
        result['overall_live_valid_dmarc_count'] = self.__results['live_valid_dmarc_count']
        result['overall_live_valid_dmarc_pct_int'] = self.__results['live_valid_dmarc_pct_int']
        result['overall_live_dmarc_reject_count'] = self.__results['live_dmarc_reject_count']
        result['overall_live_dmarc_reject_pct_int'] = self.__results['live_dmarc_reject_pct_int']
        result['cfo_orgs_dmarc_reject_all'] = sorted(self.__cfo_orgs_dmarc_reject_all, key=lambda x:x.get('org_id'))
        result['cfo_orgs_dmarc_reject_some'] = sorted(self.__cfo_orgs_dmarc_reject_some, key=lambda x:x.get('org_id'))
        result['cfo_orgs_dmarc_reject_none'] = sorted(self.__cfo_orgs_dmarc_reject_none, key=lambda x:x.get('org_id'))
        result['all_orgs_dmarc_reject_all'] = sorted(self.__all_orgs_dmarc_reject_all, key=lambda x:x.get('org_id'))
        result['all_orgs_dmarc_reject_some'] = sorted(self.__all_orgs_dmarc_reject_some, key=lambda x:x.get('org_id'))
        result['all_orgs_dmarc_reject_none'] = sorted(self.__all_orgs_dmarc_reject_none, key=lambda x:x.get('org_id'))
        result['scores'] = self.__scores    # scores were sorted earlier, no need to sort here

        # result['previous_scorecard_date_tex'] = parser.parse(self.__previous_scorecard_data['generated_time']).strftime('{%d}{%m}{%Y}')
        #
        # if self.__log_scorecard_to_db:
        #     result['scorecard_oid'] = str(self.__scorecard_oid)
        # else:
        #     result['scorecard_oid'] = None      # If scorecard_oid is None, it will not be included in the PDF metadata

        # escape latex special characters in key lists
        for x in ['scores', 'cfo_orgs_dmarc_reject_all', 'cfo_orgs_dmarc_reject_some', 'cfo_orgs_dmarc_reject_none', 'all_orgs_dmarc_reject_all', 'all_orgs_dmarc_reject_some', 'all_orgs_dmarc_reject_none']:
            self.__latex_escape_structure(result[x])

        with open(filename, 'w') as out:
            out.write(json.dumps(result, default=json_util.default))

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

        return_code = subprocess.call(['xelatex', SCORECARD_TEX], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'xelatex pass 1 of 2 return code was %s' % return_code

        return_code = subprocess.call(['xelatex', SCORECARD_TEX], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'xelatex pass 2 of 2 return code was %s' % return_code

    def __log_scorecard_report(self):
        pass    # Not currently implemented
        #TODO Set this up when we integrate with a non-temporary DB
        # report = self.__db.ReportDoc()
        # report['_id'] = self.__scorecard_oid
        # report['generated_time'] = self.__generated_time
        # report['report_types'] = [REPORT_TYPE.CYBEX]
        # report.save()

def generate_empty_scorecard_json():
    #TODO Update this when things settle down
    current_time = datetime.now(tz.tzutc())
    result = {'scores':[]}
    result['title_date_tex'] = current_time.strftime('{%d}{%m}{%Y}')
    result['draft'] = True
    result['generated_time'] = current_time
    result['previous_scorecard_date_tex'] = current_time.strftime('{%d}{%m}{%Y}')
    result['scorecard_oid'] = None
    result['scorecard_name'] = ""
    result['scorecard_subset_name'] = ""
    result['overall_domain_count'] = 0
    result['overall_live_domain_count'] = 0
    result['overall_live_valid_spf_count'] = 0
    result['overall_live_valid_dmarc_count'] = 0
    result['overall_live_dmarc_reject_count'] = 0
    return json.dumps(result, default=json_util.default)

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

    if args['--generate-empty-scorecard-json']:
        print(generate_empty_scorecard_json())
        sys.exit(0)

    db = db_from_config(DB_CONFIG_FILE)

    print('Generating Trustworthy Email Scorecard...')
    generator = ScorecardGenerator(db, agencies_csv_file=args['AGENCIES_CSV_FILE'], debug=args['--debug'], final=args['--final'], log_scorecard=not args['--nolog'], anonymize=args['--anonymize'])
    results = generator.generate_trustymail_scorecard()
    print('Done')
    sys.exit(0)

    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    # sys.exit(0)

if __name__=='__main__':
    main()
