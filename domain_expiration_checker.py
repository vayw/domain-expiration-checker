#!/usr/bin/env python3

from datetime import datetime
from subprocess import check_output, CalledProcessError
import re
import json
import os.path
import logging
import configparser
try:
    import boto3
    from whois import whois
except ImportError as err:
    if 'whois' in err.args[0]:
        print('No module python-whois, please install')
    else:
        print('{}, please install'.format(err.args[0]))
    exit(2)

WARNING = 15
CRITICAL = 5
FILTER=['.test', '.example', '.invalid', '.localhost']
DIR = os.path.dirname(os.path.realpath(__file__))
CACHEFILE = DIR + '/.expcache'
SETTINGSFILE = DIR + '/settings.ini'

def loadcache(cachef):
    cache = {'domain_expiration_dates': {},
            'updated': datetime.now().timestamp()}
    if os.path.isfile(cachef):
        with open(cachef, 'r') as cachefile:
            try:
                cache = json.load(cachefile)
            except:
                logging.warning('cache file is invalide!')
    return cache

def writecache(cachedict, cachef):
    with open(cachef, 'w') as cachefile:
        json.dump(cachedict, cachefile)

def syswhois(domainname):
    try:
        res = check_output(['whois', domainname])
        m = re.search('Expir.+ Date: ([0-9-TZ].+)\r', res.decode('utf8'))
        d = re.search('([0-9]{4}-[0-9]{2}-[0-9]{2})T.*', m.group(1))
        c = datetime.strptime(d.group(1), "%Y-%m-%d")
        return c
    except CalledProcessError:
        logging.warning('error using system whois')
        return 1
    except Exception as err:
        return 1

def getexpdate(domain):
    # lets ask whois service about expiration date
    try:
        wresp = whois(domain)
    except Exception as err:
        # if somehow domain is not found in whois
        if 'No match for' in str(err):
            return (1, domain)
    if wresp['expiration_date'] is None or wresp['status'] is None:
        # why not to give a chance for system utility
        logging.info('using system whois utility')
        exp_date = syswhois(domain)
        if exp_date == 1:
            return (1, domain)
    # for some reasons py-whois returns list of
    # expiration dates for some domains
    if type(wresp['expiration_date']) == list:
        exp_date = wresp['expiration_date'][-1]
    else:
        exp_date = wresp['expiration_date']
    return (0, exp_date)

def config():
    settings = configparser.ConfigParser()
    if not os.path.isfile(SETTINGSFILE):
        print('please, edit config file: ', SETTINGSFILE)
        createconfig(settings)
        exit(2)
    try:
        settings.read(SETTINGSFILE)
    except:
        print('error reading config file!')
        exit(1)
    try:
        WARNING = settings['MAIN']['WARNING']
        CRITICAL = settings['MAIN']['CRITICAL']
    except KeyError as err:
        logging.warning('using default value (%s) for %s', globals()[err.args[0]], err.args[0])
    except ValueError as err:
        logging.warning('using default value (%s) for %s', globals()[err.args[0]], err.args[0])
        logging.warning('got %s, but should be integer', type(settings['MAIN'][err.args[0]]))
    return settings

def createconfig(settings):
    settings['MAIN'] = {'WARNING': WARNING, 'CRITICAL': CRITICAL, 'METHOD': 'ROUTE53'}
    settings['ROUTE53'] = {'KEY': '', 'KEYID': ''}
    with open(SETTINGSFILE, 'w') as config:
        settings.write(config)

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    settings = config()
    KEYID = settings['ROUTE53']['KEYID']
    KEY = settings['ROUTE53']['KEY']
    whoiscache = loadcache(CACHEFILE)
    client = boto3.client('route53', aws_access_key_id=KEYID, aws_secret_access_key=KEY)

    resp = client.get_hosted_zone_count()
    zones_count = resp['HostedZoneCount']
    zonelist = []
    marker = ''
    logging.info('Gathering domain list...')
    while len(zonelist) != zones_count:
        if marker == '':
            resp = client.list_hosted_zones()
        else:
            resp = client.list_hosted_zones(Marker=marker)

        for zonename in resp['HostedZones']:
            domainname = zonename['Name'].rstrip('.')
            zonelist.append(domainname)

        if resp['IsTruncated'] == True:
            marker = resp['NextMarker']
    # check for invalid domain names
    for domainname in zonelist:
        filtered=False
        for fltr in FILTER:
            if domainname.endswith(fltr):
                filtered=True
                break
        if filtered:
            logging.info('%s is filtered!', domainname)
            zonelist.remove(domainname)

    experation_list = {}
    notfound = []
    now = datetime.now()
    for domain in zonelist:
        logging.info('processing: %s', domain)
        # lets check our cache for expiration date
        if domain in whoiscache['domain_expiration_dates']:
            logging.info('taking date from cache')
            exp_date = datetime.fromtimestamp(
                whoiscache['domain_expiration_dates'][domain]
                )
            delta = exp_date - now
            if delta.days < WARNING:
                exp_result = getexpdate(domain)
                if exp_result[0] == 0:
                    exp_date = exp_result[1]
                elif exp_result[0] == 1:
                    notfound.append(domain)
        else:
            logging.info('using whois service..')
            exp_result = getexpdate(domain)
            if exp_result[0] == 0:
                exp_date = exp_result[1]
            elif exp_result[0] == 1:
                notfound.append(domain)

        # now try to calculate remaining time
        try:
            delta = exp_date - now
            whoiscache['domain_expiration_dates'][domain] = exp_date.timestamp()
            logging.info('%s will expire in %s', domain, delta.days)
            writecache(whoiscache, CACHEFILE)
        except Exception as err:
            logging.info(domain)
            logging.info(err)
        if delta.days < WARNING:
            experation_list[domain] = delta.days

    logging.info('%s domains processed', len(zonelist))

    exitcode = 0
    m = min(experation_list.values())
    if m < CRITICAL:
        exitcode = 2
    elif CRITICAL < m < WARNING:
        exitcode = 1
    message = ''
    if len(experation_list) > 0:
        for i in experation_list:
            message = message + '{} ({}),'.format(i, experation_list[i])
        message = message.rstrip(',')
    else:
        message = 'OK'
    if len(notfound) > 0:
        nf = 'unknown domains: '
        for i in notfound:
            nf = nf + i + ','
        nf = nf.rstrip(',')
        if exitcode == 0:
            exitcode = 3
        message = message + '-- ' + nf

    print(message)
    exit(exitcode)

if __name__ == "__main__":
    main()
