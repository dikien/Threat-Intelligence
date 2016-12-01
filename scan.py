import argparse
import csv
import json
import requests
import random
from urlparse import urlsplit


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                    help='This tool is to investigate a reputation of suspicious IP or domain from VirusTotal, Malware.com and Google Safe Browsing')
parser.add_argument("-v", "--virustotal", help="Get information about VirusTotal", nargs='?', const=1, default=False)
parser.add_argument("-m", "--malwares", help="Get information about Safe Browsing", nargs='?', const=1, default=False)
parser.add_argument("-s", "--safebrowsing", help="Get information about Safe Browsing", nargs='?', const=1, default=False)
parser.add_argument("-d", "--debug", help="Print more detail Information", type=str, nargs='?', const=1, default=False)
parser.add_argument("-slack", help="Send Output to Slack Channel", type=str, nargs='?', const=1, default=False)
parser.add_argument("-raw", help="No preprosessing for output and return raw data", type=str, nargs='?', const=1, default=False)
parser.add_argument("-ip", help="Get information about IP", type=str, nargs='?', const=1, default=False)
parser.add_argument("-url", help="Get information about URL", type=str, nargs='?', const=1, default=False)
parser.add_argument("-c", "--config", help="Set the Json Config for API Key", type=str, nargs='?', const=1, default=False)
parser.add_argument("-o", "--output", help="Save Output. Supporting type is csv and json", nargs='?', const=1, default=False)
args = parser.parse_args()


# default values
CONFIG = False
SAFEBROWSING = False
VIRUSTOTAL = False
MALWARES = False
ENABLE_DEBUG_PRINT = False
IP = False
URL = False
OUTPUT = False
SLACK = False
RAW = False


# set values from user input
if args.config is not False:
    CONFIG = json.load(open(args.config))
if args.url is not False:
    assert args.url != ""
    URL = args.url
if args.ip is not False:
    assert args.ip != ""
    IP = args.ip
if args.virustotal is not False:
    VIRUSTOTAL = True
if args.malwares is not False:
    MALWARES = True
if args.safebrowsing is not False:
    SAFEBROWSING = True
if args.output is not False:
    OUTPUT = True
if args.debug is not False:
    ENABLE_DEBUG_PRINT = True
if args.slack is not False:
    if (CONFIG['slack_webhook'] != "") and (CONFIG['slack_channel'] != ""):
        SLACK = True
if args.raw is not False:
    RAW = True


# Retrieving URL scan reports
def request_to_vt_url_scan(url):
    agent_list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
        "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
        ]
    User_Agent = random.choice(agent_list)
    headers = {"User-Agent" : User_Agent}

    if URL is not False:

        params = {'apikey': CONFIG['virustotal'], 'resource' : URL}
        try:
            dprint("[VIRUSTOTAL] URL Scan : {0}".format(url))
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', headers=headers, params=params, timeout=10)

            if (response.status_code == 200) and (response.json()['response_code'] == 1):
                result = {}
                data = response.json()
                result['resource'] = data['resource']
                result['response_code'] = data['response_code']
                result['positives'] = data['positives']
                result['total'] = data['total']

                if RAW is not False:
                    return response.json()
                return result

            elif response.json()['response_code'] != 1:
                result = {}
                data = response.json()
                result['resource'] = data['resource']
                result['response_code'] = data['response_code']
                return result

        except Exception as e:
            if response.status_code == 204:
                return {'resource': url, 'error': "Daily quota was exceed"}
            else:
                return {'resource' : url, 'error' : str(e)}


# Retrieving domain reports
def request_to_vt_domain_report(url):
    agent_list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
        "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
        ]
    User_Agent = random.choice(agent_list)
    headers = {"User-Agent" : User_Agent}

    # extract domain from url
    url = extract_path(URL)

    if URL is not False:

        params = {'apikey': CONFIG['virustotal'], 'domain' : url}
        try:
            dprint("[VIRUSTOTAL] Domain Report : {0}".format(url))
            response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', headers=headers, params=params, timeout=10)

            if (response.status_code == 200) and (response.json()['response_code'] == 1):
                result = {}
                data = response.json()

                for k in data.keys():
                    if (k.find("sample") != -1) or (k.find("info") != -1) or (k.find("resolutions") != -1) or (k.find("pcap") != -1) or (k.find("detected_urls") != -1):
                        result[str(k)] = len(data[k])
                    elif (k.find("whois_timestamp") == -1) and (k.find("whois") == -1):
                        result[str(k)] = data[k]
                result['resource'] = URL
                result['response_code'] = data['response_code']

                if RAW is not False:
                    return response.json()

                return result
            elif response.json()['response_code'] != 1:
                result = {}
                data = response.json()
                result['response_code'] = data['response_code']
                return response.json()

        except Exception as e:
            if response.status_code == 204:
                return {'resource': url, 'error': "Daily quota was exceed"}
            else:
                return {'resource' : url, 'error' : str(e)}


# Retrieving IP address reports
def request_to_vt_ip_report(ip):
    agent_list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
        "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
        ]
    User_Agent = random.choice(agent_list)
    headers = {"User-Agent" : User_Agent}

    if IP is not False:

        params = {'apikey': CONFIG['virustotal'], 'ip' : ip}
        try:
            dprint("[VIRUSTOTAL] IP Report : {0}".format(ip))
            response = requests.get('http://www.virustotal.com/vtapi/v2/ip-address/report', headers=headers, params=params, timeout=10)
            if (response.status_code == 200) and (response.json()['response_code'] == 1):
                result = {}
                data = response.json()
                for k in data.keys():
                    if ((k.find("sample") != -1) or (k.find("url") != -1)) and (k.find("undetected") == -1):
                        result[str(k)] = len(data[k])
                    elif k.find("undetected") == -1:
                        result[str(k)] = data[k]

                if RAW is not False:
                    return response.json()

                return result

            elif response.json()['response_code'] != 1:
                result = {}
                data = response.json()
                result['resource'] = IP
                result['response_code'] = data['response_code']
                return result

        except Exception as e:
            if response.status_code == 204:
                return {'resource': IP, 'error': "Daily quota was exceed"}
            else:
                return {'resource' : IP, 'error' : str(e)}


# URL Analysis Request API
def request_to_malwares_url_scan(url):
    result_code = {
        "2": "Now analyzing",
        "1": "Data exists",
        "0": "Data is not exist",
        "-1": "Invalid Parameters",
        "-11": "No matching data to API Key",
        "-12": "No authority to use",
        "-13": "Expired API Key",
        "-14": "Over the daily request limit",
        "-15": "Over the hourly request limit",
        "-41": "Invalid type of url",
        "-404": "No result",
        "-500": "Internal Server Error"
    }
    params = {'api_key': CONFIG['malwares'], 'url': url}
    agent_list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
        "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
        ]
    User_Agent = random.choice(agent_list)
    headers = {"User-Agent": User_Agent}
    try:
        dprint("[MALWARES.COM] URL Scan : {0}".format(url))
        response = requests.post('https://www.malwares.com/api/v2/url/info', headers=headers, data=params, timeout=10)
        if (response.status_code == 200) and (response.json()['result_code'] == 1):
            data = response.json()
            url = data['url']
            positives = data['virustotal']['positives']
            smishing = data['smishing']

            if RAW is not False:
                return response.json()

            return {"response_code": result_code[str(data['result_code'])], "resource": url, "positives": positives,
                    "smishing": smishing}
        elif response.json()['result_code'] != 1:
            result = {}
            data = response.json()
            result['response_code'] = data['result_code']
            result['resource'] = url
            result['result_msg'] = data['result_msg']
            return result
    except Exception as e:
        return {'resource': url, 'error': str(e)}


# IP Report API
def request_to_malwares_ip(ip):
    result_code = {
        "1": "Data exists",
        "0": "Data is not exist",
        "-1": "Invalid Parameters",
        "-11": "No matching data to API Key",
        "-12": "No authority to use",
        "-13": "Expired API Key",
        "-14": "Over the daily request limit",
        "-15": "Over the hourly request limit",
        "-51": "Invalid type of ip",
        "-404": "No result",
        "-500": "Internal Server Error"
    }
    agent_list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
        "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
        ]
    User_Agent = random.choice(agent_list)

    headers = {"User-Agent": User_Agent}
    try:
        dprint("[MALWARES.COM] IP Scan : {0}".format(ip))
        response = requests.get(
            'https://www.malwares.com/api/v2/ip/info?api_key={0}&ip={1}'.format(CONFIG['malwares'], IP),
            headers=headers, timeout=10)
        if (response.status_code == 200) and (response.json()['result_code'] == 1):
            data = response.json()

            result = {}
            location_cname = response.json()['location']['cname']
            result['location_cname'] = location_cname

            location_city = response.json()['location']['city']
            result['location_city'] = location_city
            result['resource'] = IP
            for k in response.json().keys():
                if k == "detected_url":
                    detected_url = response.json()['detected_url']['total']
                    result['detected_url'] = detected_url
                if k == "detected_downloaded_file":
                    detected_downloaded_file = response.json()['detected_downloaded_file']['total']
                    result['detected_downloaded_file'] = detected_downloaded_file
                if k == "detected_communicating_file":
                    detected_communicating_file = response.json()['detected_communicating_file']['total']
                    result['detected_communicating_file'] = detected_communicating_file
                result["result"] = result_code[str(data['result_code'])]

            if RAW is not False:
                return response.json()

            return result
        elif response.json()['result_code'] != 1:
            result = {}
            data = response.json()
            result['response_code'] = data['result_code']
            result['resource'] = url
            result['result_msg'] = data['result_msg']
            return result
    except Exception as e:
        return {'resource': ip, 'error': str(e)}


# Google Safe Browsing
def request_to_safe_browsing(url):
    agent_list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
        "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
        ]
    User_Agent = random.choice(agent_list)
    headers = {"User-Agent": User_Agent}
    data = {
        "client": {
            "clientId": "malware scan",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION",
                            "THREAT_TYPE_UNSPECIFIED", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    params = {"key" : CONFIG['Safe Browsing']}
    try:
        dprint("[SAFEBROWSING] : {0}".format(url))
        response = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params=params,
                          headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            data = response.json()['matches'][0]
            result = {}
            result['platformType'] = data['platformType']
            result['resource'] = data['threat']['url']
            result['threatType'] = data['threatType']

            if RAW is not False:
                return response.json()

            return result
        elif response.status_code != 0:
            data = response.json()
            return {"result": data, "resource": url}
    except Exception as e:
        return {"result": str(e), "resource": url}


def send_slack(msg):
    dprint('Sending Message to Slack')
    channel = CONFIG['slack_channel']
    webhook = CONFIG['slack_webhook']
    payload = {"channel": "#{0}".format(channel),
               "mrkdwn" : "true",
               "username": "Threat Intelligence",
               "text" : "```{0}```".format(msg)
               }
    requests.post(webhook, json = payload)


def dprint(msg):
    """Debug print statements."""
    if ENABLE_DEBUG_PRINT == True:
        print "[DEBUG] {0}".format(msg)


def extract_path(url):
    url = urlsplit(URL)
    if url.path == '':
        return url.netloc
    else:
        return url.path


def save_to_csv(fn, dict_rap):
    dprint('saving {0}'.format(fn))
    with open(fn, "w") as fp:
        w = csv.writer(fp)
        w.writerow(dict_rap.keys())
        w.writerow(dict_rap.values())


def save_to_json(fn, dict_rap):
    dprint('saving {0}'.format(fn))
    with open(fn, "w") as fp:
        json.dump(dict_rap, fp)


if (VIRUSTOTAL == True) and (CONFIG['virustotal'] != ""):
    if URL is not False:
        response_to_vt_url_scan = request_to_vt_url_scan(URL)
        response_to_vt_domain_report = request_to_vt_domain_report(URL)

        virustotal = {}
        virustotal.update(response_to_vt_url_scan)
        virustotal.update(response_to_vt_domain_report)
        print response_to_vt_url_scan
        print response_to_vt_domain_report

        if SLACK is not False:
            send_slack(response_to_vt_url_scan)
            send_slack(response_to_vt_domain_report)

        # response_to_vt_url_scan
        if OUTPUT is not False:
            url = extract_path(URL)
            save_to_json('./{0}_vt_url_scan.json'.format(url), response_to_vt_url_scan)
            save_to_json('./{0}_vt_domain_report.json'.format(url), response_to_vt_domain_report)

            save_to_csv('{0}_vt_url_scan.csv'.format(url), response_to_vt_url_scan)
            save_to_csv('{0}_vt_domain_report.csv'.format(url), response_to_vt_domain_report)


    else:
        virustotal = {}
        response_to_vt_ip_report = request_to_vt_ip_report(IP)
        virustotal.update(response_to_vt_ip_report)
        print virustotal

        if SLACK is not False:
            send_slack(response_to_vt_ip_report)

        if OUTPUT is not False:
            save_to_json('{0}_vt_ip_report.json'.format(IP), response_to_vt_ip_report)
            save_to_csv('{0}_vt_ip_report.csv'.format(IP), response_to_vt_ip_report)

elif VIRUSTOTAL is True:
    print "Enter your VIRUSTOTAL API Key on key.json"

if (MALWARES == True) and (CONFIG['malwares'] != ""):
    if URL is not False:
        response_to_malwares_url_scan = request_to_malwares_url_scan(URL)
        print response_to_malwares_url_scan

        if SLACK is not False:
            send_slack(response_to_malwares_url_scan)

        if OUTPUT is not False:
            url = extract_path(URL)
            save_to_json('{0}_malware_url_report.json'.format(url), response_to_malwares_url_scan)
            save_to_csv('{0}_malware_url_report.csv'.format(url), response_to_malwares_url_scan)

    else:
        response_to_malwares_ip = request_to_malwares_ip(IP)
        print response_to_malwares_ip

        if SLACK is not False:
            send_slack(response_to_malwares_ip)

        if OUTPUT is not False:
            save_to_json('{0}_malware_ip_report.json'.format(IP), response_to_malwares_ip)
            save_to_csv('{0}_malware_ip_report.csv'.format(IP), response_to_malwares_ip)
elif MALWARES == True:
    print "Enter your MALWARES.COM API Key on key.json"

if (SAFEBROWSING == True) and (CONFIG['Safe Browsing'] != ""):
    if URL is not False:
        try:
            response_to_safe_browsing = request_to_safe_browsing(URL)
            print response_to_safe_browsing

            if SLACK is not False:
                send_slack(response_to_safe_browsing)

            if OUTPUT is not False:
                url = extract_path(URL)
                save_to_json('{0}_safe_browsing.json'.format(url), response_to_safe_browsing)
                save_to_csv('{0}_safe_browsing.csv'.format(url), response_to_safe_browsing)

        except Exception as e:
            dprint("[SAFEBROWSING] No Matched Result")
elif SAFEBROWSING == True:
    print "Enter your SAFEBROWSING API Key on key.json"