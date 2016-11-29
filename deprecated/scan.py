import ast
import argparse
from bs4 import BeautifulSoup
import pandas as pd
import requests
import random
import urlparse


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                    help='This tool is to investigate a reputation of suspicious IP or domain from VirusTotal and Google Safe Browsing')
parser.add_argument("-v", "--virustotal", help="Get information about VirusTotal", nargs='?', const=1, default=False)
parser.add_argument("-g", "--google", help="Get information about Safe Browsing", nargs='?', const=1, default=False)
parser.add_argument("-r", "--ratio", help="Set Minimum Virustotal Detection Ratio. Default is 10", nargs='?', const=1, type=int, default=10)
parser.add_argument("-d", "--debug", help="Print more detail Information", type=str, nargs='?', const=1, default=False)
parser.add_argument("-ip", help="Get information about IP", type=str, nargs='?', const=1, default=False)
parser.add_argument("-url", help="Get information about URL", type=str, nargs='?', const=1, default=False)
parser.add_argument("-slack_webhook", help="Set the Slack WebHook to get Outout", type=str, nargs='?', const=1, default=False)
parser.add_argument("-slack_channel", help="Set the Slack Channel Name to get Outout", type=str, nargs='?', const=1, default=False)
parser.add_argument("-o", "--output", help="Save Output. Supporting type is CSV and Pickle", nargs='?', const=1, default=False)
parser.add_argument("-s", "--summary", help="Print Summary of Result", nargs='?', const=1, default=False)
args = parser.parse_args()


def requests_to_vt(ip):
    agent_list = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
                  "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
                  "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
                  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
                 ]

    User_Agent = random.choice(agent_list)

    headers = {"Origin" : "https://www.virustotal.com",
               "Accept-Encoding" : "gzip, deflate",
               "User-Agent" : User_Agent,
               "Referer" : "https://www.virustotal.com/en/",
               "DNT" : "1",
               "cache-control" : "max-age=0",
               "upgrade-insecure-requests" : "1",
               "Cookie" : "VT_CSRF=a11efaaa2ba1749ec1d7dd7a35d7bc0d; VT_PREFERRED_LANGUAGE=en"}

    if URL == False:
        response = requests.get("https://www.virustotal.com/en/ip-address/%s/information/" %str(ip), headers=headers)
    else:
        response = requests.get("https://www.virustotal.com/en/domain/%s/information/" %str(ip), headers=headers)
    data = response.text
    soup = BeautifulSoup(data, "html.parser")
    return soup


def vt_to_country(soup):
    contents = soup.findAll("div", { "class" : "enum-container"})
    if contents == []:
        return None

    contents = contents[0]
    contents = contents.findAll("div", { "class" : "enum" })

    result = ""
    for content in contents:
        result += content.contents[3].text.strip()
        result += " "
    dprint(result)
    return result.strip()


def vt_to_dns(soup):
    contents = soup.findAll("div", { "id" : "dns-resolutions"})
    if contents == []:
        return None

    contents = contents[0]
    contents = contents.findAll("div", { "class" : "enum" })

    result = []
    for content in contents:
        t = content.contents[0].strip()
        domain = content.a.text.strip()
        dprint({"time" : t, "domain" : domain})
        result.append({"time" : t, "domain" : domain})
    return result


def vt_to_detected_urls(soup):
    vt_host = "https://www.virustotal.com"
    contents = soup.findAll("div", { "id" : "detected-urls"})
    if contents == []:
        return None

    contents = contents[0]
    contents = contents.findAll("div", { "class" : "enum" })

    result = []
    for content in contents:
        ratio = content.span.text
        url = content.a.text.strip()
        t = content.contents[3].text

        vt_url = content.find("a")['href']
        vt_url = urlparse.urljoin(vt_host, vt_url)
        dprint({"time" : t, "ratio" : ratio, "vt_url" : vt_url, "url" : url})
        result.append({"time" : t, "ratio" : ratio, "vt_url" : vt_url, "url" : url})
    return result


def vt_to_detected_downloaded(soup):
    vt_host = "https://www.virustotal.com"
    contents = soup.findAll("div", { "id" : "detected-downloaded"})
    if contents == []:
        return None

    contents = contents[0]
    contents = contents.findAll("div", { "class" : "enum" })

    result = []
    for content in contents:
        t = content.contents[3].text
        ratio = content.span.text
        vt_url = content.a['href']
        vt_url = urlparse.urljoin(vt_host, vt_url)
        dprint({"time" : t, "ratio" : ratio, "vt_url" : vt_url})
        result.append({"time" : t, "ratio" : ratio, "vt_url" : vt_url})
    return result


def vt_to_detected_communicating(soup):
    vt_host = "https://www.virustotal.com"
    contents = soup.findAll("div", { "id" : "detected-communicating"})
    if contents == []:
        return None

    contents = contents[0]
    contents = contents.findAll("div", { "class" : "enum" })

    result = []
    for content in contents:
        t = content.contents[3].text
        ratio = content.span.text
        vt_url = content.a['href']
        vt_url = urlparse.urljoin(vt_host, vt_url)
        dprint({"time" : t, "ratio" : ratio, "vt_url" : vt_url})
        result.append({"time" : t, "ratio" : ratio, "vt_url" : vt_url})
    return result


def vt_to_detected_referrer(soup):
    vt_host = "https://www.virustotal.com"
    contents = soup.findAll("div", { "id" : "detected-referrer"})
    if contents == []:
        return None

    contents = contents[0]
    contents = contents.findAll("div", { "class" : "enum" })

    result = []
    for content in contents:
        ratio = content.span.text
        path = content.a['href']
        vt_url = urlparse.urljoin(vt_host, path)
        dprint({"ratio" : ratio, "vt_url" : vt_url})
        result.append({"ratio" : ratio, "vt_url" : vt_url})
        return result


def check_ratio(items, ratio=10):
    if items == None:
        return None

    result = []
    if len(items) > 0:
        for item in items:
            if int(item['ratio'].split("/")[0]) >= ratio:
                result.append(item)
                dprint(item)
    return result


def request_safebrowsing(ip):
    agent_list = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
                  "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
                  "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
                  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
                 ]


    User_Agent = random.choice(agent_list)

    headers = {"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "User-Agent" : User_Agent,
               "DNT" : "1",
               "Cookie" : "PREF=ID=7c4801ccf11172b5:U=cf79dbff45e75c9b:FF=0:LD=ko:TM=1415531226:LM=1421140541:S=stJPu1zeIuoqj4eY; NID=67=S6lT0yIpAKOWo8VGcgrs7R8KkqVdaC3-bHTgxAgeTojCthyMbyu1htksbRDSqCrmht5UYQVb7b0WmvHcoj1ks-FStKihS1QOv47HTWx3DIpcWqnTiMEEX7Tm_xt-nnec7BRuqDQ6q0_KfHIIK04T_Sc3IImCKON8Z75HRlESpFY; SID=DQAAAOgAAABpCDvuqMJLeE1PaiXp0oMuiJn2sPmhhpatrUEax7wMbZmF28ei_rgFbTstNePHvnOmXaFC3zshLc-yWvLLLnpXrpE8JjLCDV83KOGNcoEdxIGQo7fzrYvYo6g0EpL7HpIRBmcfOxV86jTNoUUJ7I4uNGuSe3U1V1EorVFuSUEeb5QXxnIgjWZPJgLC5BLVKwFnQYKo_XeRyhseViIY7PmH_IvA9elJ3tnaStpia9jvr9lBYMVH31iPa1VYIL9Tu6fRpCZgy7qMqXczILT6Rm2UR4LucY00UIh879RQOy80BG3h2uLTZ9mTcVCGNDVDwac; HSID=A0oMFQ14zp7IdG69H; SSID=AVBcevuZ2xNm1FZ3T; APISID=t51XxytEHH_0a6_E/AzA8mwzdqqGk-hRYU; SAPISID=OVStu50FtudKGJGH/A879KTQhgtMkXkw1_"}

    response = requests.get("https://www.google.com/safebrowsing/diagnostic?output=jsonp&site=%s" %str(ip), headers=headers)
    response = response.content[response.content.find("{") : response.content.rfind("}")+1]
    response = ast.literal_eval(response)
    dprint(response)
    return response


def dprint(msg):
    """Debug print statements."""
    if ENABLE_DEBUG_PRINT == True:
        print "[DEBUG] {0}".format(msg)


def send_slack(channel, webhook, msg):
    payload = {"channel": "#{0}".format(channel),
               "mrkdwn" : "true",
               "username": "Security Checker",
               "text" : "```{0}```".format(msg)
               }
    r = requests.post(webhook, json = payload)


# default values
GOOGLE = False
VIRUSTOTAL = False
RATIO = 10
SUMMARY = False
URL = ""
ENABLE_DEBUG_PRINT = False
IP = False
URL = False
OUTPUT = False
TYPE = False
SLACK_WEBHOOK = False
SLACK_CHANNEL = False


# set values from user input
if args.google is not False:
    GOOGLE = True
if args.virustotal is not False:
    VIRUSTOTAL = True
if args.ratio is not False:
    RATIO = args.ratio
if args.summary is not False:
    SUMMARY = True
if args.ip is not False:
    assert args.ip != ""
    IP = args.ip
if args.url is not False:
    assert args.url != ""
    URL = args.url
if args.debug is not False:
    ENABLE_DEBUG_PRINT = True
if args.output is not False:
    OUTPUT = args.output
if args.slack_webhook is not False:
    SLACK_WEBHOOK = args.slack_webhook
if args.slack_channel is not False:
    SLACK_CHANNEL = args.slack_channel


if VIRUSTOTAL == True:
    try:
        if IP is not False:
            print "[+] Try to get {0} information from VirusTotal".format(IP)
            soup = requests_to_vt(IP)
        else:
            print "[+] Try to get {0} information from VirusTotal".format(URL)
            soup = requests_to_vt(URL)

        if str(soup) < 1000:
            print "[+] Go to Virustotal and enter captcha manually."

        try:
            country = vt_to_country(soup)
        except Exception as e:
            print "[+] Fail to parse country"
            print e

        try:
            dns = vt_to_dns(soup)
        except Exception as e:
            print "[+] Fail to parse dns"
            print e

        try:
            detected_urls = vt_to_detected_urls(soup)
        except Exception as e:
            print "[+] Fail to parse detected_urls"
            print e

        try:
            detected_downloaded = vt_to_detected_downloaded(soup)
        except Exception as e:
            print "[+] Fail to parse detected_downloaded"
            print e

        try:
            detected_communicating = vt_to_detected_communicating(soup)
        except Exception as e:
            print "[+] Fail to parse detected_communicating"
            print e

        try:
            detected_referrer = vt_to_detected_referrer(soup)
        except Exception as e:
            print "[+] Fail to detected_referrer"
            print e


        # more than 10 Anti Virus Solutions
        detected_urls = check_ratio(detected_urls, RATIO)
        detected_downloaded = check_ratio(detected_downloaded, RATIO)
        detected_communicating = check_ratio(detected_communicating, RATIO)
        detected_referrer = check_ratio(detected_referrer, RATIO)


        # Summary
        if SUMMARY == True:
            print "[+] VirusTotal Result Summary"
            if IP is not False:
                print "[+] Querying {0} ...".format(IP)
            else:
                print "[+] Querying {0} ...".format(URL)
            if country is not None: print "[+] Country is {0}".format(country)
            if dns is not None: print "[+] The number of domain is {0}".format(len(dns))
            if detected_urls is not None: print "[+] The number of detected_urls is {0}".format(len(detected_urls))
            if detected_downloaded is not None: print "[+] The number of detected_downloaded is {0}".format(len(detected_downloaded))
            if detected_communicating is not None: print "[+] The number of detected_communicating is {0}".format(len(detected_communicating))
            if detected_referrer is not None: print "[+] The number of detected_referrer is {0}".format(len(detected_referrer))
        print ""

    except Exception as e:
        print "[+] Fail to get {0} information from VirusTotal".format(IP)
        print e


if (GOOGLE == True) and (URL is not False):
    try:
        if IP is not False:
            safebrowsing = request_safebrowsing(IP)
        if URL is not False:
            safebrowsing = request_safebrowsing(URL)

         # Summary
        if SUMMARY == True:
            print "[+] Google Safe Browsing Result Summary"
            if IP is not False:
                print "[+] Querying {0} ...".format(IP)
            else:
                print "[+] Querying {0} ...".format(URL)
            if safebrowsing['website']['malwareSite'] != []: print "[+] MalwareSite is {0}".format(safebrowsing['website']['malwareSite'])
            if safebrowsing['website']['name'] != []: print "[+] URL is {0}".format(safebrowsing['website']['name'])
            if safebrowsing['website']['malwareListStatus'] != "unlisted": print "[+] MalwareListStatus is {0}".format(safebrowsing['website']['malwareListStatus'])
            if safebrowsing['website']['partialMalwareHosts'] != []: print "[+] PartialMalwareHosts is {0}".format(safebrowsing['website']['partialMalwareHosts'])
            if safebrowsing['website']['uwsListStatus'] != "unlisted": print "[+] UwsListStatus is {0}".format(safebrowsing['website']['uwsListStatus'])
            if safebrowsing['website']['partialUwsHosts'] != []: print "[+] partialUwsHosts is {0}".format(safebrowsing['website']['partialUwsHosts'])
            if safebrowsing['website']['socialListStatus'] != "unlisted": print "[+] SocialListStatus is {0}".format(safebrowsing['website']['socialListStatus'])
            if safebrowsing['website']['partialSocialEngHosts'] != []: print "[+] partialSocialEngHosts is {0}".format(safebrowsing['website']['partialSocialEngHosts'])
            if safebrowsing['website']['malwareDownloadListStatus'] != "unlisted": print "[+] MalwareDownloadListStatus is {0}".format(safebrowsing['website']['malwareDownloadListStatus'])
            if safebrowsing['website']['partialMalwareDowHosts'] != []: print "[+] PartialMalwareDowHosts is {0}".format(safebrowsing['website']['partialMalwareDowHosts'])
            if safebrowsing['website']['uwsDownloadListStatus'] != "unlisted": print "[+] UwsDownloadListStatus is {0}".format(safebrowsing['website']['uwsDownloadListStatus'])
            if safebrowsing['website']['partialUwsDowHosts'] != []: print "[+] PartialUwsDowHosts is {0}".format(safebrowsing['website']['partialUwsDowHosts'])
            if safebrowsing['website']['unknownDownloadListStatus'] != "unlisted": print "[+] UnknownDownloadListStatus is {0}".format(safebrowsing['website']['unknownDownloadListStatus'])
            if safebrowsing['website']['partialUnknownDowHosts'] != []: print "[+] PartialUnknownDowHosts is {0}".format(safebrowsing['website']['partialUnknownDowHosts'])
    except Exception as e:
        print "[+] Fail to get safebrowsing"
        print e


if not ((SLACK_WEBHOOK is False) and (SLACK_CHANNEL is False)):
    if (VIRUSTOTAL == True) and (GOOGLE == True):
        msg_v = ""
        msg_v += "[+] VirusTotal Result Summary\n"
        if IP is not False:
            msg_v += "[+] Querying {0} ...\n".format(IP)
        else:
            msg_v += "[+] Querying {0} ...\n".format(URL)
        if country is not None: msg_v += "[+] Country is {0}\n".format(country)
        if dns is not None: msg_v += "[+] The number of domain is {0}\n".format(len(dns))
        if detected_urls is not None: msg_v += "[+] The number of detected_urls is {0}\n".format(len(detected_urls))
        if detected_downloaded is not None: msg_v+= "[+] The number of detected_downloaded is {0}\n".format(len(detected_downloaded))
        if detected_communicating is not None: msg_v += "[+] The number of detected_communicating is {0}\n".format(len(detected_communicating))
        if detected_referrer is not None: msg_v += "[+] The number of detected_referrer is {0}\n".format(len(detected_referrer))

        msg_s = ""
        msg_s += "[+] Google Safe Browsing Result Summary\n"
        if IP is not False:
            msg_s += "[+] Querying {0} ...\n".format(IP)
        else:
            msg_s += "[+] Querying {0} ...\n".format(URL)
        if safebrowsing['website']['malwareSite'] != []: msg_s += "[+] MalwareSite is {0}\n".format(safebrowsing['website']['malwareSite'])
        if safebrowsing['website']['name'] != []: msg_s += "[+] URL is {0}".format(safebrowsing['website']['name'])
        if safebrowsing['website']['malwareListStatus'] != "unlisted": msg_s += "[+] MalwareListStatus is {0}\n".format(safebrowsing['website']['malwareListStatus'])
        if safebrowsing['website']['partialMalwareHosts'] != []: msg_s += "[+] PartialMalwareHosts is {0}\n".format(safebrowsing['website']['partialMalwareHosts'])
        if safebrowsing['website']['uwsListStatus'] != "unlisted": msg_s += "[+] UwsListStatus is {0}\n".format(safebrowsing['website']['uwsListStatus'])
        if safebrowsing['website']['partialUwsHosts'] != []: msg_s += "[+] partialUwsHosts is {0}\n".format(safebrowsing['website']['partialUwsHosts'])
        if safebrowsing['website']['socialListStatus'] != "unlisted": msg_s += "[+] SocialListStatus is {0}\n".format(safebrowsing['website']['socialListStatus'])
        if safebrowsing['website']['partialSocialEngHosts'] != []: msg_s += "[+] partialSocialEngHosts is {0}\n".format(safebrowsing['website']['partialSocialEngHosts'])
        if safebrowsing['website']['malwareDownloadListStatus'] != "unlisted": msg_s += "[+] MalwareDownloadListStatus is {0}\n".format(safebrowsing['website']['malwareDownloadListStatus'])
        if safebrowsing['website']['partialMalwareDowHosts'] != []: msg_s += "[+] PartialMalwareDowHosts is {0}\n".format(safebrowsing['website']['partialMalwareDowHosts'])
        if safebrowsing['website']['uwsDownloadListStatus'] != "unlisted": msg_s += "[+] UwsDownloadListStatus is {0}\n".format(safebrowsing['website']['uwsDownloadListStatus'])
        if safebrowsing['website']['partialUwsDowHosts'] != []: msg_s += "[+] PartialUwsDowHosts is {0}\n".format(safebrowsing['website']['partialUwsDowHosts'])
        if safebrowsing['website']['unknownDownloadListStatus'] != "unlisted": msg_s += "[+] UnknownDownloadListStatus is {0}\n".format(safebrowsing['website']['unknownDownloadListStatus'])
        if safebrowsing['website']['partialUnknownDowHosts'] != []: msg_s += "[+] PartialUnknownDowHosts is {0}\n".format(safebrowsing['website']['partialUnknownDowHosts'])

        msg = ""
        msg += msg_v
        msg += "\n"
        msg += msg_s

        send_slack(SLACK_CHANNEL, SLACK_WEBHOOK, msg)

    elif VIRUSTOTAL == True:
        msg_v = ""
        msg_v += "[+] VirusTotal Result Summary\n"
        if IP is not False:
            msg_v += "[+] Querying {0} ...\n".format(IP)
        else:
            msg_v += "[+] Querying {0} ...\n".format(URL)
        if country is not None: msg_v += "[+] Country is {0}\n".format(country)
        if dns is not None: msg_v += "[+] The number of domain is {0}\n".format(len(dns))
        if detected_urls is not None: msg_v += "[+] The number of detected_urls is {0}\n".format(len(detected_urls))
        if detected_downloaded is not None: msg_v+= "[+] The number of detected_downloaded is {0}\n".format(len(detected_downloaded))
        if detected_communicating is not None: msg_v += "[+] The number of detected_communicating is {0}\n".format(len(detected_communicating))
        if detected_referrer is not None: msg_v += "[+] The number of detected_referrer is {0}\n".format(len(detected_referrer))

        send_slack(SLACK_CHANNEL, SLACK_WEBHOOK, msg_v)

    elif GOOGLE == True:
        msg_s = ""
        msg_s += "[+] Google Safe Browsing Result Summary\n"
        if IP is not False:
            msg_s += "[+] Querying {0} ...\n".format(IP)
        else:
            msg_s += "[+] Querying {0} ...\n".format(URL)
        if safebrowsing['website']['malwareSite'] != []: msg_s += "[+] MalwareSite is {0}\n".format(safebrowsing['website']['malwareSite'])
        if safebrowsing['website']['name'] != []: msg_s += "[+] URL is {0}".format(safebrowsing['website']['name'])
        if safebrowsing['website']['malwareListStatus'] != "unlisted": msg_s += "[+] MalwareListStatus is {0}\n".format(safebrowsing['website']['malwareListStatus'])
        if safebrowsing['website']['partialMalwareHosts'] != []: msg_s += "[+] PartialMalwareHosts is {0}\n".format(safebrowsing['website']['partialMalwareHosts'])
        if safebrowsing['website']['uwsListStatus'] != "unlisted": msg_s += "[+] UwsListStatus is {0}\n".format(safebrowsing['website']['uwsListStatus'])
        if safebrowsing['website']['partialUwsHosts'] != []: msg_s += "[+] partialUwsHosts is {0}\n".format(safebrowsing['website']['partialUwsHosts'])
        if safebrowsing['website']['socialListStatus'] != "unlisted": msg_s += "[+] SocialListStatus is {0}\n".format(safebrowsing['website']['socialListStatus'])
        if safebrowsing['website']['partialSocialEngHosts'] != []: msg_s += "[+] partialSocialEngHosts is {0}\n".format(safebrowsing['website']['partialSocialEngHosts'])
        if safebrowsing['website']['malwareDownloadListStatus'] != "unlisted": msg_s += "[+] MalwareDownloadListStatus is {0}\n".format(safebrowsing['website']['malwareDownloadListStatus'])
        if safebrowsing['website']['partialMalwareDowHosts'] != []: msg_s += "[+] PartialMalwareDowHosts is {0}\n".format(safebrowsing['website']['partialMalwareDowHosts'])
        if safebrowsing['website']['uwsDownloadListStatus'] != "unlisted": msg_s += "[+] UwsDownloadListStatus is {0}\n".format(safebrowsing['website']['uwsDownloadListStatus'])
        if safebrowsing['website']['partialUwsDowHosts'] != []: msg_s += "[+] PartialUwsDowHosts is {0}\n".format(safebrowsing['website']['partialUwsDowHosts'])
        if safebrowsing['website']['unknownDownloadListStatus'] != "unlisted": msg_s += "[+] UnknownDownloadListStatus is {0}\n".format(safebrowsing['website']['unknownDownloadListStatus'])
        if safebrowsing['website']['partialUnknownDowHosts'] != []: msg_s += "[+] PartialUnknownDowHosts is {0}\n".format(safebrowsing['website']['partialUnknownDowHosts'])

        send_slack(SLACK_CHANNEL, SLACK_WEBHOOK, msg_s)



if OUTPUT != False:
    try:
        if (VIRUSTOTAL == True) and (GOOGLE == True):
            df_detected_urls = pd.DataFrame(detected_urls)
            df_detected_urls['description'] = 'detected_urls from virustotal'

            df_detected_downloaded = pd.DataFrame(detected_downloaded)
            df_detected_downloaded['description'] = 'detected_downloaded from virustotal'

            df_detected_communicating = pd.DataFrame(detected_communicating)
            df_detected_communicating['description'] = 'detected_communicating from virustotal'

            df_detected_referrer = pd.DataFrame(detected_referrer)
            df_detected_referrer['description'] = 'detected_referrer from virustotal'

            df_safebrowsing = pd.DataFrame(data = {'description':['safebrowsing : {0}'.format(safebrowsing)]})

            df = pd.concat([df_detected_urls, df_detected_downloaded, df_detected_communicating, df_detected_referrer, df_safebrowsing])

            if IP is not False:
                df['object'] = IP
            else:
                df['object'] = URL

        elif VIRUSTOTAL == True:
            df_detected_urls = pd.DataFrame(detected_urls)
            df_detected_urls['description'] = 'detected_urls from virustotal'

            df_detected_downloaded = pd.DataFrame(detected_downloaded)
            df_detected_downloaded['description'] = 'detected_downloaded from virustotal'

            df_detected_communicating = pd.DataFrame(detected_communicating)
            df_detected_communicating['description'] = 'detected_communicating from virustotal'

            df_detected_referrer = pd.DataFrame(detected_referrer)
            df_detected_referrer['description'] = 'detected_referrer from virustotal'

            df = pd.concat([df_detected_urls, df_detected_downloaded, df_detected_communicating, df_detected_referrer])

            if IP is not False:
                df['object'] = IP
            else:
                df['object'] = URL

        elif GOOGLE == True:
            df_safebrowsing = pd.DataFrame(data = {'description':['safebrowsing : {0}'.format(safebrowsing)]})

            df = df_safebrowsing

            if IP is not False:
                df['object'] = IP
            else:
                df['object'] = URL

        if IP is not False:

            df.to_csv('./{0}.csv'.format(IP), sep=',')
            df.to_pickle('./{0}.pickle'.format(IP))
        else:
            df.to_csv('./{0}.csv'.format(URL), sep=',')
            df.to_pickle('./{0}.pickle'.format(URL))

    except Exception as e:
        print e

