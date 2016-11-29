# Threat-Intelligence
Python Scripts to Interact with VirusTotal, Malwares.com and Google Safe Browsing.
![VirusTotal](https://github.com/dikien/Threat-Intelligence/blob/master/resources/virustotal_logo.png)
![Malware.com](https://github.com/dikien/Threat-Intelligence/blob/master/resources/logo_mws.png)
![Google Safe Browsing](https://github.com/dikien/Threat-Intelligence/blob/master/resources/safebrowsing_logo.png)

### Description
This is an intelligence tool to investigate IP/Domain reputation via [virustotal](https://www.virustotal.com/ko/documentation/public-api/), [malwares.com](https://www.malwares.com/about/api) and [google safebrowsing](https://developers.google.com/api-client-library/python/apis/safebrowsing/v4). It supports sending output to slack and save output to local machine with csv and json type.

## How To Use
### Install
    pip install -r requirements.txt

Requirements
----
* Python 2.7
* Argparse
* Requests
* API keys from VirusTotal, Malware.com and Google Safe Browsing(Enter API Keys on key.json)

### Scanning an URL to VirusTotal:
```
$ python scan.py -c key.json -v -url kingskillz.ru
{'positives': 16, 'response_code': 1, 'total': 70, 'resource': u'kingskillz.ru'}
{'domain_siblings': [], 'BitDefender domain info': 67, 'undetected_referrer_samples': 2, 'whois_timestamp': 1480012951.01238, 'detected_downloaded_samples': 6, 'response_code': 1, 'Malwarebytes hpHosts info': 47, 'subdomains': [u'blog.kingskillz.ru', u'test.kingskillz.ru', u'wp.kingskillz.ru', u'www.kingskillz.ru'], 'Websense ThreatSeeker category': u'bot networks', 'undetected_downloaded_samples': 8, 'resolutions': 6, 'verbose_msg': u'Domain found in dataset', 'Opera domain info': 66, 'detected_urls': 57, 'categories': [u'bot networks']}

```

### Scanning an URL to VirusTotal and Save Output:
```
$ python scan.py -c key.json -v -url kingskillz.ru
{'positives': 16, 'response_code': 1, 'total': 70, 'resource': u'kingskillz.ru'}
{'domain_siblings': [], 'BitDefender domain info': 67, 'undetected_referrer_samples': 2, 'whois_timestamp': 1480012951.01238, 'detected_downloaded_samples': 6, 'response_code': 1, 'Malwarebytes hpHosts info': 47, 'subdomains': [u'blog.kingskillz.ru', u'test.kingskillz.ru', u'wp.kingskillz.ru', u'www.kingskillz.ru'], 'Websense ThreatSeeker category': u'bot networks', 'undetected_downloaded_samples': 8, 'resolutions': 6, 'verbose_msg': u'Domain found in dataset', 'Opera domain info': 66, 'detected_urls': 57, 'categories': [u'bot networks']}

```

### Scanning an URL to Malware.com:
```
$ python scan.py -c key.json -m -url kingskillz.ru
{'smishing': 0, 'positives': 17, 'response_code': 'Data exists', 'resource': u'http://kingskillz.ru'}
```

### Scanning an IP to VirusTotal and Malware.com:
```
$ python scan.py -c key.json -v -m -ip 8.8.8.8
{'resource': '8.8.8.8', 'detected_downloaded_samples': 9, 'response_code': 1, 'as_owner': u'Google Inc.', 'detected_referrer_samples': 100, 'country': u'US', 'detected_urls': 100, 'detected_communicating_samples': 100}
{'location_cname': u'UNITED STATES', 'location_city': u'MOUNTAIN VIEW', 'resource': '8.8.8.8', 'detected_communicating_file': 1000, 'detected_downloaded_file': 11, 'result': 'Data exists', 'detected_url': 1000}
```

![Google Safe Browsing](https://github.com/dikien/Threat-Intelligence/blob/master/resources/safebrowsing_ex_2.png)
### Scanning a URL to Google Safe Browsing:
```
$ python scan.py -c key.json -s -url ihaveaproblem.info
{'threatType': u'SOCIAL_ENGINEERING', 'resource': u'ihaveaproblem.info', 'platformType': u'ANY_PLATFORM'}
```

### Scanning an URL to VirusTotal, Malware.com and Google Safe Browsing and Save output:
```
$ python scan.py -c key.json -v -m -s -url ihaveaproblem.info -o -d
[DEBUG] request ihaveaproblem.info to virustotal url scan
[DEBUG] request ihaveaproblem.info to virustotal domain report
{'positives': 6, 'response_code': 1, 'total': 68, 'resource': u'ihaveaproblem.info'}
{'domain_siblings': [], 'BitDefender domain info': 67, 'undetected_downloaded_samples': 7, 'whois_timestamp': 1479032079.93, 'detected_downloaded_samples': 9, 'response_code': 1, 'verbose_msg': u'Domain found in dataset', 'Websense ThreatSeeker category': u'phishing and other frauds', 'resolutions': 2, 'subdomains': [u'www.ihaveaproblem.info'], 'Opera domain info': 66, 'detected_urls': 41, 'categories': [u'phishing and other frauds']}
[DEBUG] saving ./ihaveaproblem.info_vt_url_scan.json
[DEBUG] saving ./ihaveaproblem.info_vt_domain_report.json
[DEBUG] saving ihaveaproblem.info_vt_url_scan.csv
[DEBUG] saving ihaveaproblem.info_vt_domain_report.csv
[DEBUG] request ihaveaproblem.info to malwares.com url scan
{'smishing': 0, 'positives': 6, 'response_code': 'Data exists', 'resource': u'http://ihaveaproblem.info'}
[DEBUG] saving ihaveaproblem.info_malware_url_report.json
[DEBUG] saving ihaveaproblem.info_malware_url_report.csv
[DEBUG] request ihaveaproblem.info to safe browsing
{'threatType': u'SOCIAL_ENGINEERING', 'resource': u'ihaveaproblem.info', 'platformType': u'ANY_PLATFORM'}
[DEBUG] saving ihaveaproblem.info_safe_browsing.json
[DEBUG] saving ihaveaproblem.info_safe_browsing.csv
```

![slack example](https://github.com/dikien/dikien/Threat-Intelligence/blob/master/resources/slack_2.png)
### Scanning an URL to VirusTotal, Malwares.com and Google Safe Browsing and Sending output to Slack Channel:
```
$ python scan.py -c key.json -v -m -s -slack -url ihaveaproblem.info 
{'positives': 6, 'response_code': 1, 'total': 68, 'resource': u'ihaveaproblem.info'}
{'domain_siblings': [], 'BitDefender domain info': 67, 'undetected_downloaded_samples': 7, 'detected_downloaded_samples': 9, 'response_code': 1, 'verbose_msg': u'Domain found in dataset', 'Websense ThreatSeeker category': u'phishing and other frauds', 'resource': 'ihaveaproblem.info', 'resolutions': 2, 'subdomains': [u'www.ihaveaproblem.info'], 'Opera domain info': 66, 'detected_urls': 41, 'categories': [u'phishing and other frauds']}
{'smishing': 0, 'positives': 6, 'response_code': 'Data exists', 'resource': u'http://ihaveaproblem.info'}
{'threatType': u'SOCIAL_ENGINEERING', 'resource': u'ihaveaproblem.info', 'platformType': u'ANY_PLATFORM'}
```

### Scanning an URL to VirusTotal, Malwares.com and Google Safe Browsing with Debug Print:
```
$ python scan.py -c key.json -v -m -s -slack -url ihaveaproblem.info -d
[DEBUG] [VIRUSTOTAL] URL Scan : ihaveaproblem.info
[DEBUG] [VIRUSTOTAL] Domain Report : ihaveaproblem.info
{'positives': 6, 'response_code': 1, 'total': 68, 'resource': u'ihaveaproblem.info'}
{'domain_siblings': [], 'BitDefender domain info': 67, 'undetected_downloaded_samples': 7, 'detected_downloaded_samples': 9, 'response_code': 1, 'verbose_msg': u'Domain found in dataset', 'Websense ThreatSeeker category': u'phishing and other frauds', 'resource': 'ihaveaproblem.info', 'resolutions': 2, 'subdomains': [u'www.ihaveaproblem.info'], 'Opera domain info': 66, 'detected_urls': 41, 'categories': [u'phishing and other frauds']}
[DEBUG] Sending Message to Slack
[DEBUG] Sending Message to Slack
[DEBUG] [MALWARES.COM] URL Scan : ihaveaproblem.info
{'smishing': 0, 'positives': 6, 'response_code': 'Data exists', 'resource': u'http://ihaveaproblem.info'}
[DEBUG] Sending Message to Slack
[DEBUG] [SAFEBROWSING] : ihaveaproblem.info
{'threatType': u'SOCIAL_ENGINEERING', 'resource': u'ihaveaproblem.info', 'platformType': u'ANY_PLATFORM'}
[DEBUG] Sending Message to Slack
```

### Scanning an URL to Google Safe Browsing and Return Raw Data which is not Preprocessed:
```
$ python scan.py -c key.json -s -url ihaveaproblem.info -r
{u'matches': [{u'threatType': u'SOCIAL_ENGINEERING', u'threatEntryType': u'URL', u'platformType': u'ANY_PLATFORM', u'threat': {u'url': u'ihaveaproblem.info'}, u'cacheDuration': u'300s'}]}
```