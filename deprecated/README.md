# Threat-Intelligence
Python Scripts to Interact with VirusTotal and Google Safe Browsing without API Key
![VirusTotal](https://github.com/dikien/Threat-Intelligence/blob/master/resources/virustotal_logo.png)
![Google Safe Browsing](https://github.com/dikien/Threat-Intelligence/blob/master/resources/safebrowsing_logo.png)

### Description
There are lots of querying tools to [virustotal](https://www.virustotal.com/ko/documentation/public-api/) and [google safebrowsing](https://developers.google.com/api-client-library/python/apis/safebrowsing/v4) with Public API.
This tool is for educational purpose to study how to parse raw html and extract useful information. It could be blocked by abusing system such as captcha and ip blocker if you request too many. It is able to checks url or ip's reputation out, not file hash. This tool will not work when virustotal or google safe browsing's html structure change. If you set slack information, it is able to send output to your slack channel.
If you are searching tools with public api, check out:
- [Scripts to interact with the VirusToal public API](https://www.virustotal.com/ko/documentation/public-api/#scanning-urls)
- [Python client library for Google Safe Browsing API](https://github.com/afilipovich/gglsbl)

## How To Use
### Install
    pip install -r requirements.txt

Requirements
----
* Python 2.7
* Argparse
* Beautifulsoup4
* Requests
* Pandas

### Scanning an IP to VirusTotal:
```
 $ python run.py -s -v -ip 8.8.8.8
[+] Try to get 8.8.8.8 information from VirusTotal
[+] VirusTotal Result Summary
[+] Country is US 15169 (Google Inc.)
[+] The number of domain is 20
[+] The number of detected_urls is 2
[+] The number of detected_downloaded is 1
[+] The number of detected_communicating is 86
[+] The number of detected_referrer is 1
```

### Scanning an URL to VirusTotal:
```
$ python run.py -s -v -r 1 -url apexgames.org
[+] Try to get apexgames.org information from VirusTotal
[+] VirusTotal Result Summary
[+] The number of domain is 2
[+] The number of detected_urls is 17
[+] The number of detected_downloaded is 2
```

### Scanning an URL to VirusTotal more than 10 ratio:
```
$ python run.py -s -v -r 10 -url apexgames.org
[+] Try to get apexgames.org information from VirusTotal
[+] VirusTotal Result Summary
[+] The number of domain is 2
[+] The number of detected_urls is 1
[+] The number of detected_downloaded is 1
```

![safe browsing example](https://github.com/dikien/Threat-Intelligence/blob/master/resources/safebrowsing_ex_1.png)
### Scanning a URL to Google Safe Browsing 1:
```
$ python run.py -s -g -url apexgames.org
[+] Google Safe Browsing Result Summary
[+] MalwareSite is {'sendsToAttackSites': [], 'receivesTrafficFrom': [], 'type': 6, 'sendsToIntermediarySites': []}
[+] URL is apexgames.org/
[+] UwsListStatus is partial
[+] partialUwsHosts is ['apexgames.org/']
```

### Scanning a URL to Google Safe Browsing 2:
```
$ python run.py -s -g -url whitemirchi.com
[+] Google Safe Browsing Result Summary
[+] MalwareSite is {'sendsToAttackSites': [], 'receivesTrafficFrom': [], 'type': 0, 'sendsToIntermediarySites': []}
[+] URL is whitemirchi.com/
[+] SocialListStatus is partial
[+] partialSocialEngHosts is ['whitemirchi.com/']
```

### Scanning an URL to VirusTotal and Google Safe Browsing:
```
$ python run.py -s -v -r 1 -g -url whitemirchi.com
[+] Try to get whitemirchi.com information from VirusTotal
[+] VirusTotal Result Summary
[+] The number of domain is 1

[+] Google Safe Browsing Result Summary
[+] MalwareSite is {'sendsToAttackSites': [], 'receivesTrafficFrom': [], 'type': 0, 'sendsToIntermediarySites': []}
[+] URL is whitemirchi.com/
[+] SocialListStatus is partial
[+] partialSocialEngHosts is ['whitemirchi.com/']
```

### Scanning an URL to VirusTotal and Google Safe Browsing and Save output to csv and pickle type:
```
$ python run.py -s -v -r 1 -g -url whitemirchi.com -o 
[+] Try to get whitemirchi.com information from VirusTotal
[+] VirusTotal Result Summary
[+] The number of domain is 1

[+] Google Safe Browsing Result Summary
[+] MalwareSite is {'sendsToAttackSites': [], 'receivesTrafficFrom': [], 'type': 0, 'sendsToIntermediarySites': []}
[+] URL is whitemirchi.com/
[+] SocialListStatus is partial
[+] partialSocialEngHosts is ['whitemirchi.com/']

$ ls  whitemirchi*
whitemirchi.com.csv     whitemirchi.com.pickle
```

![slack example](https://github.com/dikien/Threat-Intelligence/blob/master/resources/slack_1.png)
### Scanning an URL to VirusTotal and Google Safe Browsing and Sending output to Slack Channel:
```
$ python run.py -s -v -r 1 -g -url apexgames.org -slack_webhook https://hooks.slack.com/services/{enter your webhook} -slack_channel {enter your channel name}
[+] Try to get apexgames.org information from VirusTotal
[+] VirusTotal Result Summary
[+] Querying apexgames.org ...
[+] The number of domain is 2
[+] The number of detected_urls is 17
[+] The number of detected_downloaded is 2

[+] Google Safe Browsing Result Summary
[+] Querying apexgames.org ...
[+] MalwareSite is {'sendsToAttackSites': [], 'receivesTrafficFrom': [], 'type': 6, 'sendsToIntermediarySites': []}
[+] URL is apexgames.org/
[+] UwsListStatus is partial
[+] partialUwsHosts is ['apexgames.org/']

```