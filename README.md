# O.D.I.N. [BETA]
### Observe, Detect, and Investigate Networks

[![Python Version](https://img.shields.io/badge/Python-3.6-brightgreen.svg)]() [![license](https://img.shields.io/github/license/mashape/apistatus.svg)]()

![ODIN](https://github.com/chrismaddalena/viper/blob/master/odin.jpg "ODIN")

Current version: v1.0 Muninn

>A Python tool for automating intelligence gathering, testing and reporting. O.D.I.N. is still in active development and is incomplete. Feedback on issues is welcome!

> Note: O.D.I.N. is designed to be run on Linux. About 90% of it will absolutely work on Windows or MacOS with Python 3 and a copy of urlcrazy, but `extract`, used for pulling metadata from non-PDF files, is exclusive to Linux. You'll be fine using an OS without access to `extract`, but you'll see some warnings and get less information.

## First Things First
O.D.I.N. is made possible through the help, input, and work provided by others. Therefore, this project is entirely open source and available to all to use/modify. All this developer did was assemble the tools, convert some of them to Python 3, and stitch them together.

## What Can O.D.I.N. Do?
O.D.I.N. is still very much in development, but it aims to automate many of the common recon tasks carried out by penetration testers. Such as:
* Harvesting email addresses and employee names for a company.
* Linking employees and companies to social media profiles.
* Checking to see if discovered accounts have been a part of any public security breaches or appeared in any pastes.
* Collecting data on domains and IP addresses from Shodan, Censys, DNS records, and whois/RDAP.
* Discovering subdomains, their related IP addresses, and looking for CDNs that might allow for domain fronting.
* Hunting Office files and PDFs under a domain, downloading them, and extracting metadata.
* Linking key words, like a company name or domain, to AWS via S3 buckets and account aliases.
* More to come in the future...

## Getting Started
1. Review the keys.config.sample file to fill-in your API keys and create a keys.config file.
2. `cd` into the /setup directory and run `setup_check.py` to make sure your keys.config file is in order.
3. Install any missing libraries by running pip with the requirements.txt file in the /setup directory: `pip3 install -r requirements.txt` or `python3 -m pip install -r requirements.txt`

### Optional AWS Setup
If you'd like to have O.D.I.N. do recon against AWS you will need an IAM user account and the associated ID and Secret. Get this from your AWS console. Typically, you will place this in ~/.aws/credentials, but it's nice to keep everything in one place. O.D.I.N. will use your keys.config file, but Amazon's Boto3 library for AWS may still look at ~/.aws/credentials. If that file has errors, Boto3 may log an error and quit. Just be aware of this possibility in case you have/use ~/.aws/credentials.

### The APIs and Services
O.D.I.N. uses several APIs to gather information. Some of these require an API key, but they're mostly free. That is to say, you can get a free key or pay for more requests/day. Shodan is a good example of this.

#### Whois and RDAP
Both of these services are used to collect data on domains and IP addresses. This includes attaching domains to IP addresses, identifying the network CIDRs for these addresses, and pulling information about the owners.

No API key is needed.

#### Robtex
The Robtex free API is used to collect domain names tied to IP addresses. This information is displayed alongside the RDAP information for IP addresses, so you can see what else is hosted at that IP address.

No API key is needed.

#### Shodan
Shodan is used to search for domains and lookup hosts (IP addresses). This pulls in information like open ports, banners, hostnames, and location data. Shodan also flags hosts for well known vulnerabilities like Heartbleed. This data is recorded as well, if it exists.

Sign-up for an account to get your API key: [shodan.io](https://www.shodan.io/)

#### Censys
Censys is very much like Shodan, except less information about open ports/services is available. However, Censys provides a way to search for certificates tied to a domain. This can be a *lot* of data, but you may find new hosts, like those tied to an employee's email address and used for a VPS in the cloud.

Sign-up for an account to get your API key: [censys.io](https://www.censys.io/)

#### URLVoid
URLVoid offers reputation data for domains, including Alexa and Google rankings, domain age, and location data. It also keeps track of domains that have been flagged for malicious activity by various entities (e.g. Fortinet, Avira).

This may be the most "skippable" of the APIs, but some of the data can be useful and worthwhile. It's included for those occasions.

Sign-up for an account to get your API key: [urlvoid.com/api](http://api.urlvoid.com/)

#### Twitter
If you setup a Twitter app for O.D.I.N., the tokens can be used with Tweepy and TheHarvester to not only locate Twitter handles tied to the provided domain but also collect account data (e.g. real name, location, follower count, and user description).

In the future, this may be used to also collect analytics from Twitter to help you find very active users or get a profile of them.

Become a Twitter developer by going to [dev.twitter.com](https://dev.twitter.com/) and then create an app on [apps.twitter.com](https://apps.twitter.com/).

#### Cymon
eSentire's Cymon is used to check domains and IP addresses to see if the target appears in any of Cymon's collected threat intelligence feeds. This is used for reputation checks, but also used in combination with urlcrazy to check similar, registered domains to see if the domain or the domain's A-record IP addresses have been reported.

Note that appearing in a threat feed doesn't mean something is wrong or that Cymon has bad data. A domain may have been used for phishing, been detected and seized, and is now dormant with the old malicious A records. Then you have things like cloud service IPs that change hands often. Events like that can lead to a domain or IP being flagged a week ago and no longer being malicious. Always investigate these findings.

Sign-up for an account to get your API key: [cymon.io](https://www.cymon.io/)

#### HaveIBeenPwned
Email addresses are checked against HIBP to determine if any email addresses for the organization have been mentioned in any pastes or been involved in any security breaches.

No API key is needed.

#### DNS Dumpster
DNS Dumpster is a cool project you can find at dnsdumpster.com. Subdomain information is collected from DNS Dumpster, including a neat domain map image!

No API key is needed.

#### EmailHunter
Meant for marketing folks to find leads and contacts at a company, this service offers free API keys for harvesting their contact information organizaed by company/domain. Hunter will return names, email addresses, phone numbers, Twitter handles, LinkedIn profile links, and job titles.

Sign-up for an account to get your API key: [hunter.io](https://hunter.io/)

#### Full Contact
Full Contact support is implemented only for their Company API at the moment, but support for the People API may come in the future. For now, this is used to build a company profile based on a target domain, such as the client's primary domain used for email and their website. Full Contact catalogues everything from website info and company logo(s) to website blurbs and social media profiles.

It's likely Full Contact will get some things wrong, such as number of employees. It's usually not *really* wrong, but the profile is meant to act as a snapshot to get you started.

Sign-up for an account to get your API key: [app.fullcontact.com](https://app.fullcontact.com/start/welcome)

#### AWS
Yes, Amazon Web Services. With an AWS IAM user's Access ID and Secret, the AWS API can be leveraged to do recon against AWS to find things like S3 buckets and accounts names and aliases. Account names are strings of numbers, so you will need some idea of what you're looking for there. Aliases, however, can be anything, like a company name, and those can be validated as existing or not.

By default, O.D.I.N. uses the client (`-c`) name and domain (`-d`) for searches. O.D.I.N. will search for the name with spaces stripped out, the domain with the TLD, and the domain without the TLD. An optional wordlist can be provided with `--aws`. Keywords can be anything, really. Consider assembling a list of related words or running a tool like `cEWL` to generate one.

Setup an IAM user on any Amazon account to get an Access ID and Secret.

## FAQ
**I get this syntax error. What's the deal?**

Please make sure you are using Python 3, not Python 2.7 or earlier. I don't write tools in Python 2.x and O.D.I.N. will not work when run with Python 2.x.

**I get an error when O.D.I.N. tries to import a library. What's wrong?**

Like above, please make sure you are using Python 3. O.D.I.N. must be run in Python 3 and the requirements must be installed using `pip` for Python 3. To ensure Python 3 is used, just in case your `pip` command are tied to another version, run this command: `python3 -m pip install -r requirements.txt`

**Why do you not like "why not" questions?**

If you ask "why not use X API," that's not very helpful. Presumably, the question is meant to convey the idea that X API would be a good addition and inquire about any reason it is not currently supported. The answer is most likely "I wasn't aware of this API." That also means I don't know anything about it.

If you have a suggestion for a service or API, please explain what it does and provide some details explaining why you think it would be a good addition.

**Why not add support for the Clearbit API?**

Clearbit looks useful for OSINT, but the free tier is restricted to 20 API calls in a month. That may even be 20 API calls for the life of the account. The details are unclear. Either way, that's very restrictive and I want O.D.I.N. to be as simple and free to use as possible. The paid tiers are quire expensive.

**Why not use Wappalyzer?**

Wappalyzer is useful, but it's very difficult to automate fetching the results from Wappalyzer. Some tools can do this, but they use an unmaintained package called wappalyzer-python (https://github.com/scrapinghub/wappalyzer-python). This package works, as far as I know, but there are several problems with it. The package has not been updated in three years, the developers have stated they have no plans to change that or support wappalyzer-python, and the package is Python 2. It could be used until it breaks one day, but the Python 2 bit is the real sticking point.

**Why not add support for the BuiltWith API?**

Like Clearbit, BuiltWith is a neat resource and some interesting details can be reviewed on the website. The API, however, is not free. The free version of the API won't give you any details, so at best it can be used to highlight a domain you may want to then review on the BuiltWith website. Scraping the website search results is certainly possible, but that could easily break and/or be unreliable.

Adding support for BuiltWith hasn't been ruled out, but the goal is to make O.D.I.N. entirely free to use.

**Why not use Full Contact's People API?**

Currently only the Company API is used. There are plans to incorproate the People API in the future.

**Why not use NetCraft?**

NetCraft is awesome, but it doesn't have an API. There are changes in the works to make use of web requests and BeautifulSoup to parse the results. This will come in a later release.

**Does O.D.I.N. perform DNS brute forcing?**

No, but it is being considered. However, brute forcing can take a long time and there are many tools that take care of this quite well. Those tools are not so easy to incorporate into O.D.I.N. without just running the commands for those tools. Look to Fierce and DNSRecon for this.

That does not mean more subdomain goodies are not coming. Some opportunities are being investigated and optional DNS brute forcing is probably happening in the future.

**I don't have X API key, can I still use O.D.I.N.?**

Absolutely. If an API key is missing from the keys.config file, any checks using those keys will be skipped. You are strongly encouraged to go get the free API keys to get the most out of O.D.I.N., but you can skip any you don't want.

### Special Thanks
A big thank you to a few contributors who gave me the OK to re-use some of their code:

* Ninjasl0th - Creator of the original scope verification script and all around cool dude!
* 0xF1 - Architect behind Cymon and a great guy to have on your team!
* GRC_Ninja - For providing great feedback regarding HTTP requests and RDAP.
* Troy Hunt - For giving me permission to use HaveIBeenPwned's REST API in this way.

And to these folks who have created/maintained some of the tools integrated into O.D.I.N.:

* Alton Johnson (altjx) - The creator of the original very cool [PyFOCA](https://github.com/altjx/ipwn) that exists here in its new Python 3 form as a part of O.D.I.N.
* Laramies - Creator of the awesome [TheHarvester](https://github.com/laramies/theHarvester).
* PaulSec - Creator of the unofficial API for the DNS Dumpster (https://github.com/PaulSec/API-dnsdumpster.com)
* Daniel Grzalek (Dagrz) - Creator of [aws_pwn](https://github.com/dagrz/aws_pwn) and the reason why I was able to build out AWS recon options. 
* TrullJ - For making the slick [SSL Labs Scanner module](https://github.com/TrullJ/ssllabs).
