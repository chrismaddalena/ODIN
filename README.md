# O.D.I.N. [BETA]
### Observe, Detect, and Investigate Networks

![O.D.I.N.](https://vignette3.wikia.nocookie.net/archer/images/4/46/ODINLogo.png/revision/latest/scale-to-width-down/250?cb=20170319051757)

>A Python tool for automating penetration testing work, like intelligence gathering, testing, and reporting. O.D.I.N. is still in active development and is not be fully functional. Feedback on issues is welcome!

> Note: O.D.I.N. is designed to be run on Linux. About 90% of it will absolutely work on Windows or MacOS with Python 3 and a copy of urlcrazy, but certain tools are Linux-only, like extract used for pulling metadata from non-PDF files. You'll be fine using an OS without these tools, but you'll see some warnings and get less information.

## Getting Started
1. Review the keys.config.sample file to fill-in your API keys and create a keys.config file.
2. `cd` into the /setup directory and run `setup_check.py` to make sure your keys.config file is in order.
3. Install any missing libraries by running pip with the requirements.txt file in the /setup directory: `pip install -r requirements.txt`

### Optional AWS Setup

If you'd like to have O.D.I.N. do recon against AWS you will need an IAM user account and the associated ID and Secret. Get this from your AWS console and setup your ~/.aws/credentials file. It needs to look like this:

~~~~
[default]
aws_access_key_id = xxxxxxxxxxxxxxxx
aws_secret_access_key = xyz+abc
~~~~

## What Can O.D.I.N. Do?
O.D.I.N. is still very much in development, but it aims to automate many of the common recon tasks carried out by penetration testers. Such as:
* Harvesting email addresses and employee names for a company.
* Collecting data on domains and IP addresses from Shodan, DNS, Censys, and whois/RDAP.
* Pulling DNS information for subdomains and related IP addresses.
* A whole lot more...

### The APIs and Services
O.D.I.N. uses several APIs to gather information. Some of these require an API key, but they're mostly free. That is to say, you can get a free key or pay for more requests/day. Shodan is a good example of this.

#### Whois and RDAP
Both of these services are used to collect data on domains and IP addresses. This includes attaching domains to IP addresses, identifying the network CIDRs for these addresses, and pulling information about the owners.

#### Shodan
Shodan is used to search for domains and lookup hosts (IP addresses). This pulls in information like open ports, banners, hostnames, and location data. Shodan also flags hosts for well known vulnerabilities like Heartbleed. This data is recorded as well, if it exists.

#### Censys
Censys is very much like Shodan, except less information about open ports/services is available. However, Censys also provides a way to search for certificates tied to a domain. This can be a *lot* of data, but you may find new hosts, like those tied to an employee's email address and used for a VPS in the cloud.

#### URLVoid
URLVoid offers reputation data for domains, including Alexa and Google rankings, domain age, and location data. It also keeps track of domains that have been flagged for malicious activity by various entities (e.g. Fortinet, Avira).

#### Twitter
If you setup a Twitter app for O.D.I.N., the tokens can be used with Tweepy and TheHarvester to not only locate Twitter handles tied to the provided domain but also collect account data (e.g. real name, location, follower count, and user description).

#### Cymon
eSentire's Cymon is used to check domains and IP addresses to see if the target appears in any of Cymon's collected threat intelligence feeds. This is used for reputation checks, but also used in combination with urlcrazy to check similar, registered domains to see if the domain or the domain's A-record IP addresses have been reported.

#### HaveIBeenPwned
Email addresses are checked against HIBP to determine if any email addresses for the organization have been mentioned in any pastes or been involved in any security breaches.

#### DNS Dumpster
DNS Dumpster is a cool project you can find at dnsdumpster.com. Subdomain information is collected from DNS Dumpster, including a neat domain map image!

#### EmailHunter
Meant for marketing folks to find leads and contacts at a company, this service offers free API keys for harvesting their contact information organizaed by company/domain. Hunter will return names, email addresses, phone numbers, Twitter handles, LinkedIn profile links, and job titles.

#### Full Contact
Full Contact support is implemented only for their Company API at the moment, but support for the People API may come in the future. For now, this is used to build a company profile based on a target domain, such as the client's primary domain used for email and their website. Full Contact catalogues everything from website info and company logo(s) to website blurbs and social media profiles.

#### AWS
Yes, Amazon Web Services. With an AWS IAM user's Access ID and Secret, the AWS API can be leveraged to do recon against AWS to find things like S3 buckets.

### Special Thanks
A big thank you to a few contributors who gave me the OK to re-use some of their code:
* Ninjasl0th - Creator of the original scope verification script and all around cool dude!
* 0xF1 - Architect behind Cymon and a great guy to have on your team!
* GRC_Ninja - For providing great feedback regarding HTTP requests and RDAP.
* Troy Hunt - For giving me permission to use HaveIBeenPwned's REST API in this way.

And to these folks who have created/maintained some of the tools integrated into O.D.I.N.:
* Alton Johnson (altjx) - The creator of the original very cool PyFOCA (https://github.com/altjx/ipwn) that exists here in its new Python 3 form as a part of O.D.I.N.
* Laramies - Creator of the awesome TheHarvester (https://github.com/laramies/theHarvester).
* PaulSec - Creator of the unofficial API for the DNS Dumpster (https://github.com/PaulSec/API-dnsdumpster.com)
* TrullJ - For making the slick SSL Labs Scanner module (https://github.com/TrullJ/ssllabs).
