## O.D.I.N.
### Observe, Detect, and Investigate networks

![O.D.I.N.](https://vignette3.wikia.nocookie.net/archer/images/4/46/ODINLogo.png/revision/latest/scale-to-width-down/250?cb=20170319051757)

>A Python tool for automating penetration testing work, like intelligence gathering, testing, and reporting.

>This version of O.D.I.N. is still in active development and may not be fully functional.

### Special Thanks
A big thank you to a few contributors who gave me the OK to re-use some of their code:

Ninjasl0th - Creator of the original scope verification script and all around cool dude!

0xF1 - Creator of the original JoiNessus tool and a great guy to have on your team!

GRC_Ninja - For providing great feedback regarding HTTP requests and RDAP.

And to these folks who have maintained and offered some of the tools used by O.D.I.N.:

Laramies - Creator of the awesome TheHarvester (https://github.com/laramies/theHarvester)!

TrullJ - For making the slick SSL Labs Scanner module (https://github.com/TrullJ/ssllabs)!

### Getting Started
Run the setup.py script in the /setup directory to setup of API keys.

Then run setup_check.py to make sure everything is in order.

Install any missing libraries by running pip with the requirements.txt file in the /setup directory:

>pip install -r requirements.txt

### What Can O.D.I.N. Do?
O.D.I.N. is still very much in development, but it aims to automate many of the common tasks carried out by penetration testers. Such as:
* Email harvesting with theharvester.
* File discovery via Google Hacking.
* Investigating targets with DNS tools, urlcrazy, Shodan, and more.
* Actively scanning targets with nmap and masscan.
* Parsing scan results to find ports of interest and target them with tools like EyeWitness.
* Managing reports and files for tasks like joining multiple Nessus files and parsing Burp reports.
