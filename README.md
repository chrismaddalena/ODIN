##Codename Viper

![Codename Viper](https://upload.wikimedia.org/wikipedia/en/8/8e/Cobra_Viper_Figure.jpg)

>A Python tool for automating penetration testing work, like intelligence gathering, testing, and reporting.

###Special Thanks
A big thank you to a few contributors who gave me the OK to re-use some of their code:

Ninjasl0th - Creator of the original scope verification script and all around cool dude!

0xF1 - Creator of the original JoiNessus tool and a great guy to have on your team!

And to these folks who have maintained and offered some of the tools used by Viper:

Laramies - Creator of the awesome TheHarvester (https://github.com/laramies/theHarvester)!

TrullJ - For making the slick SSL Labs Scanner module (https://github.com/TrullJ/ssllabs)!

###Getting Started
Run the setup.py script in the /setup directory to walk through setup steps, like creation of directories and setup of API keys.

Then run setup_check.py to make sure everything is in order.

Install any missing libraries by running pip with the requirements.txt file in the /setup directory:

>pip install -r requirements.txt

###What Can Viper Do?
Viper is still very much in development, but it aims to automate many of the common tasks carried out by penetration testers. Such as:
* Email harvesting with theharvester.
* File discovery via Google Hacking.
* Investigating targets with DNS tools, urlcrazy, Shodan, and more.
* Actively scanning targets with nmap and masscan.
* Parsing scan results to find ports of interest and target them with tools like EyeWitness.
* Managing reports and files for tasks like joining multiple Nessus files and parsing Burp reports.
