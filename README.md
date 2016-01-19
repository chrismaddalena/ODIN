##Codename Viper

![Codename Viper](https://upload.wikimedia.org/wikipedia/en/8/8e/Cobra_Viper_Figure.jpg)

>A Python tool for automating penetration testing work, like intelligence gathering, testing, and reporting.

###Getting Started
Run the setup.py script in the /setup directory to walk through setup steps, like creation of directories and setup of API keys.

Then run setup_check.py to make sure everything is in order.

Install any missing libraries by running pip with the requirements.txt file in the /setup directory:

>pip install -r requirements.txt

###What Can Viper Do?
Viper is still very much in development, but it aims to automate many of the common tasks carried out by penetration testers. Such as:
* Email harvesting with theharvester.
* File discovery via goofile and Google Hacking.
* Investigating targets with DNS tools, urlcrazy, Shodan, and more.
* Actively scanning targets with nmap and masscan.
* Parsing scan results to find ports of interest and target them with tools like httpscreenshot and Nikto.
* Managing reports and files for tasks like joining multiple Nessus files and parsing Burp reports.
