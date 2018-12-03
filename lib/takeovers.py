#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains functions for analyzing domains and subdomains to determine if a domain
takeover is possible via dangling DNS records, cloud services, and various hosting providers.
"""

import re
from . import dns

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class TakeoverChecks(object):
    """Class with tools to check for potential domain and subdomain takeovers."""
    dns_toolkit = dns.DNSCollector()
    # Fingerprints for the various CDNs and services and associated 404 pages
    # Sources:
    # https://github.com/EdOverflow/can-i-take-over-xyz
    # https://github.com/Ice3man543/SubOver/blob/master/providers.json
    fingerprints = [
        {
            "name":"github", 
            "cname":["github.io", "github.map.fastly.net"], 
            "response":["There isn't a GitHub Pages site here.", "For root URLs (like http:\/\/example.com\/) you must provide an index.html file"]
        },
        {
            "name":"heroku", 
            "cname":["herokudns.com", "herokussl.com", "herokuapp.com"], 
            "response":["There's nothing here, yet.", "herokucdn.com/error-pages/no-such-app.html", "<title>No such app</title>"]
        },
        {
            "name":"unbounce",
            "cname":["unbouncepages.com"],
            "response":["The requested URL / was not found on this server.", "The requested URL was not found on this server"]
        },
        {
            "name":"tumblr",
            "cname":["tumblr.com"],
            "response":["There's nothing here.", "Whatever you were looking for doesn't currently exist at this address."]
        },
        {
            "name":"shopify",
            "cname":["myshopify.com"],
            "response":["Sorry, this shop is currently unavailable.", "Only one step left!"]
        },
        {
            "name":"instapage",
            "cname":["pageserve.co", "secure.pageserve.co", "https:\/\/instapage.com\/"],
            "response":["Looks Like You're Lost"]
        },
        {
            "name":"desk",
            "cname":["desk.com"],
            "response":["Please try again or try Desk.com free for 14 days.", "Sorry, We Couldn't Find That Page"]
        },
        {
            "name":"tictail",
            "cname":["tictail.com", "domains.tictail.com"],
            "response":["Building a brand of your own?", "to target URL: <a href=\"https:\/\/tictail.com", "Start selling on Tictail."]
        },
        {
            "name":"campaignmonitor",
            "cname":["createsend.com", "name.createsend.com"],
            "response":["Double check the URL", "<strong>Trying to access your account?</strong>", "Double check the URL or <a href=\"mailto:help@createsend.com"]
        },
        {
            "name":"cargocollective",
            "cname":["cargocollective.com"],
            "response":['<div class="notfound">']
        },
        {
            "name":"statuspage",
            "cname":["statuspage.io"],
            "response":["StatusPage.io is the best way for web infrastructure", "You are being <a href=\"https:\/\/www.statuspage.io\">redirected"]
        },
        {
            "name":"amazonaws",
            "cname":["amazonaws.com"],
            "response":["NoSuchBucket", "The specified bucket does not exist"]
        },
        {
            "name":"cloudfront",
            "cname":["cloudfront.net"],
            "response":["The request could not be satisfied", "ERROR: The request could not be satisfied"]
        },
        {
            "name":"bitbucket",
            "cname":["bitbucket.org"],	
            "response":["The Git solution for professional teams"]
        },
        {
            "name":"smartling",
            "cname":["smartling.com"],
            "response":["Domain is not configured"]
        },
        {
            "name":"acquia",
            "cname":["acquia.com"],
            "response":["If you are an Acquia Cloud customer and expect to see your site at this address"]
        },
        {
            "name":"fastly",
            "cname":["fastly.net"],
            "response":["Please check that this domain has been added to a service", "Fastly error: unknown domain"]
        },
        {
            "name":"pantheon",
            "cname":["pantheonsite.io"],
            "response":["The gods are wise", "The gods are wise, but do not know of the site which you seek."]
        },
        {
            "name":"zendesk",
            "cname":["zendesk.com"],
            "response":["<title>Help Center Closed | Zendesk</title>", "Help Center Closed"]
        },
        {
            "name":"uservoice",
            "cname":["uservoice.com"],
            "response":["This UserVoice subdomain is currently available!", "This UserVoice instance does not exist."]
        },
        {
            "name":"ghost",
            "cname":["ghost.io"],
            "response":["The thing you were looking for is no longer here", "The thing you were looking for is no longer here, or never was"]
        },
        {
            "name":"pingdom",
            "cname":["stats.pingdom.com"],
            "response":["pingdom"]
        },
        {
            "name":"tilda",
            "cname":["tilda.ws"],
            "response":["Domain has been assigned", "http:\/\/tilda.ws\/img\/logo404.png"]
        },
        {
            "name":"wordpress",
            "cname":["wordpress.com"],	
            "response":["Do you want to register"]
        },
        {
            "name":"teamwork",
            "cname":["teamwork.com"],
            "response":["Oops - We didn't find your site."]
        },
        {
            "name":"helpjuice",
            "cname":["helpjuice.com"],
            "response":["We could not find what you're looking for."]
        },
        {
            "name":"helpscout",
            "cname":["helpscoutdocs.com"],
            "response":["No settings were found for this company:"]
        },
        {
            "name":"cargo",
            "cname":["cargocollective.com"],
            "response":["If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel."]
        },
        {
            "name":"feedpress",
            "cname":["redirect.feedpress.me"],
            "response":["The feed has not been found."]
        },
        {
            "name":"surge",
            "cname":["surge.sh"],
            "response":["project not found"]
        },
        {
            "name":"surveygizmo",
            "cname":["privatedomain.sgizmo.com", "privatedomain.surveygizmo.eu", "privatedomain.sgizmoca.com"],
            "response":["data-html-name"]
        },
        {
            "name":"mashery",
            "cname":["mashery.com"],
            "response":["Unrecognized domain <strong>"]
        },
        {
            "name":"intercom",
            "cname":["custom.intercom.help"],
            "response":["This page is reserved for artistic dogs.","<h1 class=\"headline\">Uh oh. That page doesn’t exist.</h1>"]
        },
        {
            "name":"webflow",
            "cname":["proxy.webflow.io"],
            "response":["<p class=\"description\">The page you are looking for doesn't exist or has been moved.</p>"]
        },
        {
            "name":"kajabi",
            "cname":["endpoint.mykajabi.com"],
            "response":["<h1>The page you were looking for doesn't exist.</h1>"]
        },
        {
            "name":"thinkific",
            "cname":["thinkific.com"],
            "response":["You may have mistyped the address or the page may have moved."]
        },
        {
            "name":"tave",
            "cname":["clientaccess.tave.com"],
            "response":["<h1>Error 404: Page Not Found</h1>"]
        },
        {
            "name":"wishpond",
            "cname":["wishpond.com"],   
            "response":["https:\/\/www.wishpond.com\/404\?campaign=true"]
        },
        {
            "name":"aftership",
            "cname":["aftership.com"],
            "response":["Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist."]
        },
        {
            "name":"aha",
            "cname":["ideas.aha.io"],
            "response":["There is no portal here ... sending you back to Aha!"]
        },
        {
            "name":"brightcove",
            "cname":["brightcovegallery.com", "gallery.video", "bcvp0rtal.com"],
            "response":["<p class=\"bc-gallery-error-code\">Error Code: 404</p>"]
        },
        {
            "name":"bigcartel",
            "cname":["bigcartel.com"],
            "response":["<h1>Oops! We couldn&#8217;t find that page.</h1>"]
        },
        {
            "name":"activecompaign",
            "cname":["activehosted.com"],
            "response":["alt=\"LIGHTTPD - fly light.\""]
        },
        {
            "name":"acquia",
            "cname":["acquia-test.co"],
            "response":["The site you are looking for could not be found."]
        },
        {
            "name":"proposify",
            "cname":["proposify.biz"],
            "response":["If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz"]
        },
        {
            "name":"simplebooklet",
            "cname":["simplebooklet.com"],
            "response":["We can't find this <a href=\"https:\/\/simplebooklet.com", "First Impressions Count"]
        },
        {
            "name":"getresponse",
            "cname":[".gr8.com"],
            "response":["With GetResponse Landing Pages, lead generation has never been easier"]
        },
        {
            "name":"vend",
            "cname":["vendecommerce.com"],
            "response":["Looks like you've traveled too far into cyberspace."]
        },
        {
            "name":"jetbrains",
            "cname":["myjetbrains.com"],
            "response":["is not a registered InCloud YouTrack."]
        },
        {
            "name":"azure",
            "cname":["azurewebsites.net"],
            "response":["404 Web Site not found"]
        }
    ]

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        pass

    def check_domain_fronting(self,domain):
        """Check the A records for a given domain to look for references to various CDNs and
        flag the domain for domain frontability.

        Many CDN keywords provided by Rvrsh3ll on GitHub:
        https://github.com/rvrsh3ll/FindFrontableDomains

        Parameters:
        domain      The domain or subdomain to check
        """
        domain = domain.strip()
        try:
            # Get the A record(s) for the domain
            query = self.dns_toolkit.get_dns_record(domain,"A")
            # Look for records matching known CDNs
            for item in query.response.answer:
                for text in item.items:
                    target = text.to_text()
                    if "s3.amazonaws.com" in target:
                        return "S3 Bucket: {}".format(target)
                    if "cloudfront" in target:
                        return "Cloudfront: {}".format(target)
                    elif "appspot.com" in target:
                        return "Google: {}".format(target)
                    elif "googleplex.com" in target:
                        return "Google: {}".format(target)
                    elif "msecnd.net" in target:
                        return "Azure: {}".format(target)
                    elif "aspnetcdn.com" in target:
                        return "Azure: {}".format(target)
                    elif "azureedge.net" in target:
                        return "Azure: {}".format(target)
                    elif "a248.e.akamai.net" in target:
                        return "Akamai: {}".format(target)
                    elif "secure.footprint.net" in target:
                        return "Level 3: {}".format(target)
                    elif "cloudflare" in target:
                        return "Cloudflare: {}".format(target)
                    elif "unbouncepages.com" in target:
                        return "Unbounce: {}".format(target)
                    elif "secure.footprint.net" in target:
                        return "Level 3: {}".format(target)
                    else:
                        return False
        except Exception:
            return False
    
    def check_domain_takeover(self,domain):
        """Check the web response for a domain and compare it against fingerprints to identify
        responses that could indicate a domain takeover is possible.

        Parameters:
        domain      The domain or subdomain to check
        """
        domain = domain.strip()
        try:
            session = requests.session()
            request = session.get('https://' + domain.strip(),verify=False,timeout=10)
            for indentifier in self.fingerprints:
                for item in indentifier['response']:
                    take_reg = re.compile(item)
                    temp = take_reg.findall(request.text)
                    if temp != []:
                        return indentifier['name'].capitalize()
        except Exception as e:
                pass
        return False
