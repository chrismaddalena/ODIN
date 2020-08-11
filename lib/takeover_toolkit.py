#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains functions for analyzing domains and subdomains to determine if a domain
takeover is possible via dangling DNS records, cloud services, and various hosting providers.

Original Sources:
    https://github.com/EdOverflow/can-i-take-over-xyz
    https://github.com/Ice3man543/SubOver/blob/master/providers.json
"""

import asyncio
import logging
import re

import aiohttp
from aiohttp import ClientSession

logger = logging.getLogger(__name__)


class TakeoverChecks(object):
    """Review domain names for potential domain fronts, takeovers, and other issues."""

    # Fingerprints for the various CDNs and services and associated 404 pages
    fingerprints = [
        {
            "name": "readme",
            "cname": ["readme.io"],
            "response": [
                "<h1>Not Yet Active</h1>",
                "<p>The creators of this project are still working on making everything perfect!</p>",
            ],
        },
        {
            "name": "github",
            "cname": ["github.io", "github.map.fastly.net"],
            "response": [
                "There isn't a GitHub Pages site here.",
                "For root URLs (like http:\/\/example.com\/) you must provide an index.html file",
            ],
        },
        {
            "name": "heroku",
            "cname": ["herokudns.com", "herokussl.com", "herokuapp.com"],
            "response": [
                "There's nothing here, yet.",
                "herokucdn.com/error-pages/no-such-app.html",
                "<title>No such app</title>",
            ],
        },
        {
            "name": "unbounce",
            "cname": ["unbouncepages.com"],
            "response": [
                "The requested URL / was not found on this server.",
                "The requested URL was not found on this server",
            ],
        },
        {
            "name": "tumblr",
            "cname": ["tumblr.com"],
            "response": [
                "There's nothing here.",
                "Whatever you were looking for doesn't currently exist at this address.",
            ],
        },
        {
            "name": "shopify",
            "cname": ["myshopify.com"],
            "response": [
                "Sorry, this shop is currently unavailable.",
                "Only one step left!",
            ],
        },
        {
            "name": "campaignmonitor",
            "cname": ["createsend.com", "name.createsend.com"],
            "response": [
                "Double check the URL",
                "<strong>Trying to access your account?</strong>",
                'Double check the URL or <a href="mailto:help@createsend.com',
            ],
        },
        {
            "name": "cargocollective",
            "cname": ["cargocollective.com"],
            "response": [
                '<div class="notfound">',
                "If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel.",
            ],
        },
        {
            "name": "statuspage",
            "cname": ["statuspage.io"],
            "response": [
                "StatusPage.io is the best way for web infrastructure",
                'You are being <a href="https:\/\/www.statuspage.io">redirected',
            ],
        },
        {
            "name": "amazonaws",
            "cname": ["amazonaws.com"],
            "response": ["NoSuchBucket", "The specified bucket does not exist"],
        },
        {
            "name": "bitbucket",
            "cname": ["bitbucket.org"],
            "response": [
                "The Git solution for professional teams",
                "Repository not found",
            ],
        },
        {
            "name": "fastly",
            "cname": ["fastly.net"],
            "response": [
                "Please check that this domain has been added to a service",
                "Fastly error: unknown domain",
            ],
        },
        {
            "name": "pantheon",
            "cname": ["pantheonsite.io"],
            "response": [
                "The gods are wise",
                "The gods are wise, but do not know of the site which you seek.",
            ],
        },
        {
            "name": "uservoice",
            "cname": ["uservoice.com"],
            "response": [
                "This UserVoice subdomain is currently available!",
                "This UserVoice instance does not exist.",
            ],
        },
        {
            "name": "ghost",
            "cname": ["ghost.io"],
            "response": [
                "The thing you were looking for is no longer here",
                "The thing you were looking for is no longer here, or never was",
            ],
        },
        {
            "name": "tilda",
            "cname": ["tilda.ws"],
            "response": [
                "Domain has been assigned",
                "http:\/\/tilda.ws\/img\/logo404.png",
            ],
        },
        {
            "name": "wordpress",
            "cname": ["wordpress.com"],
            "response": ["Do you want to register"],
        },
        {
            "name": "helpjuice",
            "cname": ["helpjuice.com"],
            "response": ["We could not find what you're looking for."],
        },
        {
            "name": "helpscout",
            "cname": ["helpscoutdocs.com"],
            "response": ["No settings were found for this company:"],
        },
        {
            "name": "feedpress",
            "cname": ["redirect.feedpress.me"],
            "response": ["The feed has not been found."],
        },
        {"name": "surge", "cname": ["surge.sh"], "response": ["project not found"]},
        {
            "name": "mashery",
            "cname": ["mashery.com"],
            "response": ["Unrecognized domain <strong>"],
        },
        {
            "name": "webflow",
            "cname": ["proxy.webflow.io"],
            "response": [
                '<p class="description">The page you are looking for doesn\'t exist or has been moved.</p>'
            ],
        },
        {
            "name": "jetbrains",
            "cname": ["myjetbrains.com"],
            "response": ["is not a registered InCloud YouTrack."],
        },
        {
            "name": "azure",
            "cname": ["azurewebsites.net"],
            "response": ["404 Web Site not found"],
        },
    ]

    def __init__(self):
        pass

    def check_domain_fronting(self, dns_record: str) -> dict:
        """
        Check a DNS record for references to Fastly, AWS S3 buckets, and Cloudflare.

        **Parameters**

        ``record``
            DNS record from to check
        """
        # Prepare the results dict
        result = {"result": False}

        temp = []
        if isinstance(dns_record, list):
            for record in dns_record:
                temp.append(record)
        else:
            temp.append(dns_record)

        # Look for records matching known CDNs
        for record in temp:
            if "s3.amazonaws.com" in record:
                result = {"result": True, "service": "s3", "record": record}
            elif "cloudflare" in record:
                result = {"result": True, "service": "cloudflare", "record": record}
            elif "fastly" in record:
                result = {"result": True, "service": "fastly", "record": record}
            else:
                return result

    async def _fetch_html(self, url: str, session: ClientSession, **kwargs) -> str:
        """
        Execute a web request and collect the HTML for analysis.

        **Parameters**

        ``url``
            URL for the web request

        ``session``
            ClientSession to use for the web request
        """
        response = await session.request(method="GET", url=url, **kwargs)
        html = await response.text()
        return html

    async def _analyze_response(
        self, domain: str, session: ClientSession, **kwargs
    ) -> dict:
        """
        Perform asynchronous web requests and check response against fingerprints to identify
        responses that could indicate a domain takeover is possible.

        **Parameters**

        ``domain``
            The domain or subdomain to check

        ``session``
            ClientSession to use for the web request

        Will pass additional kwargs to ClientSession (e.g., ssl=False)
        """
        # Prepare the results dictionary
        result = {}
        result[domain] = {}
        result[domain]["domain"] = domain
        result[domain]["result"] = False

        # Append HTTPS:// to the domain – these services use (or redirdct to) HTTPS
        domain = domain.strip()
        url = "https://" + domain
        result[domain]["test_url"] = url

        # Try fetching tthe HTML and checking it for identifiers
        try:
            html = await self._fetch_html(url=url, session=session, **kwargs)
        except (aiohttp.ClientError, aiohttp.http_exceptions.HttpProcessingError,) as e:
            logger.debug(
                "Encountered an aiohttp exception for %s [%s]: %s",
                url,
                getattr(e, "status", None),
                getattr(e, "message", None),
            )
            return result
        except Exception as e:
            logger.debug(
                "General exception occured while checking %s:  %s",
                url,
                getattr(e, "__dict__", {}),
            )
            return result
        else:
            for indentifier in self.fingerprints:
                for item in indentifier["response"]:
                    take_reg = re.compile(item)
                    temp = take_reg.findall(html)
                    if temp != []:
                        result[domain]["result"] = True
                        result[domain]["service"] = indentifier["name"].capitalize()
        return result

    async def check_domain_takeover(
        self, domain: str, session: ClientSession, **kwargs
    ) -> dict:
        """
        Check a domain's response to a web request for indicators it is vulnerable to takeover.

        **Parameters**

        ``domain``
            The domain or subdomain to check

        ``session``
            ClientSession to use for the web request

        Will pass additional kwargs to ClientSession (e.g., ssl=False)
        """
        logger.info("Checking takeover opportunities for %s", domain)
        result = await self._analyze_response(domain=domain, session=session, **kwargs)
        return result
