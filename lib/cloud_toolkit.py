#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains functions for brute forcing bucket names for Amazon Web Services and Digital
Ocean. If a bucket is found, the bucket is checked for public access.
"""


import asyncio
import logging
import re
from asyncio import Semaphore

import boto3
import click
import requests
from botocore.exceptions import ClientError, EndpointConnectionError

import aiohttp
from aiohttp import ClientSession

logger = logging.getLogger(__name__)


class BucketHunter(object):
    """Hunt buckets in AWS and Digital Ocean."""

    def __init__(self, timeout=10, concurrent_limit=15):
        # Test connecting to a test S3 bucket with the credentials supplied to `aws configure`
        self.timeout = timeout
        self.semaphore = Semaphore(value=15)
        try:
            self.boto3_client = boto3.client("s3")
            self.boto3_client.head_bucket(Bucket="hostmenow")
        except Exception:
            self.boto3_client = None
            logger.warning(
                "Could not authenticate to AWS with secrets provided to `awsconfigure`"
            )

    def generate_wordlst(
        self, client: str, domain: str, wordlist=None, fix_wordlist=None
    ) -> list:
        """
        Generate a wordlist suitable for hunting cloud storage containers.

        Wordlists may have comments that begin with a #.

        **Parameters**

        ``client``
            Name of the client organization (for wordlist generation)

        ``domain``
            Organization's domain name (for wordlist generation)

        ``wordlist``
            Optional user-provided wordlist

        ``fix_wordlist``
            Optional user-provided list of prefixes and suffixes
        """
        # Take the user input as the initial list of keywords here
        # Both example.com and example are valid bucket names, so domain+tld and domain are tried
        search_terms = [domain, domain.split(".")[0], client.replace(" ", "").lower()]
        # Potentially valid and interesting keywords that might be used as a prefix or suffix
        fixes = [
            "apps",
            "downloads",
            "software",
            "deployment",
            "qa",
            "dev",
            "test",
            "vpn",
            "secret",
            "user",
            "confidential",
            "invoice",
            "config",
            "backup",
            "bak",
            "backups",
            "xls",
            "csv",
            "ssn",
            "resources",
            "web",
            "testing",
            "uac",
            "uat",
            "legacy",
            "adhoc",
            "docs",
            "documents",
            "res",
            "nas",
        ]
        # Add user-provided wordlist terms to our list of search terms
        if wordlist is not None:
            with open(wordlist, "r") as bucket_list:
                for name in bucket_list:
                    name = name.strip()
                    if name and not name.startswith("#"):
                        search_terms.append(name)
        # Incorporate user-provided list of fixes
        if fix_wordlist is not None:
            with open(fix_wordlist, "r") as new_fixes:
                for fix in new_fixes:
                    fix = fix.strip()
                    if fix and not fix.startswith("#"):
                        fixes.append(fix)
        # Modify search terms with some common prefixes and suffixes
        # We use this new list to avoid endlessly looping
        final_search_terms = []
        for fix in fixes:
            for term in search_terms:
                final_search_terms.append(fix + "-" + term)
                final_search_terms.append(term + "-" + fix)
                final_search_terms.append(fix + "." + term)
                final_search_terms.append(term + "." + fix)
                final_search_terms.append(fix + term)
                final_search_terms.append(term + fix)
        # Now include our original list of base terms
        for term in search_terms:
            final_search_terms.append(term)
        # Ensure we have only unique search terms in our list and start hunting
        final_search_terms = list(set(final_search_terms))
        return final_search_terms

    def enumerate_buckets(self, wordlist: list):
        """
        Search for AWS S3 buckets and Digital Ocean Spaces. Default search terms are the
        client, domain, and domain without its TLD.

        This is based on modules from aws_pwn by Dagrz on GitHub.

        **Parameters**

        ``wordlist``
            List of possible bucket names to check
        """
        bucket_results = []
        # Check for buckets and spaces
        for term in wordlist:
            logger.info("Checking AWS for an S3 bucket named %s", term)
            if self.boto3_client:
                result = self.validate_bucket("head", term)
                bucket_results.append(result)
        return bucket_results

    def validate_bucket(self, validation_type, bucket_name):
        """
        Used by `validate_bucket_head()` to validate an AWS bucket name.

        **Parameters**

        ``validation_type``
            Web request type to use for validation, e.g. head
        ``bucket_name```
            Bucket name to check
        """
        validation_functions = {"head": self.validate_bucket_head}
        if validation_functions[validation_type]:
            return validation_functions[validation_type](bucket_name)

    def validate_bucket_head(self, bucket_name):
        """
        Check a string to see if it exists as the name of an Amazon S3 bucket. This version uses
        awscli to identify a bucket and then uses Requests to check public access. The benefit of
        this is awscli will gather information from buckets that are otherwise inaccessible via
        anonymous web requests.

        This test requires authentication. Check credentials before use!

        **Parameters**

        `bucket_name`
            Bucket name to validate
        """
        error_values = {"400": True, "403": True, "404": False}
        result = {
            "bucketName": bucket_name,
            "bucketUri": "http://" + bucket_name + ".s3.amazonaws.com",
            "arn": "arn:aws:s3:::" + bucket_name,
            "exists": False,
            "public": False,
        }
        try:
            self.boto3_client.head_bucket(Bucket=bucket_name)
            result["exists"] = True
            try:
                # Request the bucket to check the response
                request = requests.get(result["bucketUri"], timeout=self.timeout)
                # All bucket names will get something, so look for the NoSuchBucket status
                if "NoSuchBucket" in request.text:
                    result["exists"] = False
                else:
                    result["exists"] = True
                # Check for a 200 OK to indicate a publicly listable bucket
                if request.status_code == 200:
                    result["public"] = True
                    logger.info("Found a public bucket: %s", result["bucketName"])
            except requests.exceptions.RequestException:
                result["exists"] = False
        except ClientError as e:
            result["exists"] = error_values[e.response["Error"]["Code"]]
        except EndpointConnectionError as e:
            logger.warning(
                "Could not connect to a bucket to check it – seeing this repeatedly might mean your awscli region is misconfigured: %s",
                getattr(e, "__dict__", {}),
            )
            result["exists"] = error
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
        return html, response.status

    async def _analyze_response(
        self, space_name: str, region: str, session: ClientSession, **kwargs
    ) -> dict:
        """
        Check a string to see if it exists as the name of a Digital Ocean Space.

        **Parameters**

        ``region``
            Digital Ocean region to use for the URL

        ``space_name``
            Name of the Space to validate
        """
        space_uri = "https://" + space_name + "." + region + ".digitaloceanspaces.com"
        result = {
            "bucketName": space_name,
            "bucketUri": space_uri,
            "arn": "arn:do:space:::" + space_name,
            "exists": False,
            "public": False,
        }
        try:
            logger.info("Checking Digital Ocean Space %s in %s", space_name, region)
            await self.semaphore.acquire()
            # Request the Space to check the response
            html, status = await self._fetch_html(
                url=space_uri, session=session, **kwargs
            )
        except (aiohttp.ClientError, aiohttp.http_exceptions.HttpProcessingError,) as e:
            logger.debug(
                "Encountered an aiohttp exception for %s [%s]: %s",
                space_uri,
                getattr(e, "status", None),
                getattr(e, "message", None),
            )
            return result
        except Exception as e:
            logger.debug(
                "General exception occured while checking %s:  %s",
                space_uri,
                getattr(e, "__dict__", {}),
            )
            return result
        else:
            # All Space names will get something, so look for the NoSuchBucket status
            if "NoSuchBucket" in html:
                result["exists"] = False
            else:
                result["exists"] = True
            # Check for a 200 OK to indicate a publicly listable Space
            if status == 200:
                result["public"] = True
        self.semaphore.release()
        return result

    async def check_space(
        self, space_name: str, region: str, session: ClientSession, **kwargs
    ):
        """

        """
        result = await self._analyze_response(
            space_name=space_name, region=region, session=session
        )
        return result
