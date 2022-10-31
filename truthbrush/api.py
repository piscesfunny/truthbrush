import configparser
from time import sleep
from typing import Any, Iterator, Optional, Generator
from loguru import logger
from requests.sessions import HTTPAdapter
from dateutil import parser as date_parse
from datetime import datetime, timezone, date
from urllib3 import Retry
import requests
import json
import logging
import os
from scrapingbee import ScrapingBeeClient

BASE_URL = "https://truthsocial.com"
API_BASE_URL = "https://truthsocial.com/api"
USER_AGENT = "TruthSocial/71 CFNetwork/1331.0.7 Darwin/21.4.0"

# Oauth client credentials, from https://truthsocial.com/packs/js/application-e63292e218e83e726270.js
CLIENT_ID = "9X1Fdd-pxNsAgEDNi_SfhJWi8T-vLuV2WVzKIbkTCw4"
CLIENT_SECRET = "ozF8jzI4968oTKFkEnsBC-UbLPCdrSv0MkXGQu2o_-M"

proxies = {"http": os.getenv("http_proxy"), "https": os.getenv("https_proxy")}

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCRAPER_API_BASE_URL = "http://api.scraperapi.com"


class LoginErrorException(Exception):
    pass


class TruthSocialClient:
    def __init__(self, username: str = None, password: str = None, profile_section="main",
                 config_fpath: str = None):
        self.ratelimit_max = 300
        self.ratelimit_remaining = None
        self.ratelimit_reset = None
        self.user_account = username
        self.user_password = password
        self.access_token = ""
        self.scrapping_bee_api_key = ""
        self.headers: dict = {}

        self.profile_section = profile_section
        self.headers_section = 'headers'
        if config_fpath:
            self.config_fpath = config_fpath
        else:
            self.config_fpath = self.default_config()

        if not self.user_account or not self.user_password:
            self.load_credentials()

        self.load_headers()

        self.api_client = ScrapingBeeClient(api_key=self.scrapping_bee_api_key)

    @staticmethod
    def default_config():
        """
        Default config file path
        """
        return os.path.join(ROOT_DIR, "truthbrush/config", "truthsocial.ini")

    def load_credentials(self):
        """
        Attempt to load gab info from config file
        """
        config_file_path = self.config_fpath
        profile_section = self.profile_section
        logging.info(f"loading profile {profile_section} from config {config_file_path}")

        if not config_file_path or not os.path.isfile(config_file_path):
            return {}

        config = configparser.ConfigParser()
        config.read(config_file_path)

        if profile_section not in config.sections():
            return {}

        data = {}
        for key in ['user_account', 'user_password', 'scrapping_bee_api_key']:
            try:
                setattr(self, key, config.get(profile_section, key))
            except configparser.NoSectionError:
                logging.error(f"no such profile {profile_section} in {config_file_path}")
            except configparser.NoOptionError:
                logging.error(f"missing {key} from profile {profile_section} in {config_file_path}")
        return data

    def load_headers(self):
        config = configparser.ConfigParser()
        config.read(self.config_fpath)
        if self.headers_section not in config.sections():
            user_agent = USER_AGENT
            authorization = 'Bearer '
        else:
            user_agent = config.get('headers', 'user-agent')
            authorization = config.get('headers', 'authorization')

        headers = {
            'user-agent': user_agent,
            'authorization': authorization
        }

        setattr(self, 'headers', headers)

        access_token = authorization.replace("Bearer ", "")
        setattr(self, 'access_token', access_token)

    def save_headers(self):
        """
        Save headers in the config file
        """
        if not self.config_fpath:
            return
        config = configparser.ConfigParser()
        config.read(self.config_fpath)
        if self.headers_section not in config.sections():
            config.add_section(self.headers_section)

        for k, v in self.headers.items():
            config.set(self.headers_section, k, v)

        with open(self.config_fpath, 'w') as config_file:
            config.write(config_file)

    def validate_access_token(self, url):
        r = requests.get(url, headers=self.headers)
        if r.status_code > 399:
            self.access_token = ""
        else:
            self.access_token = self.headers.get("authorization", "").replace("Bearer ", "")

    def __check_login(self):
        """Runs before any login-walled function to check for login credentials and generates an auth ID token"""
        if self.user_account is None:
            raise LoginErrorException("Username is missing.")
        if self.user_password is None:
            raise LoginErrorException("Password is missing.")
        if self.access_token == "":
            self.access_token = self.get_access_token(self.user_account, self.user_password)
            self.headers["authorization"] = f"Bearer {self.access_token}"
            self.save_headers()

    def _make_session(self):
        s = requests.Session()
        s.proxies.update(proxies)
        retries = Retry(
            total=10,
            backoff_factor=0.5,
            status_forcelist=[413, 429, 503, 403, 500, 501, 502, 503, 504, 524],
        )
        s.mount("http://", HTTPAdapter(max_retries=retries))
        s.mount("https://", HTTPAdapter(max_retries=retries))
        return s

    def _check_ratelimit(self, resp):
        if resp.headers.get("x-ratelimit-limit") is not None:
            self.ratelimit_max = int(resp.headers.get("x-ratelimit-limit"))
        if resp.headers.get("x-ratelimit-remaining") is not None:
            self.ratelimit_remaining = int(resp.headers.get("x-ratelimit-remaining"))
        if resp.headers.get("x-ratelimit-reset") is not None:
            self.ratelimit_reset = date_parse.parse(
                resp.headers.get("x-ratelimit-reset")
            )

        if (
            self.ratelimit_remaining is not None and self.ratelimit_remaining <= 50
        ):  # We do 50 to be safe; their tracking is a bit stochastic... it can jump down quickly
            now = datetime.utcnow().replace(tzinfo=timezone.utc)
            time_to_sleep = (
                self.ratelimit_reset.replace(tzinfo=timezone.utc) - now
            ).total_seconds()
            logger.warning(
                f"Approaching rate limit; sleeping for {time_to_sleep} seconds..."
            )
            sleep(time_to_sleep)

    def _get(self, url: str, params: dict = None) -> Any:
        full_url = API_BASE_URL + url
        params = {"render_js": 'False', 'premium_proxy': 'True'}
        headers = {
            "Accept": "application/json, text/plain, */*",
            'Authorization': "Bearer " + self.access_token
        }

        # resp = requests.get(
        #     SCRAPER_API_BASE_URL,
        #     params=payload,
        #     headers={
        #         "authorization": "Bearer " + self.access_token,
        #         "user-agent": USER_AGENT,
        #     },
        # )

        resp = self.api_client.get(full_url, params=params, headers=headers)

        logging.info(f"url - {url}")
        # Will also sleep
        self._check_ratelimit(resp)

        return resp.json()

    def _get_paginated(self, url: str, params: dict = None, resume: str = None) -> Any:
        next_link = API_BASE_URL + url

        if resume is not None:
            next_link += f"?max_id={resume}"

        while next_link is not None:
            resp = self._make_session().get(
                next_link,
                params=params,
                headers={
                    "authorization": "Bearer " + self.access_token,
                    "user-agent": USER_AGENT,
                },
            )

            next_link = resp.links.get("next", {}).get("url")
            logger.info(f"Next: {next_link}, resp: {resp}, headers: {resp.headers}")
            yield resp.json()

            # Will also sleep
            self._check_ratelimit(resp)

    def lookup(self, user_handle: str = None) -> dict:
        """Lookup a user's information."""

        self.__check_login()
        assert user_handle is not None
        return self._get("/v1/accounts/lookup", params=dict(acct=user_handle))

    def search(
        self,
        searchtype: str = None,
        query: str = None,
        limit: int = 40,
        resolve: int = 4,
        offset: int = 0,
        min_id: str = "0",
        max_id: str = None,
    ) -> Optional[Generator]:
        """Search users, statuses or hashtags."""

        self.__check_login()
        assert query is not None and searchtype is not None

        page = 0
        while page < limit:

            if max_id is None:
                resp = self._get(
                    "/v2/search",
                    params=dict(
                        q=query,
                        resolve=resolve,
                        limit=limit,
                        type=searchtype,
                        offset=offset,
                        min_id=min_id,
                    ),
                )

            else:

                resp = self._get(
                    "/v2/search",
                    params=dict(
                        q=query,
                        resolve=resolve,
                        limit=limit,
                        type=searchtype,
                        offset=offset,
                        min_id=min_id,
                        max_id=max_id,
                    ),
                )

            offset += 40
            if not resp[searchtype]:
                break

            yield resp

    def trending(self):
        """Return trending truths."""

        self.__check_login()
        return self._get("/v1/truth/trending/truths")

    def tags(self):
        """Return trending tags."""

        self.__check_login()
        return self._get("/v1/trends")

    def suggested(self, maximum: int = 50) -> dict:
        """Return a list of suggested users to follow."""

        self.__check_login()
        return self._get(f"/v2/suggestions?limit={maximum}")

    def ads(self, device: str = "desktop") -> dict:
        """Return a list of ads from Rumble's Ad Platform via Truth Social API."""

        return self._get(f"/v1/truth/ads?device={device}")

    def data_by_tag(self, tag, max_id=None):
        """Return a list of truths with a specific hashtag."""

        url = f"/v1/timelines/tag/{tag}"
        if max_id:
            url += f"?max_id={max_id}"

        self.__check_login()
        return self._get(url)

    def home(self, max_id=None):
        url = "/v1/timelines/home"
        if max_id:
            url += f"?max_id={max_id}"

        self.__check_login()
        return self._get(url)

    def user_followers(
        self,
        user_handle: str = None,
        user_id: str = None,
        maximum: int = 1000,
        resume: str = None,
    ) -> Iterator[dict]:

        assert user_handle is not None or user_id is not None
        user_id = user_id if user_id is not None else self.lookup(user_handle)["id"]

        n_output = 0
        for followers_batch in self._get_paginated(
            f"/v1/accounts/{user_id}/followers", resume=resume
        ):
            for f in followers_batch:
                yield f
                n_output += 1
                if maximum is not None and n_output >= maximum:
                    return

    def user_following(
        self,
        user_handle: str = None,
        user_id: str = None,
        maximum: int = 1000,
        resume: str = None,
    ) -> Iterator[dict]:

        assert user_handle is not None or user_id is not None
        user_id = user_id if user_id is not None else self.lookup(user_handle)["id"]

        n_output = 0
        for followers_batch in self._get_paginated(
            f"/v1/accounts/{user_id}/following", resume=resume
        ):
            for f in followers_batch:
                yield f
                n_output += 1
                if maximum is not None and n_output >= maximum:
                    return

    def pull_statuses(
        self, username: str, created_after: date, replies: bool
    ) -> Optional[Generator]:
        """Pull the given user's statuses. Returns an empty list if not found."""

        params: dict = {}
        res = self.lookup(username)
        id = res["id"]
        while True:
            try:
                url = f"/v1/accounts/{id}/statuses"
                if not replies:
                    url += "?exclude_replies=true"
                result = self._get(url, params=params)
            except json.JSONDecodeError as e:
                logger.error(f"Unable to pull user #{id}'s statuses': {e}")
                break
            except Exception as e:
                logger.error(f"Misc. error while pulling statuses for {id}: {e}")
                break

            if "error" in result:
                logger.error(
                    f"API returned an error while pulling user #{id}'s statuses: {result}"
                )
                break

            if len(result) == 0:
                break

            if not isinstance(result, list):
                logger.error(f"Result is not a list (it's a {type(result)}): {result}")

            posts = sorted(result, key=lambda k: k["id"])
            params["max_id"] = posts[0]["id"]

            most_recent_date = (
                date_parse.parse(posts[-1]["created_at"])
                .replace(tzinfo=timezone.utc)
                .date()
            )
            if created_after and most_recent_date < created_after:
                # Current and all future batches are too old
                break

            for post in posts:
                post["_pulled"] = datetime.now().isoformat()
                date_created = (
                    date_parse.parse(post["created_at"])
                    .replace(tzinfo=timezone.utc)
                    .date()
                )
                if created_after and date_created < created_after:
                    continue

                yield post

    @staticmethod
    def get_access_token(username: str, password: str) -> str:
        """Logs in to Truth account and returns the session token"""
        url = BASE_URL + "/oauth/token"
        try:

            payload = {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "password",
                "username": username,
                "password": password,
            }

            sess_req = requests.request(
                "POST",
                url,
                params=payload,
                headers={
                    "user-agent": USER_AGENT,
                },
            )
            sess_req.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"Failed login request: {str(e)}")
            return ""

        if not sess_req.json()["access_token"]:
            raise ValueError("Invalid truthsocial.com credentials provided!")

        return sess_req.json()["access_token"]
