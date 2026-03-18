import http.cookiejar
import logging
import os
from dataclasses import dataclass, field
from json import JSONDecodeError

import httpx
from lxml import etree as ET

from globalnoc.wsc.ecp import ECP
from globalnoc.wsc.exc import (
    InvalidURN,
    LoginFailure,
    NoNameService,
    NoURL,
    RemoteMethodException,
    UndefinedURN,
)


@dataclass
class _WSCBase:
    debug: bool = False
    ns: str = "/etc/grnoc/name-service-cacher/name-service.xml"
    password: str = field(default=None, repr=False)
    raw: bool = False
    realm: str = None
    strict_content_type: bool = True
    timeout: int = 60
    url: str = None
    _urn: str = field(default=None, init=False)
    username: str = None

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._remoteHandler(name)

    def __post_init__(self):
        pass

    def _build_post_args(self, name, kwargs):
        if not self.url:
            raise NoURL()

        data = {"method": name}
        data.update(kwargs)

        if not self.realm:
            logging.debug(
                "Realm not set. Launching as HTTP Basic without a fixed realm."
            )
            auth = (self.username, self.password)
        elif self.realm.startswith("https://"):
            logging.debug("Realm set and looks like Shibboleth ECP. Launching with ECP")
            auth = ECP(
                self.username,
                self.password,
                self.realm,
                cookies=self.session.cookies,
                debug=self.debug,
            )
        else:
            raise LoginFailure("Realm is not an IdP ECP Endpoint")

        return data, auth

    def _load(self, filename: str):
        jar = http.cookiejar.LWPCookieJar(filename)

        jar.load(ignore_discard=True)
        for cookie in jar:
            self.session.cookies.jar.set_cookie(cookie)

    def _process_response(self, r):
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise RemoteMethodException(f"Received status code {r.status_code}") from e

        if self.raw:
            return r.content

        if self.strict_content_type and "/json" not in r.headers.get("content-type"):
            raise RemoteMethodException(
                "Unknown content type {0}".format(r.headers.get("content-type"))
            )

        try:
            data = r.json()
        except JSONDecodeError as e:
            raise RemoteMethodException("JSON parse error") from e

        if isinstance(data, dict) and int(data.get("error", 0)) == 1:
            error_text = data.get("error_text", "UNKNOWN ERROR")
            msg = f"API returned an error: {error_text}"
            raise RemoteMethodException(msg)

        return data

    def _save(self, filename: str):
        jar = http.cookiejar.LWPCookieJar(filename)

        for cookie in self.session.cookies.jar:
            jar.set_cookie(cookie)
        jar.save(ignore_discard=True)
        os.chmod(filename, 0o600)

    @property
    def urn(self):
        return self._urn

    @urn.setter
    def urn(self, urn):
        if not self.ns:
            raise NoNameService()

        ns_etree = ET.parse(self.ns)

        if not urn.startswith("urn:publicid:IDN+grnoc.iu.edu:"):
            raise InvalidURN()

        (_, _, _, urn_cloud, urn_class, urn_version, urn_service) = urn.split(":")

        ns_cloud = [
            c for c in ns_etree.findall("./cloud") if c.attrib.get("id") == urn_cloud
        ]

        if len(ns_cloud) != 1:
            raise UndefinedURN(
                "Looking for {0} found {1} matching clouds".format(
                    urn_cloud, len(ns_cloud)
                )
            )

        ns_cloud = ns_cloud[0]

        ns_class = [
            c for c in ns_cloud.findall("./class") if c.attrib.get("id") == urn_class
        ]

        if len(ns_class) != 1:
            raise UndefinedURN(
                "Looking for {0}:{1} found {2} matching classes".format(
                    urn_cloud, urn_class, len(ns_class)
                )
            )

        ns_class = ns_class[0]

        ns_version = [
            c
            for c in ns_class.findall("./version")
            if c.attrib.get("value") == urn_version
        ]

        if len(ns_version) != 1:
            raise UndefinedURN(
                "Looking for {0}:{1}:{2} found {3} matching versions".format(
                    urn_cloud, urn_class, urn_version, len(ns_version)
                )
            )

        ns_version = ns_version[0]

        ns_service = [
            c
            for c in ns_version.findall("./service")
            if c.attrib.get("id") == urn_service
        ]

        if len(ns_service) != 1:
            raise UndefinedURN(
                "Looking for {0}:{1}:{2}:{3} found {4} matching services".format(
                    urn_cloud, urn_class, urn_version, urn_service, len(ns_service)
                )
            )

        ns_service = ns_service[0]

        ns_locations = [c for c in ns_service.findall("./location")]
        if len(ns_locations) < 1:
            raise UndefinedURN(
                "Looking for {0}:{1}:{2}:{3} found no matching locations".format(
                    urn_cloud, urn_class, urn_version, urn_service
                )
            )

        ns_locations.sort(key=lambda loc: loc.attrib.get("weight"))
        logging.debug("Setting and resolving URN: %s", urn)

        self.url = ns_locations[0].attrib.get("url")
        self._urn = urn


class WSC(_WSCBase):
    def __post_init__(self):
        self.session = httpx.Client()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _remoteHandler(self, name):
        def handler(**kwargs):
            data, auth = self._build_post_args(name, kwargs)
            r = self.session.post(self.url, auth=auth, data=data, timeout=self.timeout)
            return self._process_response(r)

        return handler

    def close(self):
        self.session.close()


class AsyncWSC(_WSCBase):
    def __post_init__(self):
        self.session = httpx.AsyncClient()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    def _remoteHandler(self, name):
        async def handler(**kwargs):
            data, auth = self._build_post_args(name, kwargs)
            r = await self.session.post(
                self.url, auth=auth, data=data, timeout=self.timeout
            )
            return self._process_response(r)

        return handler

    async def close(self):
        await self.session.aclose()
