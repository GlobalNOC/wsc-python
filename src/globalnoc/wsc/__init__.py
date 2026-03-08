import http.cookiejar
import logging
import os
from dataclasses import dataclass, field

import httpx
from json import JSONDecodeError
from lxml import etree as ET

namespaces = {
    "S": "http://schemas.xmlsoap.org/soap/envelope/",
    "paos": "urn:liberty:paos:2003-08",
    "ecp": "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


from globalnoc.wsc.exc import (
    InvalidURN,
    LoginFailure,
    NoNameService,
    NoURL,
    RemoteMethodException,
    UndefinedURN,
)


class ECP(httpx.Auth):
    requires_response_body = True

    def __init__(self, username, password, realm, cookies=None, debug=False):
        self.debug = debug
        self.username = username
        self.password = password
        self.realm = realm
        # Reference to the outer session's cookie jar; cookies saved here
        # will be sent automatically by the httpx Client on future requests,
        # allowing the SP to recognize the session without repeating ECP.
        self.cookies = cookies

    def auth_flow(self, request):
        # Update or add Accept header to indicate we want to do ECP
        if "Accept" in request.headers:
            request.headers["Accept"] += ", application/vnd.paos+xml"
        else:
            request.headers["Accept"] = "*/*, application/vnd.paos+xml"

        # Signal that we support ECP
        request.headers["PAOS"] = (
            'ver="urn:liberty:paos:2003-08";'
            '"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"'
        )

        response = yield request

        if response.headers.get("content-type", None) == "application/vnd.paos+xml":
            logging.debug("Got PAOS Header. Redirecting through ECP login.")

            e = ET.fromstring(response.content)

            with httpx.Client() as session:
                # Extract the relay state to use later
                (relaystate,) = ET.XPath("S:Header/ecp:RelayState", namespaces=namespaces)(
                    e
                )
                # Extract the response consumer URL to compare later
                responseconsumer = ET.XPath("S:Header/paos:Request", namespaces=namespaces)(
                    e
                )[0].get("responseConsumerURL")

                logging.debug("SP expects the response at: %s", responseconsumer)

                # Clean up the SP login request
                e.remove(ET.XPath("S:Header", namespaces=namespaces)(e)[0])

                # Log into the IdP with the SP request
                logging.debug(
                    "Logging into the IdP via %s as %s", self.realm, self.username
                )

                login_r = session.post(
                    self.realm,
                    auth=(self.username, self.password),
                    content=ET.tostring(e),
                    headers={"content-type": "text/xml"},
                )

                try:
                    login_r.raise_for_status()
                except httpx.HTTPStatusError as e:
                    raise RemoteMethodException(
                        f"Received status code {login_r.status_code} from IdP"
                    ) from e

                ee = ET.fromstring(login_r.content)

                # Make sure we got back the same response consumer URL
                # and assertion consumer service URL
                idpACS = ET.XPath("S:Header/ecp:Response", namespaces=namespaces)(ee)[
                    0
                ].get("AssertionConsumerServiceURL")
                logging.debug("IdP said to send the response to %s", idpACS)

                if responseconsumer != idpACS:
                    raise LoginFailure("SP and IdP ACS mismatch")

                # Make sure we got a successful login
                if (
                    ET.XPath(
                        "S:Body/saml2p:Response/saml2p:Status/saml2p:StatusCode",
                        namespaces=namespaces,
                    )(ee)[0].get("Value")
                    != "urn:oasis:names:tc:SAML:2.0:status:Success"
                ):
                    raise LoginFailure("Login to IdP unsuccessful")

                logging.debug("IdP accepted login.")

                # Clean up login token
                (h,) = ET.XPath("S:Header", namespaces=namespaces)(ee)

                for el in h:
                    h.remove(el)
                h.append(relaystate)

                # Pass login token to SP
                logging.debug("Sending login token to SP.")

                return_r = session.post(
                    responseconsumer,
                    content=ET.tostring(ee),
                    headers={"Content-Type": "application/vnd.paos+xml"},
                    follow_redirects=False,
                )

                if return_r.status_code not in (httpx.codes.OK, httpx.codes.FOUND):
                    raise RemoteMethodException(
                        f"Received status code {return_r.status_code} from SP"
                    )

                # Persist login cookies to the outer session for reuse
                if self.cookies is not None:
                    for cookie in session.cookies.jar:
                        self.cookies.jar.set_cookie(cookie)

                # Prepare the original request with the new login cookies
                cookie_header = "; ".join(
                    f"{c.name}={c.value}" for c in session.cookies.jar
                )

            # Re-launch the original request after logging in
            logging.debug("Re-launching original request after logging in.")

            headers = dict(request.headers)
            if cookie_header:
                headers["Cookie"] = cookie_header

            retry = httpx.Request(
                method=request.method,
                url=request.url,
                headers=headers,
                content=request.content,
            )
            yield retry

        else:
            logging.debug(
                "No PAOS header. Assuming already logged in, or no Shib required."
            )

    def __eq__(self, other):
        return all(
            [
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
                self.realm == getattr(other, "realm", None),
            ]
        )

    def __ne__(self, other):
        return not self == other


@dataclass
class WSC:
    debug: bool = False
    ns: str = "/etc/grnoc/name-service-cacher/name-service.xml"
    password: str = field(default=None, repr=False)
    raw: bool = False
    realm: str = None
    session: httpx.Client = field(default=None, init=False, repr=False)
    strict_content_type: bool = True
    timeout: int = 60
    url: str = None
    _urn: str = field(default=None, init=False)
    username: str = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __post_init__(self):
        logging.debug("Initialized WSC object")
        self.session = httpx.Client()

    def __getattr__(self, name):
        return self._remoteHandler(name)

    def _load(self, filename: str):
        jar = http.cookiejar.LWPCookieJar(filename)

        jar.load(ignore_discard=True)
        for cookie in jar:
            self.session.cookies.jar.set_cookie(cookie)

    def _remoteHandler(self, name):
        def handler(*args, **kwargs):
            if not self.url:
                raise NoURL()

            data = {"method": name}
            data.update(kwargs)

            if not self.realm:
                logging.debug(
                    "Realm not set. Launching as HTTP Basic without a fixed realm."
                )
                r = self.session.post(
                    self.url,
                    auth=(self.username, self.password),
                    data=data,
                    timeout=self.timeout,
                )
            elif self.realm.startswith("https://"):
                logging.debug(
                    "Realm set and looks like Shibboleth ECP. Launching with ECP"
                )
                r = self.session.post(
                    self.url,
                    auth=ECP(
                        self.username, self.password, self.realm,
                        cookies=self.session.cookies, debug=self.debug,
                    ),
                    data=data,
                    timeout=self.timeout,
                )
            else:
                raise LoginFailure("Realm is not an IdP ECP Endpoint")

            try:
                r.raise_for_status()
            except httpx.HTTPStatusError as e:
                raise RemoteMethodException(
                    f"Received status code {r.status_code}"
                ) from e

            if self.raw:
                return r.content

            if self.strict_content_type and "/json" not in r.headers.get(
                "content-type"
            ):
                raise RemoteMethodException(
                    "Unknown content type {0}".format(r.headers.get("content-type"))
                )

            try:
                return r.json()
            except JSONDecodeError as e:
                raise RemoteMethodException("JSON parse error") from e

        return handler

    def _save(self, filename: str):
        jar = http.cookiejar.LWPCookieJar(filename)

        for cookie in self.session.cookies.jar:
            jar.set_cookie(cookie)
        jar.save(ignore_discard=True)
        os.chmod(filename, 0o600)

    def close(self):
        self.session.close()

    @property
    def urn(self):
        return self._urn

    @urn.setter
    def urn(self, urn):
        ns_etree = ET.parse(self.ns)

        if not self.ns:
            raise NoNameService()

        if not urn.startswith("urn:publicid:IDN+grnoc.iu.edu:"):
            raise InvalidURN()

        (_, _, _, urn_cloud, urn_class, urn_version, urn_service) = urn.split(":")

        ns_cloud = [
            c
            for c in ns_etree.findall("./cloud")
            if c.attrib.get("id") == urn_cloud
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
