import logging

import httpx
from lxml import etree as ET

from globalnoc.wsc.exc import LoginFailure, RemoteMethodException

_NAMESPACES = {
    "S": "http://schemas.xmlsoap.org/soap/envelope/",
    "paos": "urn:liberty:paos:2003-08",
    "ecp": "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
_PAOS_CONTENT_TYPE = "application/vnd.paos+xml"


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

    def _add_ecp_headers(self, request):
        if "Accept" in request.headers:
            request.headers["Accept"] += f", {_PAOS_CONTENT_TYPE}"
        else:
            request.headers["Accept"] = f"*/*, {_PAOS_CONTENT_TYPE}"

        request.headers["PAOS"] = (
            'ver="urn:liberty:paos:2003-08";'
            '"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"'
        )

    def _parse_sp_response(self, content):
        e = ET.fromstring(content)

        (relaystate,) = ET.XPath("S:Header/ecp:RelayState", namespaces=_NAMESPACES)(e)
        (paos_request,) = ET.XPath("S:Header/paos:Request", namespaces=_NAMESPACES)(e)
        responseconsumer = paos_request.get("responseConsumerURL")

        logging.debug("SP expects the response at: %s", responseconsumer)
        e.remove(ET.XPath("S:Header", namespaces=_NAMESPACES)(e)[0])

        return relaystate, responseconsumer, e

    def _validate_idp_response(self, idp_content, responseconsumer, relaystate):
        idp_etree = ET.fromstring(idp_content)

        (ecp_response,) = ET.XPath("S:Header/ecp:Response", namespaces=_NAMESPACES)(
            idp_etree
        )
        idp_acs = ecp_response.get("AssertionConsumerServiceURL")

        logging.debug("IdP said to send the response to %s", idp_acs)

        if responseconsumer != idp_acs:
            raise LoginFailure("SP and IdP ACS mismatch")

        (status_code,) = ET.XPath(
            "S:Body/saml2p:Response/saml2p:Status/saml2p:StatusCode",
            namespaces=_NAMESPACES,
        )(idp_etree)

        if status_code.get("Value") != "urn:oasis:names:tc:SAML:2.0:status:Success":
            raise LoginFailure("Login to IdP unsuccessful")

        logging.debug("IdP accepted login.")
        (soap_header,) = ET.XPath("S:Header", namespaces=_NAMESPACES)(idp_etree)

        for child in soap_header:
            soap_header.remove(child)

        soap_header.append(relaystate)

        return ET.tostring(idp_etree)

    def _check_sp_return(self, status_code):
        if status_code not in (httpx.codes.OK, httpx.codes.FOUND):
            raise RemoteMethodException(f"Received status code {status_code} from SP")

    def _persist_and_build_retry(self, session_cookies, request):
        if self.cookies is not None:
            for cookie in session_cookies.jar:
                self.cookies.jar.set_cookie(cookie)

        headers = dict(request.headers)
        cookie_header = "; ".join(f"{c.name}={c.value}" for c in session_cookies.jar)

        if cookie_header:
            headers["Cookie"] = cookie_header

        return httpx.Request(
            method=request.method,
            url=request.url,
            headers=headers,
            content=request.content,
        )

    def auth_flow(self, request):
        self._add_ecp_headers(request)
        response = yield request

        if response.headers.get("content-type") == _PAOS_CONTENT_TYPE:
            logging.debug("Got PAOS Header. Redirecting through ECP login.")

            relaystate, responseconsumer, sp_etree = self._parse_sp_response(
                response.content
            )

            with httpx.Client() as session:
                logging.debug(
                    "Logging into the IdP via %s as %s", self.realm, self.username
                )

                login_r = session.post(
                    self.realm,
                    auth=(self.username, self.password),
                    content=ET.tostring(sp_etree),
                    headers={"content-type": "text/xml"},
                )

                try:
                    login_r.raise_for_status()
                except httpx.HTTPStatusError as e:
                    raise RemoteMethodException(
                        f"Received status code {login_r.status_code} from IdP"
                    ) from e

                sp_token = self._validate_idp_response(
                    login_r.content, responseconsumer, relaystate
                )

                logging.debug("Sending login token to SP.")

                return_r = session.post(
                    responseconsumer,
                    content=sp_token,
                    headers={"Content-Type": _PAOS_CONTENT_TYPE},
                    follow_redirects=False,
                )

                self._check_sp_return(return_r.status_code)
                retry = self._persist_and_build_retry(session.cookies, request)

            logging.debug("Re-launching original request after logging in.")
            yield retry
        else:
            logging.debug(
                "No PAOS header. Assuming already logged in, or no Shib required."
            )

    async def async_auth_flow(self, request):
        self._add_ecp_headers(request)
        response = yield request
        await response.aread()

        if response.headers.get("content-type") == _PAOS_CONTENT_TYPE:
            logging.debug("Got PAOS Header. Redirecting through ECP login.")
            relaystate, responseconsumer, sp_etree = self._parse_sp_response(
                response.content
            )

            async with httpx.AsyncClient() as session:
                logging.debug(
                    "Logging into the IdP via %s as %s", self.realm, self.username
                )

                login_r = await session.post(
                    self.realm,
                    auth=(self.username, self.password),
                    content=ET.tostring(sp_etree),
                    headers={"content-type": "text/xml"},
                )

                try:
                    login_r.raise_for_status()
                except httpx.HTTPStatusError as e:
                    raise RemoteMethodException(
                        f"Received status code {login_r.status_code} from IdP"
                    ) from e

                sp_token = self._validate_idp_response(
                    login_r.content, responseconsumer, relaystate
                )

                logging.debug("Sending login token to SP.")

                return_r = await session.post(
                    responseconsumer,
                    content=sp_token,
                    headers={"Content-Type": _PAOS_CONTENT_TYPE},
                    follow_redirects=False,
                )

                self._check_sp_return(return_r.status_code)
                retry = self._persist_and_build_retry(session.cookies, request)

            logging.debug("Re-launching original request after logging in.")
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
