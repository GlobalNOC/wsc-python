import logging

import httpx
from lxml import etree as ET

from globalnoc.wsc.exc import LoginFailure, RemoteMethodException

namespaces = {
    "S": "http://schemas.xmlsoap.org/soap/envelope/",
    "paos": "urn:liberty:paos:2003-08",
    "ecp": "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


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
