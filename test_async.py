import asyncio
import getpass
import json

from globalnoc.wsc import AsyncWSC

mappings = {
    "w1.ll.k8s.grnoc.iu.edu": {
        "v4": "149.165.134.16",
        "v6": "2001:18e8:ff00:23:0:2:95a5:8610",
    },
    "w2.ll.k8s.grnoc.iu.edu": {
        "v4": "149.165.134.17",
        "v6": "2001:18e8:ff00:23:0:2:95a5:8611",
    },
    "w3.ll.k8s.grnoc.iu.edu": {
        "v4": "149.165.134.18",
        "v6": "2001:18e8:ff00:23:0:2:95a5:8612",
    },
    "w1.ll.k8s.net.internet2.edu": {
        "v4": "149.165.134.19",
        "v6": "2001:18e8:ff00:23:0:2:95a5:8613",
    },
    "w2.ll.k8s.net.internet2.edu": {
        "v4": "149.165.134.20",
        "v6": "2001:18e8:ff00:23:0:2:95a5:8614",
    },
    "w1.ll.k8s.net.cen.ct.gov": {
        "v4": "149.165.134.21",
        "v6": "2001:18e8:ff00:23:0:2:95a5:8615",
    },
    "w2.ll.k8s.net.cen.ct.gov": {
        "v4": "149.165.134.22",
        "v6": "2001:18e8:ff00:23:0:2:95a5:8616",
    },
    "w1.ll.k8s.oshean.org": {
        "v4": "149.165.134.23",
        "v6": "2001:18e8:ff00:23:0:2:95a5:8617",
    },
    "w2.ll.k8s.oshean.org": {
        "v4": "149.165.134.24",
        "v6": "2001:18e8:ff00:23:0:2:95a5:8618",
    },
}


async def main():
    password = getpass.getpass()

    async with AsyncWSC(
        url="https://db2.grnoc.iu.edu/cds2/netblock.cgi",
        username="jdratlif",
        password=password,
        realm="https://idp.grnoc.iu.edu/idp/profile/SAML2/SOAP/ECP",
    ) as w:
        w._load("/tmp/jdratlif.cookies")

        promises = []
        for hostname, addrs in mappings.items():
            promises.append(
                w.add_netblock(
                    allocatable=0,
                    name=hostname,
                    network_id=3,
                    prefix=addrs["v4"],
                    length=32,
                    version=4,
                    parent_netblock_id=8172,
                )
            )
            promises.append(
                w.add_netblock(
                    allocatable=0,
                    name=hostname,
                    network_id=3,
                    prefix=addrs["v6"],
                    length=128,
                    version=6,
                    parent_netblock_id=152095,
                )
            )

        result = await asyncio.gather(*promises)

        for r in result:
            print(json.dumps(r, indent=2))


asyncio.run(main())
