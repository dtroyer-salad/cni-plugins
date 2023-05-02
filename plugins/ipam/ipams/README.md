CNI Plugin - IPAM multiple plugins
==================================

An IPAM plugin that calls a list of IPAM plugins to configure multiple addresses
on an interface using multiple methods, such as a combination of static and host-only.

In the input JSON replace the contents of the `ipam` dict with a dict of type `ipams`
and a list of `ipam` dicts:

    "ipam": {
        "type": "ipams",
        "ipams": [
        {
            "type": "static",
            "addresses": [
            {
                "address": "10.10.0.1/24",
                "gateway": "10.10.0.254"
            }
            ],
            "routes": [
            {
                "dst": "::/0"
            }
            ]
        },
        {
            "type": "host-local",
            "ranges": [
            [
                {
                "subnet": "172.27.71.0/24"
                }
            ]
            ],
            "routes": [
            {
                "dst": "0.0.0.0/0"
            }
            ]
        }
        ]
    },
