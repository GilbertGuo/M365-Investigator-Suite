# Third-Party Services and Reference Data

The MIT License in [`LICENSE`](LICENSE) applies to the source code in this
repository. It does not grant rights to third-party services, data, names, or
trademarks.

## IP-API

M365 Investigator Suite includes an optional integration with the IP-API batch
service operated by `ip-api.com`. The integration is not used automatically.
When an analyst explicitly accepts the notice and runs **Enrich IPs**, public
IP addresses selected from the case are transmitted to IP-API. Private,
loopback, link-local, and invalid addresses are classified locally.

The anonymous free endpoint:

- is governed by the [IP-API terms](https://ip-api.com/docs/legal);
- is offered only for a non-commercial purpose in a non-commercial
  environment;
- uses unencrypted HTTP; and
- is subject to the provider's rate limits and other service conditions.

The interface also accepts an optional IP-API Pro key. When supplied, public IP
addresses and the key are sent over HTTPS to `pro.ip-api.com`; the key is held
only for the active request and is not persisted or returned. Paid use remains
subject to the subscriber's plan, key restrictions, acceptable-use policy, and
the [IP-API Pro terms](https://members.ip-api.com/legal). Commercial or
organizational deployments must obtain an appropriate subscription or
replace/disable this integration. No subscription, API key, response data, or
service license is included with this repository. IP-API is not affiliated with
or endorsing this project.

## Domain registration enrichment (RDAP)

M365 Investigator Suite includes optional domain-registration enrichment using
the Registration Data Access Protocol (RDAP). The integration is not used
automatically. When an analyst runs **Enrich domains**, the tool extracts domain
names from the selected sender and/or recipient fields; complete email
addresses are not submitted.

The tool first retrieves the public
[IANA RDAP bootstrap registry](https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml)
from `data.iana.org` to discover the authoritative service for each top-level
domain. Retrieving the bootstrap registry does not send the queried domain to
IANA. The extracted domain is then submitted over HTTPS to the authoritative
RDAP endpoint listed by IANA. That endpoint may be operated by a registry,
registrar, or another registration-data service provider and may redirect the
request to another authoritative endpoint.

Each RDAP operator can apply its own terms, privacy practices, acceptable-use
rules, logging, access controls, and rate limits. A provider may receive the
queried domain, the requester's public IP address, request time, user agent, and
other ordinary network metadata. Analysts and organizations are responsible for
ensuring that their queries are lawful and consistent with the applicable
provider terms and their own evidence-handling requirements. See ICANN's
[Information for RDAP Users](https://www.icann.org/en/contracted-parties/registry-operators/registration-data-access-protocol/information-for-rdap-users-31-08-2018-en)
for background on the protocol and its providers.

RDAP responses contain public registration data and can be incomplete,
redacted, unavailable, delayed, or inaccurate. A registration date, registrar,
status, or other returned value does not by itself establish domain ownership,
attribution, legitimacy, or malicious intent. Automated domain-age and
suspicious-mail results are investigation leads that require validation against
original evidence and surrounding context.

No RDAP subscription, nonpublic registration-data access, response-data
license, or service-level guarantee is included with this repository. This
integration does not use or include DomainTools services, accounts, or data.
IANA, ICANN, registry operators, registrars, RDAP providers, and DomainTools are
not affiliated with or endorsing this project.

## Microsoft application ID reference

`ual_app/app_id_names.json` contains a local snapshot of public Microsoft
first-party application ID reference data from Microsoft's
[Apps to allow](https://learn.microsoft.com/en-us/power-platform/admin/apps-to-allow)
documentation. The reference was retrieved on July 21, 2026. Microsoft names,
product names, reference data, and trademarks remain the property of their
respective owners. Microsoft is not affiliated with or endorsing this project.
