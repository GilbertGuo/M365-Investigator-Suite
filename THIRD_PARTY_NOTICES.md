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

## Microsoft application ID reference

`ual_app/app_id_names.json` contains a local snapshot of public Microsoft
first-party application ID reference data from Microsoft's
[Apps to allow](https://learn.microsoft.com/en-us/power-platform/admin/apps-to-allow)
documentation. The reference was retrieved on July 21, 2026. Microsoft names,
product names, reference data, and trademarks remain the property of their
respective owners. Microsoft is not affiliated with or endorsing this project.
