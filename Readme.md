# Vulnerability assessment for CVE-2022-22536

This repository contains a Python script that can be used to check if a SAP system is affected by CVE-2022-22536, a critical vulnerability rated with CVSSv3 Score of 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). This vulnerability was discovered by the Onapsis Research Labs, which closely collaborated with SAP to develop and release a patch on February 8, 2022. Onapsis would like to thank the SAP Product Security Response Team (PSRT) for their collaboration and timely response. The two teams worked tirelessly to ensure that a timely fix was available to all SAP customers as soon as possible.

Considering the number of potential vulnerable internet-facing SAP systems and the sensitivity of the data and processes typically supported by these systems, Onapsis decided to develop and release this open-source tool as quickly as possible. The goal is to help the information security and administration teams at all SAP customers protect their mission-critical applications by enabling them to assess their exposure and evaluate whether their SAP are affected by this vulnerability.
This tool can:

- Perform a best-effort, black-box scan of your SAP application(s) to quickly assess if they may be vulnerable to CVE-2022-22536.

This tool cannot:

- Guarantee with 100% accuracy whether your SAP applications are vulnerable or not.

There are, however, several known limitations of this tool and its usage should not be considered a guarantee that SAP applications are not affected by CVE-2022-22536. Several conditions can affect the state of the assessed applications, resulting in false positives and/or false negatives.

## How to use this tool

### Testing for SAP Systems affected by CVE-2022-22536

To test if your SAP ABAP or SAP JAVA systems are affected follow these steps:

1. Clone this repository

2. In the `src` you'll find a Python script called `ICMAD_scanner.py`.

3. You can execute it running `python ICMAD_scanner.py -H <SAP_SYSTEM_HOST_ADDRESS> -P <SAP_SYSTEM_HTTP_PORT>`

4. You can use `python ICMAD_scanner.py -h` to check for other options. The script supports systems using HTTP(s).

## Scenarios supported

This tool has been tested in the following scenarios:

### Direct testing against a SAP System

This tool provided realible results when used to test systems directly. This means with no HTTP(s) proxy device between the host executing the test and the target SAP system.

### SAP WEB Dispatcher as Proxy

This tool provided reliable results when the SAP system under test was behind a SAP Web Dispatcher.

### Other configurations / Proxies

This tool was not tested in any other environment or with any other proxy. Reliable results in any other scenario than the mentioned above are not guaranteed.

## Additional Resources

For additional information about CVE-2022-22536 vulnerability, the potential business impact, the affected versions and other data points, please review the Threat Report and information available here: [Onapsis and SAP Partner to Discover and Patch Critical ICMAD Vulnerabilities](https://onapsis.com/icmad-sap-cybersecurity-vulnerabilities?utm_campaign=2022-Q1-global-ICM-campaign-page&utm_medium=referral&utm_source=github&utm_content=internal-link)

The following SAP Notes provide additional information around patch and mitigations:

- 3123396 - [CVE-2022-22536] Request smuggling and request concatenation in SAP NetWeaver, SAP Content Server and SAP Web Dispatcher
- 3137885 - Workaround for security SAP note 3123396
- 3138881 - wdisp/additional_conn_close workaround for security SAP note 3123396


