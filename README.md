# MiniUPnPd <= 2.1 Read Out-of-Bounds (POC)

This repository contains a Proof of Concept (POC) for exploiting an out-of-bounds read vulnerability in MiniUPnPd versions <= 2.1.

Credit where credit is due [@b1ack0wl](https://github.com/b1ack0wl)

Based on https://github.com/b1ack0wl/miniupnpd_poc repository.

## Description

MiniUPnPd is a daemon that enables the use of the Universal Plug and Play (UPnP) protocol in networks. This vulnerability allows an attacker to read data outside the boundaries of memory, potentially exposing sensitive information.

## Vulnerability Details

- **Type**: Out-of-bounds read
- **Affected Version**: MiniUPnPd <= 2.1
- **CVE**: N/A
* This vulnerability has been addressed in the master branch of MiniUPnPd ([commit link](https://github.com/miniupnp/miniupnp/commit/bec6ccec63cadc95655721bc0e1dd49dac759d94)).
* The issue arises when a **SUBSCRIBE** request is sent with a callback URI (`obj->path`) exceeding 526 bytes.
* The root cause is the failure to validate the return value of `snprintf()`, which indicates how many bytes it *could* have copied, rather than how many bytes it actually did copy.
* As of January 25, 2019, the PoC provided in this repository has been successfully tested against Google Wifi.
* As of September 18, 2024, the PoC provided in this repository has been successfully tested against Movistar's RTF8115VW router.
  * Other devices utilizing `miniupnpd` may also be susceptible to this vulnerability.

## Root Cause (upnpevents.c)
```
static void upnp_event_prepare(struct upnp_event_notify * obj)
{

	obj->buffersize = 1024; /* Static Buffer Size */
	obj->buffer = malloc(obj->buffersize);
	[...]
	obj->tosend = snprintf(obj->buffer, obj->buffersize, notifymsg,
	                       obj->path, obj->addrstr, obj->portstr, l+2,
	                       obj->sub->uuid, obj->sub->seq,
	                       l, xml);
	obj->state = ESending;

static void upnp_event_send(struct upnp_event_notify * obj)
{
	int i;
	i = send(obj->s, obj->buffer + obj->sent, obj->tosend - obj->sent, 0);
```

**Man Page Entry for snprintf()**
```
RETURN VALUE
```
Upon successful return, functions return the number of characters printed 
(excluding the null byte used to end output to strings).

The functions snprintf() and vsnprintf() do not write more than size bytes 
(including the terminating  null byte ('\0')).  If the output was truncated 
due to this limit, then the return value is the number of characters 
(excluding the terminating null byte) which would have been written to the 
final string if enough space had been available. Thus, a return value of size 
or more means that the output was truncated.

## Usage
```
MiniUPnP < 2.1 Read Out-of-Bounds Vulnerability

Usage:
    exploit.py -u <target_ip> [options]

Options:
    -u, --target_ip <target_ip>       IP address of vulnerable device (required).
    -p, --target_port <target_port>    Target Port (default: 5000).
    --callback_ip <callback_ip>        Local IP address for HTTP listener (required).
    --callback_port <callback_port>    Local port for HTTP listener (required).
    --timeout <timeout>                Timeout for HTTP requests (in seconds, default: 5).
    --leak_amount <leak_amount>        Amount of arbitrary heap data to leak (in KB, default: 1).
```

## Security Considerations

This script is intended solely for educational purposes and security research within authorized environments. It is not designed for illegal activities, unauthorized access, or exploitation of systems without explicit permission.

- Authorization: Ensure you have explicit permission from the device owner before testing any vulnerabilities. Unauthorized access to devices is illegal and unethical.

- Educational Use: The primary goal of this script is to demonstrate a known vulnerability in MiniUPnP versions below 2.1. It should be used in controlled environments, such as labs or testing setups.

- Data Handling: Be cautious with the data you may retrieve or manipulate. Handling sensitive data improperly can lead to security breaches.

- Legal Compliance: Familiarize yourself with local laws and regulations regarding cybersecurity and ethical hacking. Always operate within legal boundaries.

- Responsible Disclosure: If you discover new vulnerabilities, consider responsible disclosure to the affected parties to allow for proper remediation.

### By following these guidelines, you can help ensure that your use of this script is ethical and lawful.
