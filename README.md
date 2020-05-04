# DNS Resolver

This tool has 2 parts - DNS resolution and DNSSEC resolution
- In DNS resolution, we first ping the root server and then iteratively go down the line
- We have to resolve CNAME separately (by starting from the root for each cname)
- For DNSSEC, refer the following [Cloudflare](https://www.cloudflare.com/dns/dnssec/how-dnssec-works/) and [dnssec-failed](http://www.dnssec-failed.org/)

## Depedencies
- [dnspython](http://www.dnspython.org/)

## Steps to run
1. For DNS resolution, 
```
python dnsdig.py hostname type_of_req 
type_of_req should be A, MX, NS
```
2. For DNS SEC,
```
python dnssec.py www.eurid.eu A
```