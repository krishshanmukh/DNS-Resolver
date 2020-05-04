
import dns.resolver
import dns.name
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import re
import sys
import dns.rcode
import datetime
import dns.dnssec
 # https://metebalci.com/blog/a-short-practical-tutorial-of-dig-dns-and-dnssec/

def make_query(qname, type_of_req):
    # Construct a proper name from hostname
    # Construct dns question
    if type_of_req == "A":
        q = dns.message.make_query(qname, dns.rdatatype.A, want_dnssec = True)
    elif type_of_req == "NS":
        q = dns.message.make_query(qname, dns.rdatatype.NS, want_dnssec = True)
    elif type_of_req == "MX":
        q = dns.message.make_query(qname, dns.rdatatype.MX, want_dnssec = True)
    elif type_of_req == "DNSKEY":
        q = dns.message.make_query(qname, dns.rdatatype.DNSKEY, want_dnssec = True)
    else:
        return None
    return q


root_servers = ["198.41.0.4" ,\
                "199.9.14.201",\
                "192.33.4.12",\
                "199.7.91.13",\
                "192.203.230.10",\
                "192.5.5.241",\
                "192.112.36.4",\
                "198.97.190.53",\
                "192.36.148.17",\
                "192.58.128.30",\
                "193.0.14.129",\
                "199.7.83.42",\
                "202.12.27.33",\
                "198.41.0.4"]


# return if soa
def get_soa(additional):
    ns = []
    for rr in additional:
        ip = rr.to_text().split(" SOA ")
        # print(ip)
        if (len(ip)>1):
            ns.append(ip[1].split(" ")[0])
    return ns


# return ips from rrset
def get_ips(additional):
    IPS = []
    for rr in additional:
        ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', rr.to_text())
        if (ip):
            IPS.extend(ip)
    return IPS

# return ns from rrset 
def get_ns(additional):
    ns = []
    for rr in additional:
        for r in rr.to_text().split("\n"):
            ip = r.split("IN NS ")
            # print(ip)
            if (len(ip)>1):
                ns.append(ip[1])
    # print(ns)
    return ns

def resolution(hostname, resolver, type_of_req):
	q = make_query(hostname, type_of_req)
	try:
		r = dns.query.udp(q, resolver, 2)
	except :
		return ""
	Q_IPS = []
	# print(q.question[0].to_text() + " " + resolver)

	# No domain --- NXDOMAIN
	if r.rcode() == dns.rcode.NXDOMAIN:
		return r.authority

	if r.rcode() != dns.rcode.NOERROR:
		# DNS rejects
		# print("------------ Fucked up --------------")
		return ""
	if r.answer:
		# print("Found for q "+q.question[0].to_text())
		return r.answer
	# Store ips from additional & authority
	# sections into the Q_IPS variable
	if (r.additional):
		Q_IPS.extend(get_ips(r.additional))
	if (r.authority):
		Q_IPS.extend(get_ips(r.authority))

	# No IPS in addtional? return NULL
	if (Q_IPS == []):
		ns = []
		ns.extend(get_ns(r.additional))
		ns.extend(get_ns(r.authority))
		for n in ns:
			Q_IPS.extend(get_ips(resolution(n, root_servers[0], "A")))
		if Q_IPS == []:
			return ""
	
	# print(q.question[0].to_text() + " " + resolver)
	# print(Q_IPS)
	for ip in Q_IPS:
		ans = resolution(hostname, ip, type_of_req)
		if ans != "":
			return ans
	
	return ""

    
    

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Wrong args... Use python dnsdig.py hostname type")
        exit()

    type_of_req = sys.argv[2]
    hostname = dns.name.from_text(sys.argv[1])

    depth = 2

    resolver = root_servers[0]
    flag = True
    ans = None
    DS_RECORD = None

    # Flag is false when entire hostname is resolved
    while flag:

        try:
            x = hostname.split(depth)
        except:
            x = ['', hostname]
            flag = False
        # print(x[1], type(x[1]))
        # print(hostname.split(depth-1)[1])

        q = make_query(x[1], 'A')
        print("\n\nQUESTION:")
        print(q.question[0].to_text())
        # print(q)
        response = dns.query.udp(q, resolver, 5)
        support = False
        # print(response)
        if response.answer:
            ans = response.answer
            flag = False
            for rr in response.answer:
                if rr.rdtype == dns.rdatatype.RRSIG:
                    support = True

        # print(response)
        # temp has ip of child zone, whom we can query next
        temp = []
        if response.additional:
            temp = get_ips(response.additional)
        # print("additional" ,temp)
        if temp == [] and response.authority:
            name = get_ns(response.authority)
            name.extend(get_soa(response.authority))
            print(name)
            temp = get_ips(resolution(name[0], root_servers[0], "A"))
        # print("authority", temp)
        if temp != []:
            temp = temp[0]

        # Check if RRSIG is there => DNSSEC support
        if response.authority:
            for rr in response.authority:
                if rr.rdtype == dns.rdatatype.RRSIG:
                    support = True
        if response.answer:
            for rr in response.answer:
                if rr.rdtype == dns.rdatatype.RRSIG:
                    support = True

        # If DNSSEC is supported, check for DNSKEYs of the zone and
        # 1. Get DNSKEYS from zone - KSK and ZSK
        # 2. Compare RRSIG of DNSKEYS using validate
        # 3. Make ds using DNSKEY and hash algo and compare with
        #    DS obtained from parent
        if support:
            print("--------------------Came to DNS CHECK-----------------------------")
            q = make_query(hostname.split(depth-1)[1], 'DNSKEY')
            # resolver is current zone
            # 1
            # print(q)
            response_dnskey = dns.query.tcp(q, resolver, 5)
            # print(resolver)
            # print(response_dnskey)
            # get zone host name and dns keys
            name = hostname.split(depth-1)[1]
            print(name)
            if response_dnskey.answer:
                try:
                    # verify KSK and ZSK RRSIG with KSK
                    # r.answer[0] has rrset of KSK AND ZSK
                    # r.answer[1] has rrsig of ZSK AND KSK
                    # 2
                    rrsig = None
                    dnskeys = None
                    for rr in response_dnskey.answer:
                        if rr.rdtype == dns.rdatatype.DNSKEY:
                            dnskeys = rr
                        if rr.rdtype == dns.rdatatype.RRSIG:
                            rrsig = rr
                    dns.dnssec.validate(dnskeys, rrsig, {name:dnskeys})
                    print("Domain ZSK AND KSK " + hostname.split(depth-1)[1].to_text() + " Verified")
                    
                    if DS_RECORD:
                        verified = False
                        for ds in  DS_RECORD:
                            # print(dns.dnssec.make_ds(hostname.split(depth-1)[1].to_text(), 
                            # response_dnskey.answer[0], "SHA1"))
                            htype = 'SHA256' if ds.digest_type == 2 else 'SHA1'
                            for dnskey in dnskeys:
                                child_ds = dns.dnssec.make_ds(hostname.split(depth-1)[1].to_text(), 
                                dnskey, htype)
                                # print(child_ds)
                                if ds == child_ds:
                                    verified = True
                                    print("Verified DS record from parent!")
                            # dns.dnssec.validate(DS_RECORD, response_dnskey.answer[1],
                            # {name:response_dnskey.answer[0]})
                            # print("DS Record from parent is also verified!")
                        if verified == False:
                            print("DS record verification failed!")
                            raise dns.dnssec.ValidationFailure
                except dns.dnssec.ValidationFailure:
                    print("\n\n*********DNS CHECK FAILED********")
                    exit(-1)
        else:
            print("No DNS SEC Support for the zone")
        # get DS record from current zone and compare to child zone
        DS_RECORD = None
        if response.authority:
            for rr in response.authority:
                if rr.rdtype == dns.rdatatype.DS:
                    # Store the ds record
                    # It has the public ZSK of child zone
                    DS_RECORD = rr

        depth = depth+1
        resolver = temp
    
    print("\n\nANSWER\n")
    for rr in ans:
        print(rr.to_text())