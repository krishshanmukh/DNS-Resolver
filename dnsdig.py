
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
 # https://metebalci.com/blog/a-short-practical-tutorial-of-dig-dns-and-dnssec/

def make_query(hostname, type_of_req):
	# Construct a proper name from hostname
	qname = dns.name.from_text(hostname)


	# Construct dns question
	if type_of_req == "A":
		q = dns.message.make_query(qname, dns.rdatatype.A)
	elif type_of_req == "NS":
		q = dns.message.make_query(qname, dns.rdatatype.NS)
	elif type_of_req == "MX":
		q = dns.message.make_query(qname, dns.rdatatype.MX)
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
		r = dns.query.udp(q, resolver, 5)
		# print(r)
	except :
		return 0,""
	Q_IPS = []
	# print(q.question[0].to_text() + " " + resolver)

	# No domain --- NXDOMAIN
	if r.rcode() == dns.rcode.NXDOMAIN:
		return len(r.to_wire()), r.authority

	if r.rcode() != dns.rcode.NOERROR:
		# DNS rejects
		# print("------------ Fucked up --------------")
		return 0, ""
	if r.answer:
		# print("Found for q "+q.question[0].to_text())
		return len(r.to_wire()), r.answer

	if get_soa(r.authority) != []:
		ans = r.authority
		return len(r.to_wire()), ans


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
		ns.extend(get_soa(r.authority))
		for n in ns:
			Q_IPS.extend(get_ips(resolution(n, root_servers[0], "A")))
		if Q_IPS == []:
			return 0, ""
	
	# print(q.question[0].to_text() + " " + resolver)
	# print(Q_IPS)
	for ip in Q_IPS:
		l, ans = resolution(hostname, ip, type_of_req)
		if ans != "":
			return l, ans
	
	return ""

	
	

if __name__ == "__main__":
	if len(sys.argv) != 3:
		print("Wrong args... Use python dnsdig.py hostname type")
		exit()

	type_of_req = sys.argv[2]
	hostname = sys.argv[1]
	q = make_query(hostname, type_of_req)

	start = datetime.datetime.now()

	print("QUESTION:")
	print(q.question[0].to_text())
	ans = ""
	l = 0
	for IP in root_servers[2:]:
		q = make_query(hostname, type_of_req)
		Q_IPS = []
		r = dns.query.udp(q, IP, 5)
		if r.answer:
			ans = r.answer
			l = len(r.to_wire())
			break
		# Store ips from additional & authority
		# sections into the Q_IPS variable
		if (r.additional):
			Q_IPS = get_ips(r.additional)
		if (r.authority):
			Q_IPS.extend(get_ips(r.additional))
		# print(Q_IPS)
		
		for ip in Q_IPS:
			l, ans = resolution(hostname, ip, type_of_req)
			if ans != "":
				break
		has_cname_only = True
		cname = None
		while ans != "":
			for rr in ans:
				if rr.rdtype != dns.rdatatype.CNAME:
					has_cname_only = False
				if rr.rdtype == dns.rdatatype.CNAME:
					cname = rr
			if has_cname_only:
				# resolve cname
				if cname != None:
					hostname = cname.to_text().split()[-1]
					l, ans = resolution(hostname, ip, type_of_req)
					print("GOT CNAME: resolving further, ", hostname)
			else:
				break
		if ans != "":
			break
	
	print("\n\nANSWER:")
	for rr in ans:
		print(rr.to_text())

	print("\n\nQUERY TIME (ms):")
	print((datetime.datetime.now()-start).total_seconds()*1000)

	print("\n\nWHEN?:")
	print(start)

	print("\n\nSIZE?:")
	print(l)