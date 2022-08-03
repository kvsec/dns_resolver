import dns.resolver
import ipwhois
import socket

with open('target.txt') as f:
    domains = [line.strip() for line in f.readlines()]

all_ips = []
ips = []
resolved = []
non_resolvable = []
wcloudfront = []
wcloudfront_ips = []

for domain in domains:
    try:
        result_cname = dns.resolver.resolve(domain, 'CNAME')
        for v in result_cname:
            if 'cloudfront' in v.to_text():
                wcloudfront.append(domain)
            else:
                print(f'CNAME: {v}')
    except Exception:
        try:
            exception_cname = socket.gethostbyaddr(domain)[0]
            if 'cloudfront' in exception_cname:
                wcloudfront.append(domain)
            else:
                print(f'CNAME : {exception_cname}')
        except:
            print('No CNAME')

    try:
        result = dns.resolver.resolve(domain, 'A')
        for r in result:
            if domain not in wcloudfront:
                print('A', domain + ':', r.to_text())
                ips.append(r.to_text())
                resolved.append(domain)
            elif domain in wcloudfront:
                print('A', domain + ':', r.to_text() + ' CLOUDFRONT')
                wcloudfront_ips.append(r.to_text())
    except Exception:
        non_resolvable.append(domain)

print('-------------')
if non_resolvable:
    print("Non-Resolvable:")
    for line in non_resolvable:
        print(line)
    print('-------------')

uniq = list(sorted(set(resolved)))
with open('resolved.txt', 'a') as file:
    for u in uniq:
        file.write(u + '\n')

result = []
uniq = sorted(set(ips))

for line in uniq:
    try:
        whois_description = ipwhois.IPWhois(line).lookup_whois()
        whois_description = whois_description["nets"][0]['description']
        organizations = ['cloudflare', 'imperva', 'twitter', 'level 3', 'zendesk', 'microsoft',
                         'sendgrid', 'cloudfront']
        blacklist = False
        for organization in organizations:
            if whois_description is None:
                pass
            if whois_description is not None:
                if organization in whois_description.lower():
                    blacklist = True
            if line in wcloudfront_ips:
                blacklist = True
            else:
                pass
        if not blacklist:
            result.append(line)
    except ipwhois.exceptions.IPDefinedError:
        print(f"{line} is private IP")

print('Unique IPs for NMAP: ')
uniqips = list(sorted(set(result)))
with open('ips.txt', 'a') as ff:
    for i in uniqips:
        ff.write(i + '\n')
for ip in uniqips:
    print(ip)

uniq_cloudfront = list(sorted(set(wcloudfront)))
with open('cloudfront_resolved.txt', 'a') as clouddom:
    for cld in uniq_cloudfront:
        clouddom.write(cld + '\n')

uniq_cloudfront_ips = list(sorted(set(wcloudfront_ips)))
with open('cloudfront_ips.txt', 'a') as cloudip:
    for cl in uniq_cloudfront_ips:
        cloudip.write(cl + '\n')

all_ipaddresses = uniq_cloudfront_ips + uniqips
with open('all_ips.txt', 'a') as allip:
    for ipaddr in all_ipaddresses:
        allip.write(ipaddr + '\n')
