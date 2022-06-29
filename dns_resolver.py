import dns.resolver
import ipwhois

with open('target.txt') as f:
    domains = [line.strip() for line in f.readlines()]

ips = []
resolved = []
non_resolvable = []
for domain in domains:
    try:
        result = dns.resolver.resolve(domain, 'A')
        for r in result:
            print('A', domain + ':', r.to_text())
            ips.append(r.to_text())
            resolved.append(domain)
    except Exception:
        non_resolvable.append(domain)
    try:
        result_cname = dns.resolver.resolve(domain, 'CNAME')
        for v in result_cname:
            print(f'CNAME : {v}')
            print('----------------------------------------------------')
    except Exception:
        pass

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
# print('***************')
result = []
uniq = sorted(set(ips))

for line in uniq:
    try:
        whois_description = ipwhois.IPWhois(line).lookup_whois()
        whois_description = whois_description["nets"][0]['description']
        organizations = ['cloudflare', 'google', 'imperva', 'twitter', 'level 3', 'zendesk', 'microsoft',
                         'sendgrid']
        blacklist = False
        for organization in organizations:
            if organization in whois_description.lower():
                blacklist = True
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
