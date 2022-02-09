import dns.resolver
import whois

with open('target.txt') as f:
    domains = [line.strip() for line in f.readlines()]

ips = []
resolved = []
non_resolvable = []
cloudflare = []
for d in domains:
    try:
        result = dns.resolver.resolve(d, 'A')
        for r in result:
            print('A', d + ':', r.to_text())
            ips.append(r.to_text())
            resolved.append(d)
    except:
        non_resolvable.append(d)
    try:
        resultc = dns.resolver.resolve(d, 'CNAME')
        for v in resultc:
            print('CNAME : ', v.to_text())
            print('----------------------------------------------------')
    except:
        pass

print('')
print('-------------')
print("Non-Resolvable:")
for ln in non_resolvable:
    print(str(ln))

print('')
print('-------------')
uniq = sorted(set(ips))
print('Unique IPs for NMAP: ')
for l in uniq:
    print(str(l))


uni = sorted(set(resolved))
uniqness = list(uni)
with open('resolved.txt', 'a') as file:
    for u in uniqness:
        file.write(u + '\n')
