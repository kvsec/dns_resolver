# dns_resolver
Allows to resolve hosts and collect a list of IP addresses for further nmap scan avoiding WAFs and custom organizations depending on the purpose. 

<code>organizations</code> section in the script allows to exclude IPs related to certain organizations that are out of scope.

Install:

```pip install ipwhois```

```pip install dnspython==2.2.0```


Run (the script require "<b>target.txt</b>" file to run):

<code>python3 dns_resolver.py</code>
