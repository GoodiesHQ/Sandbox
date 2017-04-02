#!/usr/bin/env python3

from argparse import ArgumentParser, ArgumentTypeError
import asyncio
import aiodns
import sys

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

RTYPES = (
    "A", "AAAA", "MX",
    # "CNAME", "MX", "NAPTR", "NS", "PTR", "SOA", "SRV", "TXT"
)

SUBNAMES = tuple({
    "admin", "administration", "ads", "adserver", "alerts", "alpha", "ap", "apache", "app", "apps", "appserver", "aptest", "auth", "backup", "beta", "blog", "cdn", "chat", "citrix", "cms", "corp", "crs", "cvs", "database", "db", "demo", "dev", "devel", "development", "devsql", "devtest", "dhcp", "direct", "dmz", "dns", "dns0", "dns1", "dns2", "download", "en", "erp", "eshop", "exchange", "f5", "fileserver", "firewall", "forum", "ftp", "ftp0", "git", "gw", "help", "helpdesk", "home", "host",
    "http", "id", "images", "info", "internal", "internet", "intra", "intranet", "ipv6", "lab", "ldap", "linux", "local", "log", "mail", "mail2", "mail3", "mailgate", "main", "manage", "mgmt", "mirror", "mobile", "monitor", "mssql", "mta", "mx", "mx0", "mx1", "mysql", "news", "noc", "ns", "ns0", "ns1", "ns2", "ns3", "ntp", "ops", "oracle", "owa", "pbx", "s3", "secure", "server", "shop", "sip", "smtp", "sql", "squid", "ssh", "ssl", "stage", "stats", "svn", "syslog", "test", "test1", "test2",
    "testing", "upload", "vm", "vnc", "voip", "vpn", "web", "web2test", "whois", "wiki", "www", "www2", "xml", "dc", "dc01", "dc1", "dc02", "dc2", "dc03", "dc3",
})  # In case I add duplicates by mistake, tuple(set()) them...

print("""
  ____  _   _ ____  ____             _
 |  _ \| \ | / ___|| __ ) _ __ _   _| |_ ___
 | | | |  \| \___ \|  _ \| '__| | | | __/ _ \\
 | |_| | |\  |___) | |_) | |  | |_| | |_  __/
 |____/|_| \_|____/|____/|_|   \__,_|\__\___|

 """)

@asyncio.coroutine
def resolve(sub, domain, rtype, sem, fmt, loop=None):
    loop = loop or asyncio.get_event_loop()
    dom = "{}.{}".format(sub, domain)
    with (yield from sem):
        try:
            resolver = aiodns.DNSResolver(loop=loop)
            results = yield from resolver.query(dom, rtype)
            if rtype in ("A", "AAAA", "MX"):
                hosts = ', '.join(res.host for res in results)
                print(fmt.format(dom, rtype, hosts), flush=True)
            else:
                pass
                print("Type: {}".format(rtype))
                print(results)
        except aiodns.error.DNSError:
            pass
        except Exception as e:
            print("Error: ", e, file = sys.stderr)


def brute(domain, connections, artype):
    longest_sd = len(max(SUBNAMES, key=len)) + len(domain)
    longest_rt = len(max(RTYPES, key=len)) + 2
    fmt = "{{:<{}}} {{:<{}}} {{}}".format(longest_sd, longest_rt)
    sem = asyncio.BoundedSemaphore(connections)
    loop = asyncio.get_event_loop()
    resolutions = [resolve(sub, domain, rtype, sem, fmt) for sub in SUBNAMES for rtype in RTYPES]
    loop.run_until_complete(asyncio.gather(*resolutions))


def main():
    ap = ArgumentParser()
    ap.add_argument("-c", "--connections", type=int, default=50, help="Number of concurrent resolutions")
    ap.add_argument("-d", "--domain", type=str, required=True, help="The domain you'd like kkk")
    args = ap.parse_args()
    brute(args.domain, args.connections, 'A')

if __name__ == "__main__":
    main()
