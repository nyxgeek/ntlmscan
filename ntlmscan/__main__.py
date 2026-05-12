#!/usr/bin/env python3
# 2019.10.22 - @nyxgeek - TrustedSec
# NTLM scanner - finds HTTP header that specifies NTLM auth

from queue import Queue
import threading
import requests
from requests.exceptions import Timeout
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urlparse
import os

outputfile = "output.log"
dictionaryfile = "paths.dict"
debugoutput = False
nmapscan = False
foundURLs = []
add_lock = threading.Lock()
queue = Queue()


def _default_dictionary_path():
    """Resolve bundled paths.dict (works when installed via pip/pipx)."""
    try:
        from importlib.resources import files as _resource_files
        path = _resource_files("ntlmscan") / "paths.dict"
        if path.is_file():
            return str(path)
    except Exception:
        pass
    try:
        import pkg_resources
        return pkg_resources.resource_filename("ntlmscan", "paths.dict")
    except Exception:
        pass
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "paths.dict")


def process_queue():
    while True:
        url = queue.get()
        makeRequests(url)
        queue.task_done()


def nmapScanner(foundURLs):
    for targeturl in foundURLs:
        print("Initializing nmap scan for {}".format(targeturl))
        parsedURL = urlparse(targeturl)
        targethost = parsedURL.hostname
        targetpath = parsedURL.path
        port = parsedURL.port
        if port is None:
            port = 80 if parsedURL.scheme == "http" else 443
        print("host:\t{host}\npath:\t{path}\nport:\t{port}".format(host=targethost, path=targetpath, port=port))
        nmapcmd = "nmap -Pn -sT -p{port} --script=http-ntlm-info --script-args=http-ntlm-info.root={path} {host}".format(
            port=port, path=targetpath, host=targethost
        )
        os.system(nmapcmd)


def makeRequests(url_data):
    global foundURLs
    url, force_ntlm, virtualhost = url_data
    with add_lock:
        print("[-] Testing path {}".format(url))
    try:
        if virtualhost:
            headers = {"Host": virtualhost}
        else:
            headers = {}
        if force_ntlm:
            headers["Authorization"] = "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="
        r = requests.head(url, timeout=3, headers=headers, verify=False)
        if debugoutput:
            print(r.headers)
        if "WWW-Authenticate" in r.headers:
            checkNTLM = r.headers["WWW-Authenticate"]
            if "NTLM" in checkNTLM:
                with add_lock:
                    if force_ntlm:
                        print(f"[+] FOUND FORCED NTLM - {url}")
                    else:
                        print("[+] FOUND NTLM - {}".format(url))
                    foundURLs.append(url)
                    with open(outputfile, "a") as outfilestream:
                        if force_ntlm:
                            outfilestream.write(f"[+] FOUND FORCED NTLM - {url}\n")
                        else:
                            outfilestream.write("[+] FOUND NTLM - {}\n".format(url))
    except requests.exceptions.ReadTimeout:
        pass
    except Exception:
        pass


def main():
    global outputfile, dictionaryfile, debugoutput
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="full url path to test")
    parser.add_argument("--host", help="a single host to search for ntlm dirs on")
    parser.add_argument("--virtualhost", help="Virtualhost header to add to --host")
    parser.add_argument("--hostfile", help="file containing ips or hostnames to test")
    parser.add_argument(
        "--urlfile",
        help="file containing full base URLs (supports alternate ports, e.g. http://host:8080/)",
    )
    parser.add_argument("--outfile", help="file to write results to")
    parser.add_argument(
        "--dictionary",
        help="list of paths to test, default: paths.dict (bundled when installed via pip/pipx)",
        default=_default_dictionary_path(),
    )
    parser.add_argument("--nmap", help="run nmap when complete", action="store_true", default=False)
    parser.add_argument("--debug", help="show request headers", action="store_true", default=False)
    parser.add_argument("--threads", help="Number of threads to use Default 100", type=int, default=100)
    parser.add_argument("--http", help="use HTTP instead of HTTPS when constructing URLs", action="store_true", default=False)
    parser.add_argument("--both", help="try both HTTP and HTTPS for each path", action="store_true", default=False)
    args = parser.parse_args()

    if args.http and args.both:
        parser.error("--http and --both are mutually exclusive")

    if not (args.url or args.host or args.hostfile or args.urlfile):
        parser.print_help()
        quit(1)

    if args.outfile:
        print("Output file set to {}".format(args.outfile))
        outputfile = args.outfile

    if args.dictionary:
        print("custom dictionary has been set to {}".format(args.dictionary))
        dictionaryfile = args.dictionary
        if not os.path.isfile(dictionaryfile) and not os.path.isabs(args.dictionary):
            dictionaryfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.dictionary)

    with open(dictionaryfile, "r") as pathdict:
        pathlist = pathdict.readlines()

    if args.debug:
        debugoutput = args.debug

    if args.nmap:
        nmapscan = True

    if args.both:
        schemes = ["http", "https"]
    elif args.http:
        schemes = ["http"]
    else:
        schemes = ["https"]

    if args.url:
        queue.put([args.url, False, None])

    if args.host:
        host_has_scheme = args.host[:4] == "http" if len(args.host) >= 4 else False
        for urlpath in pathlist:
            urlpath = urlpath.rstrip()
            if urlpath.startswith("/"):
                urlpath = urlpath[1:]
            if host_has_scheme:
                testurl = args.host.rstrip("/") + "/" + urlpath
                queue.put([testurl, False, args.virtualhost])
            else:
                for scheme in schemes:
                    testurl = scheme + "://" + args.host + "/" + urlpath
                    queue.put([testurl, False, args.virtualhost])
        if host_has_scheme:
            testurl = args.host.rstrip("/") + "/"
            queue.put([testurl, True, args.virtualhost])
        else:
            for scheme in schemes:
                testurl = scheme + "://" + args.host + "/"
                queue.put([testurl, True, args.virtualhost])

    if args.hostfile:
        with open(args.hostfile, "r") as hostfile:
            hostlist = hostfile.readlines()
        for hostname in hostlist:
            hostname = hostname.rstrip()
            host_has_scheme = hostname[:4] == "http" if len(hostname) >= 4 else False
            for urlpath in pathlist:
                urlpath = urlpath.rstrip()
                if urlpath.startswith("/"):
                    urlpath = urlpath[1:]
                if host_has_scheme:
                    testurl = hostname.rstrip("/") + "/" + urlpath
                    queue.put([testurl, False, args.virtualhost])
                else:
                    for scheme in schemes:
                        testurl = scheme + "://" + hostname + "/" + urlpath
                        queue.put([testurl, False, args.virtualhost])

    if args.urlfile:
        with open(args.urlfile, "r") as f:
            urllist = [line.rstrip() for line in f if line.strip()]
        for baseurl in urllist:
            for urlpath in pathlist:
                urlpath = urlpath.rstrip()
                if urlpath.startswith("/"):
                    urlpath = urlpath[1:]
                testurl = baseurl.rstrip("/") + "/" + urlpath
                queue.put([testurl, False, args.virtualhost])
            queue.put([baseurl.rstrip("/") + "/", True, args.virtualhost])

    for i in range(args.threads):
        t = threading.Thread(target=process_queue)
        t.daemon = True
        t.start()

    queue.join()
    print("\r\nTesting complete")

    if args.nmap:
        nmapScanner(foundURLs)

    if foundURLs:
        print("\n" + "=" * 50)
        print("NTLM URLs Found:")
        print("=" * 50)
        for url in foundURLs:
            print(f"  [+] {url}")
        print("=" * 50)
        print(f"Total: {len(foundURLs)} URL(s)")
    else:
        print("\nNo NTLM URLs found.")


if __name__ == "__main__":
    main()
