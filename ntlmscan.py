#!/usr/bin/env python3


# 2019.10.22 - @nyxgeek - TrustedSec
#
# NTLM scanner - just looks for HTTP header that specifies NTLM auth
# takes a url, or a list of hosts

from queue import Queue
import threading
import requests
from requests.exceptions import Timeout
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from urllib.parse import urlparse
import os

dictionaryfile = "paths.dict"
outputfile = "output.log"
debugoutput = False
nmapscan = False
foundURLs = []
add_lock = threading.Lock()
queue = Queue()


def process_queue():
    while True:
        url = queue.get()
        makeRequests(url)
        queue.task_done()


def nmapScanner(foundURLs):
    # if nmap was selected, let's do some scans
    for targeturl in foundURLs:
        print("Initializing nmap scan for {}".format(targeturl))
        parsedURL = urlparse(targeturl)
        targethost = parsedURL.hostname
        targetpath = parsedURL.path
        print("host:\t{host}\npath:\t{path}".format(host=targethost, path=targetpath))

        nmapcmd = "nmap -Pn -sT -p443 --script=http-ntlm-info --script-args=http-ntlm-info.root={path} {host}".format(
            path=targetpath, host=targethost
        )
        returned_nmap = os.system(nmapcmd)
        print(returned_nmap)


def makeRequests(url_data):
    global foundURLs
    url, force_ntlm, virtualhost = url_data
    # print("\r[-] Testing path {}".format(url), end='')
    with add_lock:
        print("[-] Testing path {}".format(url))
    try:
        if virtualhost:
            headers = {"Host": virtualhost}
        else:
            headers = {}
        if force_ntlm:
            # This checks for forced NTLM, which would show positive on every URL on the site
            headers[
                "Authorization"
            ] = "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="

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
                    # here we open the file quick to write to it - we might want to relocate this open/close to outside here
                    with open(outputfile, "a") as outfilestream:
                        if force_ntlm:
                            outfilestream.write(f"[+] FOUND FORCED NTLM - {url}\n")
                        else:
                            outfilestream.write("[+] FOUND NTLM - {}\n".format(url))
    except requests.exceptions.ReadTimeout:
        # print("\r", end='')
        pass

    except Exception:
        # print("Unexpected error:", sys.exc_info()[0])
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="full url path to test")
    parser.add_argument("--host", help="a single host to search for ntlm dirs on")
    parser.add_argument("--virtualhost", help="Virtualhost header to add to --host")
    parser.add_argument("--hostfile", help="file containing ips or hostnames to test")
    parser.add_argument("--outfile", help="file to write results to")
    parser.add_argument(
        "--dictionary",
        help="list of paths to test, default: paths.dict",
        default=os.path.dirname(os.path.abspath(__file__)) + "/paths.dict",
    )
    parser.add_argument(
        "--nmap", help="run nmap when complete", action="store_true", default=False
    )
    parser.add_argument(
        "--debug", help="show request headers", action="store_true", default=False
    )
    parser.add_argument(
        "--threads", help="Number of threads to use Default 100", type=int, default=100
    )
    args = parser.parse_args()

    # print help if no host arguments are supplied
    if not (args.url or args.host or args.hostfile):
        parser.print_help()
        quit(1)
    # check to see if a custom outfile has been specified
    if args.outfile:
        print("Output file set to {}".format(args.outfile))
        outputfile = args.outfile

    # check to see if a custom dictionary is set
    if args.dictionary:
        print("custom dictionary has been set to {}".format(args.dictionary))
        dictionaryfile = args.dictionary
        if not os.path.isfile(dictionaryfile):
            dictionaryfile = os.path.dirname(__file__) + args.dictionary

    # now that we have that sorted, load the dictionary into array called pathlist
    # print("Using dictionary located at: {}".format(dictionaryfile))
    with open(dictionaryfile, "r") as pathdict:
        pathlist = pathdict.readlines() + [""]

    if args.debug:
        debugoutput = args.debug

    if args.nmap:
        nmapscan = True

    ## NOW, HERE ARE THE MAIN WORKHORSE FUNCTION CALLS ##

    if args.url:
        queue.put([args.url, False])

    if args.host:
        for urlpath in pathlist:
            urlpath = urlpath.rstrip()
            if urlpath.startswith("/"):
                urlpath = urlpath[1:]
            if args.host[:4] == "http":
                testurl = args.host + "/" + urlpath
            else:
                testurl = "https://" + args.host + "/" + urlpath

            queue.put([testurl, False, args.virtualhost])

        if args.host[:4] == "http":
            testurl = args.host + "/"
        else:
            testurl = "https://" + args.host + "/"

        queue.put([testurl, True, args.virtualhost])
    if args.hostfile:
        with open(args.hostfile, "r") as hostfile:
            hostlist = hostfile.readlines()

        for hostname in hostlist:
            hostname = hostname.rstrip()

            for urlpath in pathlist:
                urlpath = urlpath.rstrip()
                if urlpath.startswith("/"):
                    urlpath = urlpath[1:]
                if hostname[:4] == "http":
                    testurl = hostname + "/" + urlpath
                else:
                    testurl = "https://" + hostname + "/" + urlpath
                queue.put([testurl, False, args.virtualhost])
    # Get ready to queue some requests
    for i in range(args.threads):
        t = threading.Thread(target=process_queue)
        t.daemon = True
        t.start()

    queue.join()
    print("\r\nTesting complete")

    if args.nmap:
        nmapScanner(foundURLs)
