#!/usr/bin/env python


# 2019.10.22 - @nyxgeek
#
# NTLM scanner - just looks for HTTP header that specifies NTLM auth
# takes a url, or a list of hosts


import requests
from requests.exceptions import Timeout
import argparse
import sys
#import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dictionaryfile = 'paths.dict'
outputfile = 'output.log'

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="full url path to test")
    parser.add_argument("--host", help="a single host to search for ntlm dirs on")
    parser.add_argument("--hostfile", help="file containing ips or hostnames to test")
    parser.add_argument("--outfile", help="file to write results to")
    parser.add_argument("--dictionary", help="list of paths to test, default: paths.dict")
    args = parser.parse_args()

    # check to see if a custom outfile has been specified
    if args.outfile:
        print("Output file set to {}".format(args.outfile))
        global outputfile
        outputfile = args.outfile

    # check to see if a custom dictionary is set
    if args.dictionary:
        print("custom dictionary has been set to {}".format(args.dictionary))
        global dictionaryfile
        dictionaryfile = args.dictionary

    # now that we have that sorted, load the dictionary into array called pathlist
    #print("Using dictionary located at: {}".format(dictionaryfile))
    pathdict = open(dictionaryfile, 'r')
    pathlist = pathdict.readlines()
    pathdict.close()

   ## NOW, HERE ARE THE MAIN WORKHORSE FUNCTION CALLS ##

    if args.url:
        makeRequests(args.url)


    if args.host:
        for urlpath in pathlist:
            urlpath = urlpath.rstrip()
            testurl = "https://" + args.host + "/" + urlpath
            makeRequests(testurl)


    if args.hostfile:
        hostfile = open(args.hostfile, 'r')
        hostlist = hostfile.readlines()
        hostfile.close()

        for hostname in hostlist:
            hostname = hostname.rstrip()

            for urlpath in pathlist:
                urlpath = urlpath.rstrip()
                testurl = "https://" + hostname + "/" + urlpath
                makeRequests(testurl)

    print("\r\nTesting complete")


def makeRequests(url):
    #print("\r[-] Testing path {}".format(url), end='')
    print("[-] Testing path {}".format(url))
    try:
        r = requests.head(url, timeout=3,verify=False)
        if 'WWW-Authenticate' in r.headers:

            print("[+] FOUND NTLM - {}".format(url))

            # here we open the file quick to write to it - we might want to relocate this open/close to outside here
            outfilestream = open(outputfile,"w+")
            outfilestream.write("[+] FOUND NTLM - {}".format(url))
            outfilestream.close()

    except requests.exceptions.ReadTimeout:
        #print("\r", end='')
        pass

    except Exception:
        #print("Unexpected error:", sys.exc_info()[0])
        pass


if __name__ == '__main__':
        main()
