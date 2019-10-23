# ntlmscan
scan for NTLM directories

reliable targets are:
* OWA servers
* Skype for Business/Lync servers
* Autodiscover servers (autodiscover.domain.com and lyncdiscover.domain.com)


once identified, use nmap and the [http-ntlm-info](https://nmap.org/nsedoc/scripts/http-ntlm-info.html) script to extract internal domain/server information 


```
usage: ntlmscan.py [-h] [--url URL] [--host HOST] [--hostfile HOSTFILE]
                   [--outfile OUTFILE] [--dictionary DICTIONARY]

optional arguments:
  -h, --help              show this help message and exit
  --url URL               full url path to test
  --host HOST             a single host to search for ntlm dirs on
  --hostfile HOSTFILE     file containing ips or hostnames to test
  --outfile OUTFILE       file to write results to
  --dictionary DICTIONARY list of paths to test, default: paths.dict
 ```

![Screenshot of usage](http://nyxgeek.com/ntlmscan.py_use3.png)
