# ntlmscan
scan for NTLM directories

reliable targets are:
* OWA servers
* Skype for Business/Lync servers
* Autodiscover servers (autodiscover.domain.com and lyncdiscover.domain.com)
* ADFS servers


once identified, use nmap and the [http-ntlm-info](https://nmap.org/nsedoc/scripts/http-ntlm-info.html) script to extract internal domain/server information

## Install

**pipx** (recommended):
```
pipx install git+https://github.com/nyxgeek/ntlmscan.git
```

**uv**:
```
uv tool install git+https://github.com/nyxgeek/ntlmscan.git
```

**pip**:
```
pip install git+https://github.com/nyxgeek/ntlmscan.git
```

Or just clone and run directly — no install needed:
```
git clone https://github.com/nyxgeek/ntlmscan.git
cd ntlmscan
python3 ntlmscan.py --host target.com
```

## Usage

```
usage: ntlmscan.py [-h] [--url URL] [--host HOST] [--virtualhost VIRTUALHOST]
                   [--hostfile HOSTFILE] [--urlfile URLFILE]
                   [--outfile OUTFILE] [--dictionary DICTIONARY] [--nmap]
                   [--debug] [--threads THREADS] [--http] [--both]

optional arguments:
  -h, --help              show this help message and exit
  --url URL               full url path to test
  --host HOST             a single host to search for ntlm dirs on
  --virtualhost VIRTUALHOST  Virtualhost header to add to --host
  --hostfile HOSTFILE     file containing ips or hostnames to test
  --urlfile URLFILE       file containing full base URLs (supports alternate ports)
  --outfile OUTFILE       file to write results to
  --dictionary DICTIONARY list of paths to test, default: paths.dict
  --nmap                  run nmap with http-ntlm-info after testing (requires nmap)
  --debug                 show request headers
  --threads THREADS       number of threads (default: 100)
  --http                  use HTTP instead of HTTPS when constructing URLs
  --both                  try both HTTP and HTTPS for each path
 ```

## Examples

 ```
 python3 ntlmscan.py --url https://autodiscover.domain.com/autodiscover

 python3 ntlmscan.py --host autodiscover.domain.com

 python3 ntlmscan.py --hostfile hosts.txt --dictionary big.txt

 python3 ntlmscan.py --host mail.domain.com --both --threads 50
 ```

If installed via pipx/uv, use `ntlmscan` instead of `python3 ntlmscan.py`:
```
ntlmscan --host autodiscover.domain.com
```

![Screenshot of usage](http://nyxgeek.com/ntlmscan.py_use3.png)
