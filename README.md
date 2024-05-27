# ZeroSSL-CertRenew
A python script that automatically renews the certificate on ZeroSSL

Change following variables:

``` python
        self.proxies = None
        self.apiKey = 'your api key' #https://app.zerossl.com/developer
        self.certificateDomain = 'your domain name'
        self.install_loc = '/etc/nginx/ssl/'
        self.web_root = '/var/www/html/'
```

The script will download certificates to self.install_loc.

OpenSSL is used to create the private key and csr.

There is no exception handling anywhere in the code, so things might not be stable.

Execute the script with

	python3 ZeroSSL_CertRenew.py

For users who cannot use acme certbot
