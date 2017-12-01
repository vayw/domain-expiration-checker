# check functions
from datetime import datetime
import ssl, socket

def certs_check(domains_list, cachedata={}):
    """Check all domains from domains_list.
    Return dict with domain name as KEY and count of remained days as VALUE
    VALUE also can be:
    -1 : if cert doesnt match hostname
    -2 : for other errors
    """
    result = {}
    for name in domains_list:
        if name not in cachedata:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(socket.socket(), server_hostname=name)
            try:
                s.connect((name, 443))
            except ssl.CertificateError:
                result[name]= -1
                continue
            except:
                result[name]= -2
                continue
            cert = s.getpeercert()
            s.close()
            exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        else:
            if cachedata[name] < 0:
                res = certs_check([name])
                exp_date = res[name]
            else:
                exp_date = datetime.fromtimestamp(cachedata[name])
        now = datetime.now()
        delta = exp_date - now
        result[name] = delta.days
    return result
