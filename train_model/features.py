import ipaddress
import re
import socket
from urllib.parse import urlparse
import urllib
from datetime import datetime
import time
import requests
from ipaddress import ip_address, IPv4Address, IPv6Address
from bs4 import BeautifulSoup
import tldextract
from whois import whois


def get_hostname(url):
    parsed_url = urlparse(url)
    return parsed_url.path if parsed_url.path == url else parsed_url.hostname



def is_ip(url):
    try:
        host_name = get_hostname(url)
        if host_name is None:
            if (type(ip_address(url)) is IPv4Address) or (type(ip_address(url)) is IPv6Address):
                return 1
        else:
            return 1 if type(ip_address(host_name)) is IPv4Address or IPv6Address else 0
    except:
        return 0



def length_url(url):
    return len(url)



def length_hostname(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    return len(hostname)


shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"


def tiny_url(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0



def countAtSign(url):
    return len(re.findall("\@", url))



def countQuestionMark(url):
    return len(re.findall("\?", url))


def countHyphen(url):
    return len(re.findall("\-", url))
def countDot(url):
    return len(re.findall("\.", url))


def countComma(url):
    return len(re.findall("\,", url))


def countSemicolon(url):
    return len(re.findall("\;", url))



def countDollar(url):
    return len(re.findall("\$", url))

def countAnd(url):
    return len(re.findall("\&", url))

def countSlash(url):
    return len(re.findall(r'/', url))


# redirect '//'
def have_redirect(url):
    parsed_url = urllib.parse.urlparse(url)
    protocol = parsed_url.scheme
    position = url.rfind('//')

    if (protocol == 'http' and position > 6) or (protocol == 'https' and position > 7):
        return 1
    else:
        return 0


def CountEqual(url):
    return len(re.findall("\=", url))



def CountPercent(url):
    return len(re.findall("\%", url))



def CountUnderScore(url):
    return len(re.findall("\_", url))



def CountDotHostName(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    return len(re.findall("\.", hostname))



def CountColon(url):
    return len(re.findall("\:", url))



def CountStar(url):
    return len(re.findall("\*", url))



def CountHttp(url):
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme
    if (protocol == "http" or protocol == "https"):
        return len(re.findall("http", url)) - 1
    return len(re.findall("http", url))



def check_https_protocol(url):
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme
    if protocol == 'https':
        return 1
    return 0



def RatioDigitsInHostname(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    return len(re.sub("[^0-9]", "", hostname)) / len(hostname)



def RatioDigitsURL(url):
    return len(re.sub("[^0-9]", "", url)) / len(url)



def have_prefixOrSuffix(url):
    domain = urlparse(url).netloc
    if '-' in domain:
        return 1
    else:
        return 0



def web_forwarding(response):
    if (response == ""):
        return 0
    return len(response.history)



# DomainRegLen
def DomainRegLen(whois_response):
    try:
        expiration_date = whois_response.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            return 0
    except:
        return 0



def DomainAge(domain_name):
    try:
        creation_date = domain_name.creation_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if creation_date:
            if type(creation_date) == list:
                creation_date = min(creation_date)
            return abs((creation_date - today).days)
        else:
            return 0
    except:
        return 0


def page_rank(key, url):
    domain = urlparse(url).netloc
    page = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    try:
        request = requests.get(page, headers={'API-OPR': key})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        return 0



def dns_expiration(url):
    try:
        return 0 if len(socket.gethostbyname(get_hostname(url))) > 0 else 1
    except:
        return 1



# LinksInScriptTags - Percentile of internal links
def LinksInScriptTags(soup, url):
    i, success = 0, 0
    if (soup == ""):
        return 0
    else:

        for link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in link['href'] or urlparse(url).netloc in link['href'] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for script in soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if url in script['src'] or urlparse(url).netloc in script['src'] or len(dots) == 1:
                success = success + 1
            i = i + 1
        try:
            percentage = success / float(i) * 100
            return percentage
        except:
            return 0


# AnchorURL 18
# Percentile of safe anchor
def AnchorURL(soup, url):
    if (soup == ""):
        return 0
    else:
        domain = urlparse(url).netloc
        i, unsafe = 0, 0
        for a in soup.find_all('a', href=True):
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                    url in a['href'] or domain in a['href']):
                unsafe = unsafe + 1
            i = i + 1

        try:
            percentage = (1 - unsafe / float(i)) * 100
            return percentage
        except:
            return 0

def popup_window(response):
  if response == "":
    return 0
  else: 
    if "prompt(" in str(response).lower():
      return 1
    else:
      return 0

def abnormal_subdomain(url):
    matches = re.findall('(http[s]?://(w[w]?|\d))([w]?(\d|-))', url)
    if matches:
        return 1
    return 0


def iframe(response):
    if response == "":
        return 0
    else:
        if re.compile(r"<iframe>|<frameBorder>").finditer(response):
            return 1
        else:
            return 0
##
def words_raw_extraction(domain, subdomain, path):
    w_domain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", domain.lower())
    w_subdomain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", subdomain.lower())
    w_path = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", path.lower())
    return w_domain, w_subdomain, w_path

# Word wrap
def word_raws(url):
    extracted_domain = tldextract.extract(url)
    subdomain = extracted_domain.subdomain
    path = url[url.find(extracted_domain.suffix):len(url)].partition("/")
    return words_raw_extraction(extracted_domain.domain, subdomain, path[2])
def raw_words(url):
    domain, subdomain, path = word_raws(url)
    raw_words = domain + path + subdomain
    return list(filter(None, raw_words))


def raw_words_host(url):
    domain, subdomain, path = word_raws(url)
    host = domain + subdomain
    return list(filter(None, host))


def raw_words_path(url):
    domain, subdomain, path = word_raws(url)
    return list(filter(None, path))

def count_www_path(url):
    return raw_words(url).count("www")



def count_com_path(url):
    return raw_words(url).count("com")


def length_word_raw(url):
    return len(raw_words(url))

def average_word_length(raw_words):
    if len(raw_words) == 0:
        return 0
    return sum(len(word) for word in raw_words) / len(raw_words)

def longest_word_length(raw_words):
    if len(raw_words) == 0:
        return 0
    return max(len(word) for word in raw_words)


def shortest_word_length(raw_words):
    if len(raw_words) == 0:
        return 0
    return min(len(word) for word in raw_words)


###################################################################################
# get token of neilpatel https://app.neilpatel.com/api/get_token
###################################################################################

def get_token():
    url = "https://app.neilpatel.com/api/get_token"
    params = {
        "debug": "app_norecaptcha"
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        token = data["token"]
        return token
    else:
        return None


###################################################################################
# check web traffic base on site https://app.neilpatel.com/en/traffic_analyzer
###################################################################################
def web_traffic(url):
    try:
        domain = get_hostname(url)
        if not domain.find('www') == -1:
            domain = domain.replace('www.', '')
        url = "https://app.neilpatel.com/api/domain_overview"
        headers = {
            "Authorization": "Bearer " + get_token()
        }
        params = {
            "domain": domain,
            "locId": 2840,
            "language": "en",
            "withKeywords": True
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()
            traffic = data["traffic"]
            return traffic
        else:
            return 0
    except:
        return 0


def whois_registered_domain(url):
    try:
        domain = get_hostname(url)
        hostname = whois(domain).domain_name
        if type(hostname) == list:
            for host in hostname:
                if re.search(host.lower(), domain):
                    return 1
            return 0
        else:
            if re.search(hostname.lower(), domain):
                return 1
            else:
                return 0
    except:
        return 0
