import aiohttp
import pandas as pd
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urlencode
import whois
import time

async def fetch(url, session):
    async with session.get(url) as response:
        return await response.text()

async def get_google_index(url, headers):
    async with aiohttp.ClientSession(headers=headers) as session:
        query = {'q': 'site:' + url}
        google = "https://www.google.com/search?" + urlencode(query)
        data = await fetch(google, session)
        soup = BeautifulSoup(data, "html.parser")
        try:
            if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
                return -1
            check = soup.find(id='rso').find('div').find('div').find('a')
            if check and check['href']:
                return 0
            else:
                return 1
        except:
            return 1

async def get_domain_age(url):
    try:
        res = whois.whois(url)
        creation_date = res.creation_date
        today = time.strftime('%Y-%m-%d')
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        delta = (today - creation_date).days
        return delta
    except:
        return -1

async def get_page_rank(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split('.')[-2] + '.' + parsed_url.netloc.split('.')[-1]
    api_url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    headers = {'API-OPR':'8sgwc0kg8oo0w84g8c8848scso0wcccg8o8s44o8'}
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(api_url) as response:
            result = await response.json()
            result = result['response'][0]['page_rank_integer']
            if result:
                return result
            else:
                return 0

async def extract_features(url):
    # define the list of columns to keep in the output dataframe
    cols_to_keep = ['nb_qm', 'ip', 'ratio_digits_url', 'phish_hints', 'google_index', 'nb_www', 'domain_age', 'page_rank']

    # create an empty dataframe with the desired columns
    df2 = pd.DataFrame(columns=cols_to_keep)

    # extract data for the 'nb_qm' column
    nb_qm = url.count('?')
    df2['nb_qm'] = [nb_qm]

    hostname = urlparse(url).hostname
    match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
            '[0-9a-fA-F]{7}', url)
    if match:df2['ip'] = 1
    else:df2['ip'] = 0

    # extract data for the 'ratio_digits_url' column
    url_length = len(url)
    digits = sum([1 for char in url if char.isdigit()])
    if url_length == 0:
        ratio_digits_url = 0
    else:
        ratio_digits_url = digits / url_length
    df2['ratio_digits_url'] = [ratio_digits_url]

    # extract data for the 'phish_hints' column
    HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']
    phish_hints = sum(url.lower().count(hint) for hint in HINTS)
    df2['phish_hints'] = [phish_hints]

    # extract data for the 'google_index' column
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    google_index = await get_google_index(hostname, headers)
    df2['google_index'] = [google_index]

    # extract data for the 'nb_www' column
    if hostname.startswith('www.'):
        nb_www = 1
    else:
        nb_www = 0
    df2['nb_www'] = [nb_www]

    # extract data for the 'domain_age' column
    domain_age = await get_domain_age(hostname)
    df2['domain_age'] = [domain_age]

    # extract data for the 'page_rank' column
    page_rank = await get_page_rank(url)
    df2['page_rank'] = [page_rank]

    return df2