from bs4 import BeautifulSoup
import pandas as pd
import math
import requests
import json
import re
import os
import time
from datetime import datetime
from zenrows import ZenRowsClient
import time
from DrissionPage import ChromiumPage


zenrows_api_key = ''


def clean_header(head):
    header_dict = {}
    split_new_line = head.split('\n')
    for x in split_new_line:
        if x != '':
            x = x.lstrip(':').split(': ')
            header_dict[x[0]] = x[1]
    for n in header_dict.items():
        output = f"'{n[0]}': '{n[-1]}',"
        print(output)


def status_log(response=None, url=None):
    print(f"Logging status: {response.status_code if response else 'No response'}")
    if url:
        print(f"URL: {url}")
    with open('status_log.txt', 'a') as f:
        f.write(f"Status: {response.status_code if response else 'No response'}, URL: {url}\n")


def retry(func, retries=5):
    """Decorator function to retry a function call upon connection errors."""
    def retry_wrapper(*args, **kwargs):
        attempt = 0
        while attempt < retries:
            try:
                return func(*args, **kwargs)
            except requests.exceptions.ConnectionError as e:
                attempt += 1
                total_time = attempt * 10
                print(f'Retrying {attempt}: Sleeping for {total_time} seconds, error: {e}')
                time.sleep(total_time)
                if attempt == retries:
                    log_retry_failure(args[0], 'requests.exceptions.ConnectionError')
        print("Stopped after retries, check network connection")
        raise SystemExit

    return retry_wrapper


def log_retry_failure(url, error_type):
    '''Log URL and error type after retries are exhausted'''
    url_log_file = 'url_log.txt'
    with open(url_log_file, 'a') as file:
        file.write(f'{url}, {error_type}\n')


ses = requests.Session()


@retry
def get_soup_verify(url, headers=None):
    try:
        r = ses.get(url, headers=headers, timeout=500, verify=False)
    except requests.exceptions.Timeout:
        print(f'Timeout error for URL: {url}')
        status_log(url=url)
        return None
    if r.status_code == 200:
        soup = BeautifulSoup(r.text, 'html.parser')
        return soup
    elif 499 >= r.status_code >= 400:
        print(f'client error response, status code {r.status_code} \nrefer: {r.url}')
        status_log(response=r, url=r.url)
        return None
    elif 599 >= r.status_code >= 500:
        print(f'server error response, status code {r.status_code} \nrefer: {r.url}')
        count = 1
        while count != 10:
            print('while', count)
            r = requests.Session().get(url, headers=headers, timeout=500, verify=False)
            print('status_code: ', r.status_code)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                return soup
            else:
                print('retry ', count)
                count += 1
                time.sleep(count * 2)
                status_log(response=r, url=r.url)
                return None

    else:
        status_log(response=r, url=r.url)
        return None



@retry
def get_soup(url, headers=None):
    try:
        r = ses.get(url, headers=headers, timeout=500)
    except requests.exceptions.Timeout:
        print(f'Timeout error for URL: {url}')
        status_log(url=url)
        return None
    if r.status_code == 200:
        soup = BeautifulSoup(r.text, 'html.parser')
        return soup
    elif 499 >= r.status_code >= 400:
        print(f'client error response, status code {r.status_code} \nrefer: {r.url}')
        status_log(response=r, url=r.url)
        return None
    elif 599 >= r.status_code >= 500:
        print(f'server error response, status code {r.status_code} \nrefer: {r.url}')
        count = 1
        while count != 10:
            print('while', count)
            r = requests.Session().get(url, headers=headers, timeout=500)
            print('status_code: ', r.status_code)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                return soup
            else:
                print('retry ', count)
                count += 1
                time.sleep(count * 2)
                status_log(response=r, url=r.url)
                return None
    else:
        status_log(response=r, url=r.url)
        return None


@retry
def post_soup(url, headers=None, payload=None):
    try:
        r = ses.post(url, headers=headers, json=payload, timeout=500)
    except requests.exceptions.Timeout:
        print(f'Timeout error for URL: {url}')
        status_log(url=url)
        return None
    if r.status_code == 200:
        soup = BeautifulSoup(r.text, features="html.parser")
        return soup
    elif 499 >= r.status_code >= 400:
        print(f'client error response, status code {r.status_code} \nrefer: {r.url}')
        status_log(response=r, url=r.url)
        return None
    elif 599 >= r.status_code >= 500:
        print(f'server error response, status code {r.status_code} \nrefer: {r.url}')
        count = 1
        while count != 10:
            print('while', count)
            r = requests.Session().post(url, headers=headers, json=payload, timeout=500)
            print('status_code: ', r.status_code)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                return soup
            else:
                print('retry ', count)
                count += 1
                time.sleep(count * 2)
                status_log(response=r, url=r.url)
                return None
    else:
        status_log(response=r, url=r.url)
        return None


@retry
def get_json_response(url, headers=None):
    try:
        r = ses.get(url, headers=headers, timeout=500)
    except requests.exceptions.Timeout:
        print(f'Timeout error for URL: {url}')
        status_log(url=url)
        return None
    if r.status_code == 200:
        data_ = r.json()
        return data_
    elif 499 >= r.status_code >= 400:
        print(f'client error response, status code {r.status_code} \nrefer: {r.url}')
        status_log(response=r, url=r.url)
        return None
    elif 599 >= r.status_code >= 500:
        print(f'server error response, status code {r.status_code} \nrefer: {r.url}')
        count = 1
        while count != 10:
            print('while', count)
            r = requests.get(url, headers=headers, timeout=500)
            print('status_code: ', r.status_code)
            if r.status_code == 200:
                data_ = r.json()
                return data_
            else:
                print('retry ', count)
                count += 1
                time.sleep(count * 2)
                status_log(response=r, url=r.url)
                return None
    else:
        status_log(response=r, url=r.url)
        return None


@retry
def post_json_response(url, headers=None, payload=None):
    try:
        r = ses.post(url, headers=headers, json=payload, timeout=500)
    except requests.exceptions.Timeout:
        print(f'Timeout error for URL: {url}')
        status_log(url=url)
        return None
    if r.status_code == 200:
        return r.json()
    elif 499 >= r.status_code >= 400:
        print(f'client error response, status code {r.status_code} \nrefer: {r.url}')
        status_log(response=r, url=r.url)
        return None
    elif 599 >= r.status_code >= 500:
        print(f'server error response, status code {r.status_code} \nrefer: {r.url}')
        count = 1
        while count != 10:
            print('while', count)
            r = ses.post(url, headers=headers, json=payload, timeout=500)
            print('status_code: ', r.status_code)
            if r.status_code == 200:
                return r.json()
            else:
                print('retry ', count)
                count += 1
                time.sleep(count * 2)
                status_log(response=r, url=r.url)
                return None
    else:
        status_log(response=r, url=r.url)
        return None


@retry
def get_zenrowa(url, params=None):
    try:
        client = ZenRowsClient(zenrows_api_key)
        r = client.get(url, params=params)
    except requests.exceptions.Timeout:
        print(f'Timeout error for URL: {url}')
        status_log(url=url)
        return None
    if r.status_code == 200:
        soup = BeautifulSoup(r.text, 'html.parser')
        return soup
    elif 499 >= r.status_code >= 400:
        print(f'client error response, status code {r.status_code} \nrefer: {r.url}')
        status_log(response=r, url=r.url)
        return None
    elif 599 >= r.status_code >= 500:
        print(f'server error response, status code {r.status_code} \nrefer: {r.url}')
        count = 1
        while count != 10:
            print('while', count)
            client = ZenRowsClient('52e9cd0e048a062fba225a28c885b96cc873feb7')
            r = client.get(url, params=params)
            print('status_code: ', r.status_code)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                return soup
            else:
                print('retry ', count)
                count += 1
                time.sleep(count * 2)
                status_log(response=r, url=r.url)
                return None
    else:
        status_log(response=r, url=r.url)
        return None


class CloudflareBypasser:
    def __init__(self, driver: ChromiumPage):
        self.driver = driver

    def clickCycle(self):
        if self.driver.wait.ele_displayed('xpath://div/iframe',timeout=1.5):
            time.sleep(1.5)
            self.driver('xpath://div/iframe').ele("Verify you are human", timeout=2.5).click()

    def isBypassed(self):
        title = self.driver.title.lower()
        return "just a moment" not in title

    def bypass(self):
        while not self.isBypassed():
            time.sleep(2)
            print("Verification page detected.  Trying to bypass...")
            time.sleep(2)
            self.clickCycle()


def strip_it(text):
    return re.sub(r"\s+", ' ', text).strip()