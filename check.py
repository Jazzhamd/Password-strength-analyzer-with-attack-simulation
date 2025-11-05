import requests
import hashlib
import sys
from requests.exceptions import RequestException, ConnectionError, Timeout


def request_api_data(char):
    url = 'https://api.pwnedpasswords.com/range/' + char
    try:
        res = requests.get(url, timeout=5)
        res.raise_for_status()
        return res
    except (ConnectionError, Timeout):
        # No internet / timeout — silently indicate no data
        return None
    except RequestException as e:
        print(f"HIBP API error: {e}")
        return None



def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    if response is None:
        # No connection or error — skip lookup
        return None
    print(response)
    return get_password_leaks_count(response, tail)


def check_password(password):
    count = pwned_api_check(password)
    if count is None:
        return "Network unavailable - breach check skipped."
    if count:
        return f'Your password was found {count} times. You should change it'
    else:
        return f"Your password wasn't found. You're good to go"

if __name__ == '__main__':
    import sys
    print(check_password(sys.argv[1]))


