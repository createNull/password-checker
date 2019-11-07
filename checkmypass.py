import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check API and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count


def pwned_api_check(password):
    # check if pw exists in API response
    sha1pw = hashlib.sha1(password.encode()).hexdigest().upper()
    first5_char, tail = sha1pw[:5], sha1pw[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def check_my_pass(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times')
        else:
            print(f'{password} was NOT found')
    return 'Done!'


if __name__ == '__main__':
    sys.exit(check_my_pass(sys.argv[1:]))
