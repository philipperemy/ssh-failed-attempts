#!/usr/bin/python3.6

import gzip
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

if not sys.version_info.major == 3 and sys.version_info.minor >= 6:
    print("Python 3.6 or higher is required.")
    print("You are using Python {}.{}.".format(sys.version_info.major, sys.version_info.minor))
    sys.exit(1)

LOG_DIR = Path('/var/log/')
MC = 20

if not LOG_DIR.exists():
    print(f'ERROR: {LOG_DIR} does not exist. Are you running on Linux?')
    exit(1)

if len(sys.argv) > 1:
    try:
        MC = int(sys.argv[1])
    except:
        print('ERROR: Invalid value. Specify n to list the n most common attacks.')
        exit(1)


def persist_counter(c: Counter, filename: str):
    o = dict([(k, v) if isinstance(k, str) else (k[0] + '|' + k[1], v) for k, v in dict(c).items()])
    o = {k: v for k, v in sorted(o.items(), key=lambda item: item[1])}
    output_dir = Path('ssh-result')
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_dir / filename, 'w') as w:
        json.dump(obj=o, fp=w, indent=2)
    print(f'Dumped result to {output_dir / filename}.')


def print_counter(c: Counter):
    ljust = 30
    for cc in c.most_common(MC):
        key, value = cc
        if isinstance(key, str):
            print(f'{str(key).ljust(ljust)} : {value:,}')
        else:  # tuple
            a, b = key
            cc = a + ', ' + b
            print(f'{str(cc).ljust(ljust)} : {value:,}')
    print(f'{"TOTAL".ljust(ljust)} : {sum(c.values()):,}')


def read_line(line: str):
    matches = re.findall(pattern='Failed password for [a-zA-Z0-9]+ from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', string=line)
    if len(matches) > 0:
        assert len(matches) == 1
        match = matches[0]
        match2 = re.sub(' from ', ' ', re.sub('Failed password for ', '', match))
        ip = re.findall('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', match2)[0]
        user = re.sub(ip, '', match2).strip()

        repeated = re.findall(pattern='message repeated [0-9]+ times', string=line)
        if len(repeated) > 0:
            assert len(repeated) == 1
            count = int(re.findall('[0-9]+', repeated[0])[0])
        else:
            count = 1

        date = re.findall('^[a-zA-z]{3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}', line)
        if len(date) > 0:
            try: # won't work for Feb 29...
                d = datetime.strptime(date[0], '%b %d %H:%M:%S')
            except:
                return None
            d = d.replace(year=datetime.utcnow().year)
        else:
            d = None
        return ip, user, count, d
    return None


class Processor:

    def __init__(self):
        self.oldest_date = datetime.utcnow()
        self.ip_counter = Counter()
        self.user_counter = Counter()
        self.joint_counter = Counter()
        self.attempts = 0

    def print(self):
        print('------- Attackers IPs and their username guesses (most common) -------')
        print_counter(self.joint_counter)
        print('')
        print('------- Attackers IPs (most common) -------')
        print_counter(self.ip_counter)
        print('')
        print('------- Attackers username guesses (most common) -------')
        print_counter(self.user_counter)

    def apply(self, line: str):
        o = read_line(line)
        if o is not None:
            ip, user, count, d = o
            if d is not None and d < self.oldest_date:
                self.oldest_date = d
            for c in range(count):
                self.attempts += 1
                self.ip_counter[ip] += 1
                self.user_counter[user] += 1
                self.joint_counter[(ip, user)] += 1
                # if self.attempts % 10000 == 0:
                #     print(f'FOUND: {self.attempts} attempts...')

    def persist(self):
        persist_counter(self.joint_counter, 'ip_user.json')
        persist_counter(self.ip_counter, 'ip.json')
        persist_counter(self.user_counter, 'user.json')


def main():
    print('*******************************')
    print('** SSH ATTACKS COUNTER TOOL  **')
    print('*******************************')
    log_files = [f for f in LOG_DIR.iterdir() if f.is_file() and f.name.startswith('auth.log')]
    print(f'Found {len(log_files)} log files. It might take up to 1 minute to complete...')
    p = Processor()
    for log_file in log_files:
        print(f'- {log_file}')
        if log_file.suffix == '.gz':
            with gzip.open(log_file, 'r') as f:
                for line in f:
                    pass
                    p.apply(line.decode('utf8'))
        else:
            with open(str(log_file), 'r') as f:
                for line in f:
                    p.apply(line)
    p.print()
    p.persist()


if __name__ == '__main__':
    main()
