#!/usr/bin/python3
import re

def get_bad_urls():
    with open("data/urls/domains_database", "rt") as urls_database:
        bad_urls = [line.strip() for line in urls_database]

    return bad_urls

def is_benign_task1(url, bad_urls):
    if url.endswith(".exe") or url.endswith(".com"):
        return False

    domain = re.search("[^/]*", url).group()

    if domain in bad_urls:
        return False

    if sum(c.isdigit() for c in domain) > 0.092 * len(domain):
        return False

    return True

def is_benign_task2(line, fields):
    benign = True
    duration_exceeded = False
    flag_count = 0
    count = 0

    seconds = None
    minutes = None

    time = None

    field = line.split(",")
    for i in range(len(field)):
        if fields[count] == "flow_duration":
            time_parts = field[i].split(':')

            minutes = float(time_parts[1])
            seconds = float(time_parts[2])

            time = 60.0 * minutes + seconds

            if time >= 1.0:
                duration_exceeded = True

        if fields[count] == "flow_pkts_payload.avg":
            if duration_exceeded and float(field[i]) > 580.0:
                benign = False

        if fields[count] in ["flow_FIN_flag_count", "flow_SYN_flag_count", "flow_ACK_flag_count"]:
            if field[i] == "0":
                flag_count += 1

        count += 1

    if flag_count == 3:
        benign = False

    return benign

def main():
    # taskul 1
    bad_urls = get_bad_urls()
    with open("data/urls/urls.in", "rt") as input:
        with open("urls-predictions.out", "wt") as output:
            for url in input:
                url = url.strip()

                if is_benign_task1(url, bad_urls):
                    output.write("0\n")
                else:
                    output.write("1\n")

    # taskul 2
    with open("data/traffic/traffic.in", "rt") as input:
        with open("traffic-predictions.out", "wt") as output:
            fields_line = input.readline().strip()
            fields = fields_line.split(",")

            for line in input:
                line = line.strip()

                if is_benign_task2(line, fields):
                    output.write("0\n")
                else:
                    output.write("1\n")

if __name__ == "__main__":
    main()