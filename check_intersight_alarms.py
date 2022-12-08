#!/bin/python3
# what: check intersight alarms for nagios
#  how: generate an intersight API key and pass in parameters
# deps: intersight, tabulate

import os
from datetime import datetime, timedelta
from tabulate import tabulate
import argparse

import intersight
import intersight.api.cond_api

signing_scheme = intersight.signing.SCHEME_RSA_SHA256
signing_algorithm = intersight.signing.ALGORITHM_RSASSA_PKCS1v15

EXIT_OK = 0
EXIT_WARN = 1
EXIT_CRITICAL = 2
EXIT_UNKNOWN = 3

Parser = argparse.ArgumentParser(description='Intersight Alarms')

# Handle params
def parse_args():
    Parser.add_argument(
        '--url',
        default='https://intersight.com',
        help='The Intersight root URL for the API endpoint')
    Parser.add_argument(
        '--filter',
        default='Severity ne Cleared',
        help='Intersight Alarms Filter')
    Parser.add_argument(
        '--period',
        type=int,
        default=30,
        help='Intersight Alarms Search Period')
    Parser.add_argument(
        '--api-key-id',
        required=True,
        help='API client key id for the HTTP signature scheme')
    Parser.add_argument(
        '--api-key-file',
        required=True,
        help='Name of file containing secret key for the HTTP signature scheme')

    return Parser.parse_args()


# Takes date object and returns formatted date string for use with intersight queries
def format_time(dt):
    s = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')
    return f"{s[:-3]}Z"

def alert(val, message):
    if val == EXIT_OK:
      print('OK')
    elif val == EXIT_WARN:
      print('WARNING')
    elif val == EXIT_CRITICAL:
     print('CRITICAL')
    elif val == EXIT_UNKNOWN:
     print('UNKNOWN')

    print(message)
    exit(val)


# Takes an array of results and creates a formatted table output (assumes all entries have the same keys)
def print_results_to_table(obj, ignored_fields=[]):
    temp_alarm_exit = 0
    alarm_exit      = 0

    headers = []
    entries = []

    if 'intersight' in str(type(obj[0])):
        headers = [ k for k in obj[0].to_dict().keys() if k not in ignored_fields ]
    else:
        headers = [ k for k in obj[0].keys() if k not in ignored_fields ]

    for entry in obj:
        row = []
        for h in headers:
            row.append(entry.get(h))
        entries.append(row)

        if alarm_exit != EXIT_CRITICAL:
          status = row[2]

          if status == 'Critical':
            temp_alarm_exit = EXIT_CRITICAL

          elif status == 'Warning':
            temp_alarm_exit = EXIT_WARN

          if temp_alarm_exit > alarm_exit:
             alarm_exit = temp_alarm_exit

    alert(alarm_exit, f"<pre>{tabulate(entries, headers=headers)}</pre>")


def main():

    args = parse_args()

    configuration = intersight.Configuration(
        host=args.url,
        signing_info=intersight.HttpSigningConfiguration(
            key_id=args.api_key_id,
            private_key_path=args.api_key_file,
            signing_scheme=signing_scheme,
            signing_algorithm=signing_algorithm,
            hash_algorithm=intersight.signing.HASH_SHA256,
            signed_headers=[intersight.signing.HEADER_REQUEST_TARGET,
                            intersight.signing.HEADER_CREATED,
                            intersight.signing.HEADER_EXPIRES,
                            intersight.signing.HEADER_HOST,
                            intersight.signing.HEADER_DATE,
                            intersight.signing.HEADER_DIGEST,
                            'Content-Type',
                            'User-Agent'
                            ],
            signature_max_validity=timedelta(minutes=5)
        )
    )

    client = intersight.ApiClient(configuration)
    client.set_default_header('referer', args.url)
    client.set_default_header('x-requested-with', 'XMLHttpRequest')
    client.set_default_header('Content-Type', 'application/json')
    try:
        api_instance = intersight.api.cond_api.CondApi(client)

        search_period = datetime.now() - timedelta(days=args.period)
        query_filter = f"{args.filter} and LastTransitionTime gt {format_time(search_period)}"
        query_select = "Severity,LastTransitionTime,Description"

        alarm_query = api_instance.get_cond_alarm_list(filter=query_filter, select=query_select)

        if alarm_query.results:
            print_results_to_table(alarm_query.results, ignored_fields=['class_id', 'object_type', 'moid'])
        else:
            alert(EXIT_OK, 'No alarms found')

    except intersight.OpenApiException as e:
        exit(EXIT_UNKNOWN, 'Exception when calling API')

if __name__ == "__main__":
    main()
