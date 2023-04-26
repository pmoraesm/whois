
import os
import sys
from ast import literal_eval

import pandas as pd
from ipwhois import IPWhois


def read_data(data):
    df = pd.read_csv(data)
    return df


def get_sample_ip(df):
    df['sample_ip'] = df['IPs'].apply(lambda x: literal_eval(x)[0])
    return df


def _get_whois_info(ip_address):
    try:
        whois_obj = IPWhois(ip_address)
        whois_res = whois_obj.lookup_whois()
        print(f"Getting IP info for {ip_address}")
        whois_res['asn_description'] = whois_res['asn_description'].replace(",", "")
        print(whois_res['asn_description'], whois_res['asn_cidr'])
    except Exception as e:
        whois_res = {}
        whois_res['asn_description'] = e
        whois_res['asn_cidr'] = '0.0.0.0'
    return pd.Series([whois_res['asn_description'], whois_res['asn_cidr']])


def add_whois_info(df):
    df[['whois_desc', 'whois_cidr']] = df['sample_ip'].apply(lambda x: _get_whois_info(x))
    return df


def main():
    qdata = sys.argv[1]
    filepath = os.path.splitext(qdata)[0]
    df = read_data(qdata)
    get_sample_ip(df)
    add_whois_info(df)
    df.to_csv(f"{filepath}_results.csv", index=False)


if __name__ == "__main__":
    main()