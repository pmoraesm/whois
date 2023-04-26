
import os
import sys
from ast import literal_eval

import pandas as pd
from ipwhois import IPWhois


def read_data(data):
    """Creates Pandas df from CSV

    Args:
        data (str): Filepath of the CSV file

    Returns:
        pandas.core.frame.DataFrame: Pandas dataframe containing CSV data
    """
    df = pd.read_csv(data)
    return df


def get_sample_ip(df):
    """Creates a new 'sample_ip' column with the first IP from the array in 'IPs' column

    Args:
        df (pandas.core.frame.DataFrame): Original Pandas df 

    Returns:
        pandas.core.frame.DataFrame:: Pandas df with 'sample_ip'
    """
    df['sample_ip'] = df['IPs'].apply(lambda x: literal_eval(x)[0])
    return df


def _get_whois_info(ip_address):
    """Performs WHOIS query and returns PD series object with ASN Description and ASN CIDR

    Args:
        ip_address (str): IP address to be used in the WHOIS query

    Returns:
        pandas.core.series.Series: Pandas series object with asn_description and asn_cidr
    """
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
    """Adds new 'whois_desc' and 'whois_cidr' to dataframe using Pandas apply

    Args:
        df (pandas.core.frame.DataFrame): Pandas dataframe containing 'sample_ip' column

    Returns:
        pandas.core.frame.DataFrame: Pandas df with 'whois_desc' and 'whois_cidr' columns
    """
    df[['whois_desc', 'whois_cidr']] = df['sample_ip'].apply(lambda x: _get_whois_info(x))
    return df


def main():
    """Main function
    """
    # Reads filepath and strips extension for renaming
    qdata = sys.argv[1]
    filepath = os.path.splitext(qdata)[0]

    # Read input query data
    df = read_data(qdata)

    # Fetch sample ip from IPs list
    get_sample_ip(df)

    # Enrich with WHOIS information
    add_whois_info(df)

    # Write results to CSV file
    df.to_csv(f"{filepath}_results.csv", index=False)


if __name__ == "__main__":
    main()