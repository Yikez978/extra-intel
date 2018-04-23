import time
import sys
import requests
import OTXv2
import configparser
import urllib3

from OTXv2 import OTXv2, IndicatorTypes

urllib3.disable_warnings()

# parsing this config on the fly because threat intel stuff isn't necessary globally?
config = configparser.ConfigParser()
config.read('config.ini')


def analyze_extrahop_clients_in(extrahop_data):
    unique_client_addrs = []
    for record in extrahop_data['records']:
        try:
            client_ip = record['_source']['clientAddr']['value']
            if client_ip not in unique_client_addrs:
                unique_client_addrs.append(client_ip)
        except KeyError:
            continue
    return unique_client_addrs


def analyze_extrahop_clients_out(extrahop_data):
    unique_client_addrs = []
    for record in extrahop_data['records']:
        try:
            client_ip = record['_source']['serverAddr']['value']
            if client_ip not in unique_client_addrs:
                unique_client_addrs.append(client_ip)
        except KeyError:
            continue
    return unique_client_addrs


# Borrowed this from get_malicious https://github.com/AlienVault-OTX/OTX-Python-SDK
def get_value(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return get_value(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return get_value(results[0], keys)
            else:
                return results
    else:
        return results


# adapted this from Alienvault Python SDK examples is malicious

def alienvault_these_ips(ip_list):
    otx = OTXv2(config['THREATINTEL']['OTXKey'], server=config['THREATINTEL']['OTXServer'])
    malicious_ip_list = []
    for addr in ip_list:
        alerts = []
        result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, addr, 'general')
        validation = get_value(result, ['validation'])
        if not validation:
            pulses = get_value(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append('In pulse: ' + pulse['name'])
        if len(alerts) > 0:
            print('{0} is identified as potentially malicious by Alienvault'.format(addr))
            malicious_ip_list.append(addr)
            print(str(alerts))
        time.sleep(1)
        # sleep here to avoid rate-limiting errors that might occur
    if len(malicious_ip_list) == 0:
        print('None of the IPs are malicious according to Alienvault. Exiting')
        view_addrs(ip_list)
        # TODO add an option to send the addresses to XFORCE or other intel source to avoid missing relevant info

    return malicious_ip_list


def xforce_score_ips(alienvaulted_list):
    xforce_auth = config['THREATINTEL']['XForceKey']
    xforce_server = config['THREATINTEL']['XForceServer']
    score_limit = 0
    # threshold for Xforce risk score. Don't return a result less than or equal to this number

    header_info = {'Content-Type': 'application/json',
                   'Accept': 'application/json',
                   'Authorization': 'Basic {0}=='.format(xforce_auth)}

    scored_addresses = []
    print('Querying XForce about {0} IPs flagged by Alienvault'.format(len(alienvaulted_list)))
    for addr in alienvaulted_list:
        api_endpoint = '{0}/ipr/history/{1}'.format(xforce_server, addr)
        conn = requests.get(api_endpoint, headers=header_info, verify=True)
        output = conn.json()
        latest_risk_score = output['history'][-1]['score']
        # only take into account XForce's most recent risk score for obvious reasons
        if latest_risk_score > score_limit:
            scored_addresses.append((addr, 'RISK SCORE: {0}'.format(latest_risk_score)))
    # sort the list of tuples based on risk score - descending
    scored_addresses = sorted(scored_addresses, key=lambda x: x[1], reverse=True)

    if len(scored_addresses) == score_limit:
        print('None of the addresses had XForce scores greater than {0}'.format(score_limit))
        view_addrs(alienvaulted_list)

    return scored_addresses


def view_addrs(ip_addrs):
    view_choice = input('View the unique IPs analyzed by the previous service? (y/n):\n')
    if view_choice == 'y':
        print(ip_addrs)
        print('Done')
        sys.exit()
    else:
        print('Done.')
        sys.exit()


def get_intel_data(api_endpoint, header, json_body, direction, record_format_selection):
    print('Calling Extrahop API at {0} for {1} records'.format(api_endpoint, record_format_selection))
    conn = requests.post(api_endpoint, headers=header, json=json_body, verify=False)
    output = conn.json()

    # printout = json.dumps(output, indent=4, sort_keys=True)
    # json.dumps() allows pretty printing of the JSON response; however, conn.json() is used for analysis operations

    print('Extrahop API call status: {0} {1}'.format(conn.status_code, conn.reason))

    displayed_recs_value = len(output['records'])
    fetched_recs_value = output['total']

    if fetched_recs_value == 0:
        print('No matching records found. Try a different timeframe.')
        sys.exit()

    print('Retrieved {0} of {1} total records matching filters.'.format(displayed_recs_value, fetched_recs_value))

    if direction == 'inbound':
        resulting_addrs = analyze_extrahop_clients_in(output)
    else:
        resulting_addrs = analyze_extrahop_clients_out(output)

    print('Analyzing {0} unique, interesting addresses'.format(len(resulting_addrs)))
    malicious_results = alienvault_these_ips(resulting_addrs)
    print(xforce_score_ips(malicious_results))
    print('Done')
