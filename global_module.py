import configparser

# TODO configurationinfo class

# Extrahop-specific configuration info now global so we don't keep parsing the config unnecessarily

# get config info from config file
config = configparser.ConfigParser()
config.read('config.ini')

EH_INSTANCE_ADDR = config['API']['InstanceAddr']
EH_API_KEY = config['API']['Key']
OUTBOUND_ADDR_EXCLUSIONS = config['FILTERS']['OutClientAddrExclude'].split(',')
INBOUND_ADDR_EXCLUSIONS = config['FILTERS']['InClientAddrExclude'].split(',')


EH_RECORD_TYPE_OPTS = dict(cifs="~cifs", http="~http", tcp="advancedTCP_client", ssh="~ssh_tick", rdp="~rdp_open",
                           ftp="~ftp", dns="~dns_request", ssl="~ssl_open", smtp="~smtp", ldap="~ldap_request")
EH_CALL_BASE = {
    "filter": {
        "operator": "and",
        "rules": []
    },
    "types": [
    ],
    "from": "-12h",
    "limit": 1000,
    "sort_item": {
        "direction": "asc",
        "field": "clientAddr"
    }
}

EH_HEADER_INFO = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'Extrahop apikey={0}'.format(EH_API_KEY)}

EH_API_ENDPOINT: str = 'https://{0}/api/v1/records/search'.format(EH_INSTANCE_ADDR)
