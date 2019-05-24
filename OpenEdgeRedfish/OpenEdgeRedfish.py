#!/usr/bin/env python3
from docopt import docopt
from multiprocessing import Pool
import os
import requests
import sys
import yaml

usage = """%(prog)s
This script uses the Redfish interface to the Nokia OpenEdge server hardware
to verify and modify the versions of pre-boot software components.

Usage:
   %(prog)s [-i] [--config <config.yaml>] --status
   %(prog)s [-i] [--config <config.yaml>] --OEMstatus
   %(prog)s [-i] [--config <config.yaml>] --checkversions
   %(prog)s [-i] [--config <config.yaml>] forceoff [--target <number>]
   %(prog)s [-i] [--config <config.yaml>] poweron [--target <number>]
   %(prog)s [-i] [--config <config.yaml>] powerstate [--target <number>]
   %(prog)s [-i] [--config <config.yaml>] getbiosparameters [--target <number>]
   %(prog)s [-i] [--config <config.yaml>] preserve [--target <number>]
   %(prog)s [-i] [--config <config.yaml>] updateBMCfirmware [--target <number>]
   %(prog)s [-i] [--config <config.yaml>] updateBIOSfirmware [--target <number>]
   %(prog)s --example
   %(prog)s --help

Options:
    -c, --checkversions         Check if software versions match
    -e, --example               Use -e to see an example of
    -f <file>, --config <file>  YAML format config file [default: config.yaml]
                                that should be supplied.
    -h, --help                  Display this help message.
    -i, --insecure              Disable SSL certificate warnings
    -s, --status                Retrieve BMC Status
    -t <num>, --target <num>    # of target in config to apply to
""" % {'prog': sys.argv[0]}


def main():
    args = docopt(usage)
    config = load_config(args)
    if not config:
        sys.exit(1)

    if args['--insecure']:
        import urllib3
        urllib3.disable_warnings()  # New servers may have self signed certs
        config['verify'] = False
    else:
        config['verify'] = True
    if args['--status']:
        getStatus(config)
    if args['--OEMstatus']:
        getOEMUpdateStatuses(config)
    if args['--checkversions']:
        getVersions(config)
    if args['forceoff']:
        powerForceOff(config)
    elif args['poweron']:
        powerOn(config)
    elif args['powerstate']:
        getPowerState(config)
    if args['getbiosparameters']:
        getBIOSParameters(config)
    if args['preserve']:
        preserveBMCSettings(config)
    if args['updateBMCfirmware']:
        updateBMCfirmware(config)
    if args['updateBIOSfirmware']:
        updateBIOSfirmwares(config)


def load_config(args):
    if not os.path.isfile(args['--config']):
        print(usage)
        print('Config file %s is missing' % args['--config'])
        return None
    with open(args['--config']) as f:
        config = yaml.safe_load(f.read())
        password = config['credentials'].get('password', None)
        if password is None:
            import getpass
            password = getpass.getpass('Enter the Redfish password: ')
            config['credentials']['password'] = password
    return config


def callRedfish(config, url, postdata=None, patchdata=None):
    auth = (config['credentials']['user'], config['credentials']['password'])
    headers = {'content-type': 'application/json'}
    if postdata:
        print('POST to %s with data %s' % (url, str(postdata)))
        resp = requests.post(url, auth=auth, headers=headers, json=postdata,
                             verify=config['verify'], timeout=60)
    elif patchdata:
        print('PATCH to %s with data %s' % (url, str(patchdata)))
        resp = requests.patch(url, auth=auth, headers=headers, json=patchdata,
                             verify=config['verify'], timeout=60)
    else:
        resp = requests.get(url, auth=auth, headers=headers,
                            verify=config['verify'], timeout=60)
    print('HTTP Response Code:', resp.status_code,
          http_status_codes[resp.status_code], end='\t')
    if 200 <= resp.status_code < 300:
        return resp
    else:
        print('HTTP call failed for URL: %s with credentials %s' %
              (url, str(auth)))
        print(resp)
        # TODO:  Do something sensible if this fails


def getVersions(config):
    p = Pool(len(config['targets']))
    configs = [config for t in config['targets']]
    p.starmap(getVersion, zip(configs, config['targets']))


def getVersion(config, target):
    url = 'https://' + target + '/redfish/v1/UpdateService/FirmwareInventory'
    items = ['BIOS1', 'BMC1', 'BMC2', 'CPLD']
    print('Retrieving %s from %s' % (str(', '.join(items)), target))
    for item in items:
        fullurl = url + '/' + item
        resp = callRedfish(config, fullurl)
        if not resp:
            return None
        version = resp.json().get('Version', 'Error! Version not found')
        wantedVersion = config['images'][item]['wantedVersion']
        isGood = '\033[1m\033[32m\tGood\033[0m' if version == wantedVersion else '\t\033[1m\033[31m!! BAD !!\033[0m'
        print(target + ' > ' + item + ' version: ' + version + isGood)


def getPowerStates(config, target=None):
    """Get Power state of target server,
       or all servers in config['targets']"""
    targets = config['targets'] if target is None else [target]
    p = Pool(len(targets))
    configs = [config for t in targets]
    p.starmap(getPowerState, zip(configs, targets))


def getPowerState(config, target):
    url = 'https://' + target
    url += '/redfish/v1/Systems/Self'
    resp = callRedfish(config, url)
    print(target, resp.json()['PowerState'])


def powerChanges(config, resetType, target=None):
    """Change Power state of target server,
       or all servers in config['targets']"""
    targets = config['targets'] if target is None else [target]
    postdata = {"ResetType": resetType}
    p = Pool(len(targets))
    configs = [config for t in targets]
    postdatas = [postdata for t in targets]
    p.starmap(powerChange, zip(configs, postdatas, targets))


def powerChange(config, postdata, target):
    url = 'https://' + target
    url += '/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset'
    resp = callRedfish(config, url, postdata=postdata)
    print(resp.content)


def powerForceOff(config, target=None):
    '''Powers off a specific target (i.e. server) or all servers in config if
    no target is specified.'''

    powerChanges(config, 'ForceOff', target=target)


def powerOn(config, target=None):
    '''Powers on a specific target (i.e. server) or all servers in config if
    no target is specified.'''

    powerChanges(config, 'On', target=target)


def getBIOSParameters(config):
    for target in config['targets']:
        url = 'https://' + target + '/redfish/v1/Systems/Self/Bios'
        print('Getting BIOS Parameters from %s' % target)
        resp = callRedfish(config, url)
        print(yaml.safe_dump(resp.json()))


def getStatus(config):
    for target in config['targets']:
        url = 'https://' + target + '/redfish/v1/UpdateService'
        print('Retrieving full status from %s' % target)
        resp = callRedfish(config, url)
        someOutput = {}
        someOutput['Oem'] = resp.json()['Oem']
        someOutput['Status'] = resp.json()['Status']
        print('\n', yaml.safe_dump(someOutput))


def getOEMUpdateStatuses(config):
    p = Pool(len(config['targets']))
    configs = [config for t in config['targets']]
    p.starmap(getOEMUpdateStatus, zip(configs, config['targets']))


def getOEMUpdateStatus(config, target):
    url = 'https://' + target + '/redfish/v1/UpdateService'
    print('Retrieving BMC update status from %s' % target)
    resp = callRedfish(config, url)
    print('\n', yaml.safe_dump(resp.json()['Oem']))


def preserveBMCSettings(config):
    for target in config['targets']:
        url = 'https://' + target + '/redfish/v1/UpdateService'
        # Hardcoded parameters provided by documentation
        patchdata = {"Oem":
                     {"BMC":
                      {"PreserveConfiguration":
                       {"Authentication": True,
                        "IPMI": True,
                        "KVM": True,
                        "Network": True,
                        "SEL": True,
                        "SNMP": True,
                        "SSH": True
                       }
                      }
                     }
                    }
        print('Preserving BMC settings on %s' % target)
        resp = callRedfish(config, url, patchdata=patchdata)
        print(yaml.safe_dump(resp.json()))


def updateBMCfirmware(config):
    for target in config['targets']:
        url = 'https://' + target + \
              '/redfish/v1/UpdateService/Actions/Oem/UpdateService.BMCFwUpdate'
        firmwareImage = config['images']['BMC1']['imageurl']
        postdata = {"RemoteImagePath":
                       firmwareImage,
                       "FlashType":"FULLFwUpdate"
                   }
        print('Updating BMC firmware on %s' % target)
        resp = callRedfish(config, url, postdata=postdata)
        if resp.status_code != 204:
            print('Response %s while updating BMC firmware on %s' % (resp, target))


def updateBIOSfirmwares(config):
    p = Pool(len(config['targets']))
    configs = [config for t in config['targets']]
    p.starmap(updateBIOSfirmware, zip(configs, config['targets']))


def updateBIOSfirmware(config, target):
    url = 'https://' + target + \
          '/redfish/v1/UpdateService/Actions/Oem/UpdateService.BIOSFwUpdate'
    firmwareImage = config['images']['BIOS1']['imageurl']
    postdata = {"RemoteImagePath":
                   firmwareImage,
                   "PreserveBIOSNVRAMRegion":True
               }
    print('Updating BIOS firmware on %s' % target)
    resp = callRedfish(config, url, postdata=postdata)
    if resp.status_code != 204:
        print('Response %s while updating BIOS firmware on %s' % (resp, target))


http_status_codes = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",
    208: "Already Reported",
    226: "IM Used",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    414: "Request-URI Too Long",
    415: "Unsupported Media Type",
    416: "Requested Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a teapot",
    421: "Misdirected Request",
    422: "Unprocessable Entity",
    423: "Locked",
    424: "Failed Dependency",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    444: "Connection Closed Without Response",
    451: "Unavailable For Legal Reasons",
    499: "Client Closed Request",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates",
    507: "Insufficient Storage",
    508: "Loop Detected",
    510: "Not Extended",
    511: "Network Authentication Required",
    599: "Network Connect Timeout Error",
}


if __name__ == '__main__':
    main()

'''
# update BIOS configuration
curl -k -u userid:password -X PATCH -H 'Content-Type: application/json' -d '{"Attributes":{"PMS002":"Disable","CSM007":"Do not launch","FBO001":"LEGACY","FBO101":"Hard Disk","FBO102":"USB","FBO103":"Disabled","FBO104":"Disabled","IIOS1FE":"Enable"}}' https://172.26.16.${i}/redfish/v1/Systems/Self/Bios/SD
'''
