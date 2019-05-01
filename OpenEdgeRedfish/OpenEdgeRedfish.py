#!/usr/bin/env python3
from docopt import docopt
from multiprocessing import Pool
import requests
import sys
import yaml

usage = """%(prog)s
This script uses the Redfish interface to the Nokia OpenEdge server hardware
to verify and modify the versions of pre-boot software components.

Usage:
    %(prog)s [-i] [--config <config.yaml>] --status
    %(prog)s [-i] [--config <config.yaml>] --checkversions
    %(prog)s [-i] [--config <config.yaml>] forceoff [--target <number>]
    %(prog)s [-i] [--config <config.yaml>] poweron [--target <number>]
    %(prog)s [-i] [--config <config.yaml>] getbiosparameters [--target <number>]
    %(prog)s --example
    %(prog)s --help

Options:
    -c, --checkversions                       Check if software versions match
    -e, --example                             Use -e to see an example of   
    -f <config.yaml>, --config <config.yaml>  the YAML formatted config file [default: config.yaml]
                                              that should be supplied.      
    -h, --help                                Display this help message.    
    -i, --insecure                            Disable SSL certificate warnings
    -s, --status                              Retrieve BMC Status           
    -t <number>, --target <number>            # of target in config to apply to
""" % {'prog': sys.argv[0]}

def main():
    args = docopt(usage)
    #print(args)
    if args['--config']:
        config = load_config(args)
        password = config['credentials'].get('password', None)
        if password == None:
            import getpass
            password = getpass.getpass('Enter the Redfish password: ')
            config['credentials']['password'] = password
    else:
        print(usage)
        return
    if args['--insecure']:
        import urllib3
        urllib3.disable_warnings() # New servers may have self signed certs
        config['verify'] = False
    else:
        config['verify'] = True
    if args['--status']:
        getBMCUpdateStatus(config)
    if args['--checkversions']:
        getVersions(config)
    if args['forceoff']:
        powerForceOff(config)
    elif args['poweron']:
        powerOn(config)
    if args['getbiosparameters']:
        getBIOSParameters(config)

def load_config(args):
    with open(args['--config']) as f:
        return yaml.safe_load(f.read())

def callRedfish(config, url, postdata=None):
    auth = (config['credentials']['user'], config['credentials']['password'])
    headers = { 'content-type': 'application/json' }
    if postdata:
        print('POST to %s with data %s' % (url, str(postdata)))
        resp = requests.post(url, auth=auth, headers=headers, data=postdata,
                verify=config['verify'])
    else:
        resp = requests.get(url, auth=auth, headers=headers,
                verify=config['verify'])
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
    configs = [ config for t in config['targets'] ]
    res = p.starmap(getVersionsFromOneTarget, zip(configs, config['targets']))
    '''
    for r in res:
        print(r)
    '''

def getVersionsFromOneTarget(config, target):
    url = 'https://' + target + '/redfish/v1/UpdateService/FirmwareInventory'
    items = ['BIOS1', 'BMC1', 'BMC2', 'CPLD']
    print('Retrieving %s from %s' % (str(', '.join(items)), target))
    #ret = ''
    #ret += 'Retrieving %s from %s' % (str(', '.join(items)), target)
    for item in items:
        fullurl = url + '/' + item
        resp = callRedfish(config, fullurl)
        version = resp.json().get('Version', 'Error! Version not found')
        wantedVersion = config['images'][item]['wantedVersion']
        isGood = '\tGood' if version == wantedVersion else '\t!! BAD !!'
        #ret += target + ' > ' + item + ' version: ' + version + isGood
        print(target + ' > ' + item + ' version: ' + version + isGood)
    #return ret

def powerChange(config, resetType, target=None):
    """Change Power state of target server, or all servers in config['targets']"""
    targets = config['targets'] if target is None else [config['targets'][target]]
    postdata = '{"ResetType":"%s"}' % resetType
    p = Pool(len(config['targets']))
    configs = [ config for t in config['targets'] ]
    postdatas = [ postdata for t in config['targets'] ]
    res = p.starmap(powerChangeOneTarget, zip(configs, postdatas, config['targets']))
    '''
    for target in targets:
        url = 'https://' + target + '/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset'
        resp = callRedfish(config, url, postdata=postdata)
        print(resp.content)
    '''

def powerChangeOneTarget(config, postdata, target):
    url = 'https://' + target + '/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset'
    resp = callRedfish(config, url, postdata=postdata)
    print(resp.content)

def powerForceOff(config, target=None):
    powerChange(config, 'ForceOff', target=target)

def powerOn(config, target=None):
    powerChange(config, 'On', target=target)

'''
# power up the server
curl -k -u Administrator:superuser -H content-type:application/json -X POST -d '{"ResetType":"ForceOff"}'  https://172.26.16.205/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset
curl -k -u Administrator:superuser -H content-type:application/json -X POST -d '{"ResetType":"On"}'  https://172.26.16.205/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset
'''

def getBIOSParameters(config):
    for target in config['targets']:
        url = 'https://' + target + '/redfish/v1/Systems/Self/Bios'
        print('Getting BIOS Parameters from %s' % target)
        resp = callRedfish(config, url)
        print(yaml.safe_dump(resp.json()))
'''
# get BIOS parameters
curl -k -u Administrator:superuser -X GET -H 'Content-Type: application/json' https://172.26.16.${i}/redfish/v1/Systems/Self/Bios
'''

def getBMCUpdateStatus(config):
    for target in config['targets']:
        url = 'https://' + target + '/redfish/v1/UpdateService'
        print('Retrieving BMC update status from %s' % target)
        resp = callRedfish(config, url)
        print(yaml.safe_dump(resp.json()))

'''
# get BMC update status

curl -k -u Administrator:superuser -H content-type:application/json -X GET https://172.26.16.${i}/redfish/v1/UpdateService
'''

http_status_codes = {
	100 : "Continue",
	101 : "Switching Protocols",
	102 : "Processing",
	200 : "OK",
	201 : "Created",
	202 : "Accepted",
	203 : "Non-authoritative Information",
	204 : "No Content",
	205 : "Reset Content",
	206 : "Partial Content",
	207 : "Multi-Status",
	208 : "Already Reported",
	226 : "IM Used",
	300 : "Multiple Choices",
	301 : "Moved Permanently",
	302 : "Found",
	303 : "See Other",
	304 : "Not Modified",
	305 : "Use Proxy",
	307 : "Temporary Redirect",
	308 : "Permanent Redirect",
	400 : "Bad Request",
	401 : "Unauthorized",
	402 : "Payment Required",
	403 : "Forbidden",
	404 : "Not Found",
	405 : "Method Not Allowed",
	406 : "Not Acceptable",
	407 : "Proxy Authentication Required",
	408 : "Request Timeout",
	409 : "Conflict",
	410 : "Gone",
	411 : "Length Required",
	412 : "Precondition Failed",
	413 : "Payload Too Large",
	414 : "Request-URI Too Long",
	415 : "Unsupported Media Type",
	416 : "Requested Range Not Satisfiable",
	417 : "Expectation Failed",
	418 : "I'm a teapot",
	421 : "Misdirected Request",
	422 : "Unprocessable Entity",
	423 : "Locked",
	424 : "Failed Dependency",
	426 : "Upgrade Required",
	428 : "Precondition Required",
	429 : "Too Many Requests",
	431 : "Request Header Fields Too Large",
	444 : "Connection Closed Without Response",
	451 : "Unavailable For Legal Reasons",
	499 : "Client Closed Request",
	500 : "Internal Server Error",
	501 : "Not Implemented",
	502 : "Bad Gateway",
	503 : "Service Unavailable",
	504 : "Gateway Timeout",
	505 : "HTTP Version Not Supported",
	506 : "Variant Also Negotiates",
	507 : "Insufficient Storage",
	508 : "Loop Detected",
	510 : "Not Extended",
	511 : "Network Authentication Required",
	599 : "Network Connect Timeout Error",
}


if __name__ == '__main__':
    main()

'''
# preserve BMC settings
curl -k -u Administrator:superuser -H content-type:application/json -X PATCH -d '{"Oem":{"BMC":{"PreserveConfiguration":{"Authentication": true, "IPMI": true, "KVM": true, "Network": true, "SEL": true, "SNMP": true, "SSH": true}}}}' https://172.26.16.${i}/redfish/v1/UpdateService

#update BMC
curl -k -u Administrator:superuser -H content-type:application/json -X POST -d '{"RemoteImagePath":"http://204.127.189.10:8090/S9N31300.ima_enc","FlashType":"FULLFwUpdate"}' https://172.26.16.${i}/redfish/v1/UpdateService/Actions/Oem/UpdateService.BMCFwUpdate

#update BIOS

curl -s -m 3 -d '{ "RemoteImagePath":"http://204.127.189.10:8090/S9N_3B06.BIN_enc", "PreserveBIOSNVRAMRegion":true }' -H "Content-Type: application/json" -X POST -k -u Administrator:superuser https://172.26.16.${i}/redfish/v1/UpdateService/Actions/Oem/UpdateService.BIOSFwUpdate


# update BIOS configuration 
curl -k -u Administrator:superuser -X PATCH -H 'Content-Type: application/json' -d '{"Attributes":{"PMS002":"Disable","CSM007":"Do not launch","FBO001":"LEGACY","FBO101":"Hard Disk","FBO102":"USB","FBO103":"Disabled","FBO104":"Disabled","IIOS1FE":"Enable"}}' https://172.26.16.${i}/redfish/v1/Systems/Self/Bios/SD

'''
