#! /usr/bin/env python

# Author:
#  Cameron Geehr (@BTit0r)

import sys
from os import walk
import argparse

# Parses the input and only returns readable characters
def purify(path):
    fo = open(path, "r")
    contents = fo.read()
    fo.close()
    
    # Remove all colored text formatting, hard coded for now
    contents = contents.replace("[1;34m", "")
    contents = contents.replace("[33m", "")
    contents = contents.replace("[32m", "")
    contents = contents.replace("[31m", "")
    contents = contents.replace("[0m", "")

    # Only retain alphanumeric, spaces, ., -, :, (), \n and *
    index = 0
    while index < len (contents):
        char = contents[index]
        if not char.isalnum() and char != "-" and char != "." and char != " " and char != "\n" and char != "(" and char != ")" and char != ":" and char != "*" and char != "_" and char != "/": 
            contents = contents[0:index] + contents[index + 1:]
        else:
            index += 1
    
    return contents


# Returns true if the supplied character is allowed in a host name
def is_valid_hostname_char(char):
    if not char.isalnum() and char != "-" and char != ".":
        return False
    return True
            

# Given a file path, it searches it for the host it's connected to and returns it as a string. If it can't identify the host, it will return a blank string
def find_host(path):
    hostname = ""
    contents = purify(path)

    index = contents.find("Testing SSL server ")
    if index < 0:
        return ""
    index += len("Testing SSL server ")

    for char in contents[index:]:
        if is_valid_hostname_char(char):
            hostname = hostname + char
        else: 
            return hostname
    
    return hostname

# Given a file path, it searches for the port of the host it's connected to and returns it as a string. If it can't identify the host, it will return a blank string
def find_port(path):
    port = ""
    contents = purify(path)

    index = contents.find("on port ")
    if index < 0:
        return ""
    index += len("on port ")

    for char in contents[index:]:
        if char != " ":
            port = port + char
        else:
            return port

def is_ip(host):
    octets = host.split(".")
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit():
            return False
        if int(octet) < 0 or int(octet) > 255:
            return False
    return True

def is_host(host):
    if len(host) == 0:
        return False

    if host[0] == "-":
        return False

    for char in host:
        if not is_valid_hostname_char(char):
            return False
    return True


# Returns -1 if first ip comes before second ip, 1 if second ip comes before first ip, and 0 if they're equivalent
def compare_ips(ip1, ip2):
    if not is_ip(ip1):
        if not is_ip(ip2):
            return 0
        return -1
    if not is_ip(ip2):
        return 1

    ip1_octets = ip1.split(".")
    ip2_octets = ip2.split(".")

    for i in range(4):
        if int(ip1_octets[i]) < int(ip2_octets[i]):
            return -1
        elif int(ip1_octets[i]) > int(ip2_octets[i]):
            return 1
    return 0

# Sorts hosts in place in ascending order of IP address
def sort_hosts(hosts):
    for i in range(len(hosts)):
        for j in range(len(hosts)):
            if i != j:
                if compare_ips(hosts[i].get_ip(), hosts[j].get_ip()) < 0:
                    tmp = hosts[i]
                    hosts[i] = hosts[j]
                    hosts[j] = tmp
         

class Host:
    def __init__(self, path):
        self.path = path
        # The ip here can be a hostname or IP address, it's a misnomer
        self.ip = find_host(self.path)
        self.port = find_port(self.path)
        self.contents = purify(path)

    def get_ip(self):
        return self.ip

    def get_port(self):
        return self.port

    def supports_cbc(self):
        index_of_ciphers = self.contents.find("Supported Server Cipher(s):") + len("Supported Server Cipher(s):")
        if self.contents[index_of_ciphers:].find("-CBC") > 0:
            return True
        return False

    def supports_md4(self):
        index_of_ciphers = self.contents.find("Supported Server Cipher(s):") + len("Supported Server Cipher(s):")
        if self.contents[index_of_ciphers:].find("-MD4") > 0:
            return True
        return False

    def supports_md5(self):
        index_of_ciphers = self.contents.find("Supported Server Cipher(s):") + len("Supported Server Cipher(s):")
        if self.contents[index_of_ciphers:].find("-MD5") > 0:
            return True
        return False

    def supports_sha1(self):
        index_of_ciphers = self.contents.find("Supported Server Cipher(s):") + len("Supported Server Cipher(s):")
        if self.contents[index_of_ciphers:].find("-SHA ") > 0:
            return True
        return False

    def supports_des(self):
        index_of_ciphers = self.contents.find("Supported Server Cipher(s):") + len("Supported Server Cipher(s):")
        if self.contents[index_of_ciphers:].find("DES-CBC-") > 0 or self.contents[index_of_ciphers:].find("DES_CBC_") > 0:
            return True
        return False

    def supports_3des(self):
        index_of_ciphers = self.contents.find("Supported Server Cipher(s):") + len("Supported Server Cipher(s):")
        if self.contents[index_of_ciphers:].find("DES-CBC3") > 0:
            return True
        return False

    def supports_rc4(self):
        index_of_ciphers = self.contents.find("Supported Server Cipher(s):") + len("Supported Server Cipher(s):")
        if self.contents[index_of_ciphers:].find("-CBC") > 0:
            return True
        return False

    def supports_ssl2(self):
        index_of_ciphers = self.contents.find("SSL/TLS Protocols:") + len("SSL/TLS Protocols:")
        if self.contents[index_of_ciphers:].find("SSLv2     enabled") > 0:
            return True
        return False

    def supports_ssl3(self):
        index_of_ciphers = self.contents.find("SSL/TLS Protocols:") + len("SSL/TLS Protocols:")
        if self.contents[index_of_ciphers:].find("SSLv3     enabled") > 0:
            return True
        return False

    def supports_tls1(self):
        index_of_ciphers = self.contents.find("SSL/TLS Protocols:") + len("SSL/TLS Protocols:")
        if self.contents[index_of_ciphers:].find("TLSv1.0   enabled") > 0:
            return True
        return False

    # TODO: Make this NOT hard coded
    # In order to maintain what ciphers are used, this function needs to return a number. 2048 means that the strength is sufficient
    def lowest_supported_dh(self):
        index_of_ciphers = self.contents.find("Supported Server Cipher(s):") + len("Supported Server Cipher(s):")
        if self.contents[index_of_ciphers:].find("DHE 512") > 0:
            return 512
        if self.contents[index_of_ciphers:].find("DHE 768") > 0:
            return 768
        if self.contents[index_of_ciphers:].find("DHE 1024") > 0:
            return 1024
        return 2048

    # TODO: Make this NOT hard coded
    # In order to maintain what ciphers are used, this function needs to return a number. 2048 means that the strength is sufficient
    def lowest_supported_rsa(self):
        index_of_ciphers = self.contents.find("Supported Server Cipher(s):") + len("Supported Server Cipher(s):")
        if self.contents[index_of_ciphers:].find("RSA Key Strength:    1024") > 0:
            return 1024
        return 2048

def generate_file_contents(host_ciphers):
    #"Host,SSLv2,SSLv3,TLSv1.0,DES,3DES,RC4,MD5,SHA-1,CBC,DHE <=1024, RSA Key <=1024\n"
    header_string = "Host"
    
    sslv2 = False
    sslv3 = False
    tlsv1 = False
    des = False
    des3 = False
    rc4 = False
    md5 = False
    sha1 = False
    cbc = False
    dhe = False
    rsa = False

    for cipher_list in host_ciphers:
        if cipher_list[1]:
            sslv2 = True
        if cipher_list[2]:
            sslv3 = True
        if cipher_list[3]:
            tlsv1 = True
        if cipher_list[4]:
            des = True
        if cipher_list[5]:
            des3 = True
        if cipher_list[6]:
            rc4 = True
        if cipher_list[7]:
            md5 = True
        if cipher_list[8]:
            sha1 = True
        if cipher_list[9]:
            cbc = True
        if not not cipher_list[10]:
            dhe = True
        if not not cipher_list[11]:
            rsa = True

    if sslv2:
        header_string += ",SSLv2"
    if sslv3:
        header_string += ",SSLv3"
    if tlsv1:
        header_string += ",TLSv1.0"
    if des:
        header_string += ",DES"
    if des3:
        header_string += ",3DES"
    if rc4:
        header_string += ",RC4"
    if md5:
        header_string += ",MD5"
    if sha1:
        header_string += ",SHA-1"
    if cbc:
        header_string += ",CBC"
    if dhe:
        header_string += ",DHE <= 1024"
    if rsa:
        header_string += ",RSA Key <= 1024"
    
    file_contents = header_string + "\n"

    for cipher_list in host_ciphers:
        #IP addr
        file_contents += cipher_list[0]
        
        if sslv2:
            file_contents += ","
            if cipher_list[1]:
                file_contents += "X"
        if sslv3:
            file_contents += ","
            if cipher_list[2]:
                file_contents += "X"
        if tlsv1:
            file_contents += ","
            if cipher_list[3]:
                file_contents += "X"
        if des:
            file_contents += ","
            if cipher_list[4]:
                file_contents += "X"
        if des3:
            file_contents += ","
            if cipher_list[5]:
                file_contents += "X"
        if rc4:
            file_contents += ","
            if cipher_list[6]:
                file_contents += "X"
        if md5:
            file_contents += ","
            if cipher_list[7]:
                file_contents += "X"
        if sha1:
            file_contents += ","
            if cipher_list[8]:
                file_contents += "X"
        if cbc:
            file_contents += ","
            if cipher_list[9]:
                file_contents += "X"
        if dhe:
            file_contents += ","
            if not not cipher_list[10]:
                file_contents += cipher_list[10]
        if rsa:
            file_contents += ","
            if not not cipher_list[11]:
                file_contents += cipher_list[11]

        file_contents += "\n"

    return file_contents

def tests(sslscan_files):
    return ""

def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("sslscan_directory", help="The path to the directory with .sslscan files to convert.")
    parser.add_argument("-o", help="The directory to write the sslscan_issues.csv file to.", default="./")
    args = parser.parse_args()
    
    directory = args.sslscan_directory
    if not directory.endswith("/"):
        directory = directory + "/"
    
    target_directory = args.o
    if not target_directory.endswith("/"):
        target_directory = target_directory + "/"

    sslscan_files = []
    for (dirpath, dirnames, filenames) in walk(directory):
        for filename in filenames:
            if filename.endswith(".sslscan"):
                sslscan_files.append(directory + filename)
        break

    hosts = []
    for file in sslscan_files:
        host = find_host(file)
        if is_host(host):
            hosts.append(Host(file))

    sort_hosts(hosts)

    fo = open(target_directory + "ssl_issues.csv", "w")
    #"Host,SSLv2,SSLv3,TLSv1.0,DES,3DES,RC4,MD5,SHA-1,CBC,DHE <=1024, RSA Key <=1024\n"
    host_ciphers = []
    host_index = 0
    for host in hosts:
        cipher_list = []

        cipher_list.append(host.supports_ssl2())
        cipher_list.append(host.supports_ssl3())
        cipher_list.append(host.supports_tls1())
        cipher_list.append(host.supports_des())
        cipher_list.append(host.supports_3des())
        cipher_list.append(host.supports_rc4())
        cipher_list.append(host.supports_md5())
        cipher_list.append(host.supports_sha1())
        cipher_list.append(host.supports_cbc())
        
        dh = host.lowest_supported_dh()
        if dh < 2048:
            cipher_list.append(str(dh))
        else:
            cipher_list.append(False)
        
        rsa = host.lowest_supported_rsa()
        if rsa < 2048:
            cipher_list.append(str(rsa))
        else:
            cipher_list.append(False)
        # Only add to spreadsheet if there's actually an issue
        weakness = False
        for cipher in cipher_list:
            if not not cipher:
                weakness = True
        if weakness:
            cipher_list.insert(0, host.get_ip() + ":" + host.get_port())
            host_ciphers.append(cipher_list)
            host_index += 1

    fo.write(generate_file_contents(host_ciphers))
    fo.close()
    #tests(sslscan_files)
    if target_directory == "./":
        print ("Wrote out to ssl_issues.csv in the current directory.")
    else:
        print ("Wrote out to ssl_issues.csv in the specified directory.")

if __name__ == "__main__":
    main()
