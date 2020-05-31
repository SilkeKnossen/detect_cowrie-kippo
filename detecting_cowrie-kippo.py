#!/usr/bin/python3


import sys
import os
import argparse
import socket
import time
import nmap
import re
import subprocess


COWRIE_IDSTRINGS = ["SSH-2.0-OpenSSH_5.1p1 Debian-5",
    "SSH-1.99-OpenSSH_4.3",
    "SSH-1.99-OpenSSH_4.7",
    "SSH-1.99-Sun_SSH_1.1",
    "SSH-2.0-OpenSSH_4.2p1 Debian-7ubuntu3.1",
    "SSH-2.0-OpenSSH_4.3",
    "SSH-2.0-OpenSSH_4.6",
    "SSH-2.0-OpenSSH_5.1p1 Debian-5",
    "SSH-2.0-OpenSSH_5.1p1 FreeBSD-20080901",
    "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu5",
    "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu6",
    "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7",
    "SSH-2.0-OpenSSH_5.5p1 Debian-6",
    "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze1",
    "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2",
    "SSH-2.0-OpenSSH_5.8p2_hpn13v11 FreeBSD-20110503",
    "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1",
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    "SSH-2.0-OpenSSH_5.9"]

VALID_OPENSSH_IDSTRING = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"

OPENSSH_51_CRYPTO = ["diffie-hellman-group-exchange-sha256",
                       "diffie-hellman-group-exchange-sha1",
                       "diffie-hellman-group14-sha1",
                       "diffie-hellman-group1-sha1",
                       "ssh-rsa",
                       "ssh-dss",
                       "aes128-cbc",
                       "3des-cbc",
                       "blowfish-cbc",
                       "cast128-cbc",
                       "arcfour128",
                       "arcfour256",
                       "arcfour",
                       "aes192-cbc",
                       "aes256-cbc",
                       "rijndael-cbc@lysator.liu.se",
                       "aes128-ctr",
                       "aes192-ctr",
                       "aes256-ctr",
                       "hmac-md5",
                       "hmac-sha1",
                       "umac-64@openssh.com",
                       "hmac-ripemd160",
                       "hmac-ripemd160@openssh.com",
                       "hmac-sha1-96",
                       "hmac-md5-96",
                       "none",
                       "zlib@openssh.com"]

OPENSSH_60_CRYPTO = ["ecdh-sha2-nistp256",
                  "ecdh-sha2-nistp384",
                  "ecdh-sha2-nistp521",
                  "diffie-hellman-group-exchange-sha256",
                  "diffie-hellman-group-exchange-sha1",
                  "diffie-hellman-group14-sha1",
                  "diffie-hellman-group1-sha1",
                  "ssh-rsa",
                  "ssh-dss",
                  "ecdsa-sha2-nistp256",
                  "aes128-ctr",
                  "aes192-ctr",
                  "aes256-ctr",
                  "arcfour256",
                  "arcfour128",
                  "aes128-cbc",
                  "3des-cbc",
                  "blowfish-cbc",
                  "cast128-cbc",
                  "aes192-cbc",
                  "aes256-cbc",
                  "arcfour",
                  "rijndael-cbc@lysator.liu.se",
                  "hmac-md5",
                  "hmac-sha1",
                  "umac-64@openssh.com",
                  "hmac-sha2-256",
                  "hmac-sha2-256-96",
                  "hmac-sha2-512",
                  "hmac-sha2-512-96",
                  "hmac-ripemd160",
                  "hmac-ripemd160@openssh.com",
                  "hmac-sha1-96",
                  "hmac-md5-96",
                  "none",
                  "zlib@openssh.com"]

OPENSSH_76_CRYPTO =   ["curve25519-sha256",
                    "curve25519-sha256@libssh.org",
                    "ecdh-sha2-nistp256",
                    "ecdh-sha2-nistp384",
                    "ecdh-sha2-nistp521",
                    "diffie-hellman-group-exchange-sha256",
                    "diffie-hellman-group16-sha512",
                    "diffie-hellman-group18-sha512",
                    "diffie-hellman-group14-sha256",
                    "diffie-hellman-group14-sha1",
                    "ssh-rsa",
                    "rsa-sha2-512",
                    "rsa-sha2-256",
                    "ecdsa-sha2-nistp256",
                    "ssh-ed25519",
                    "chacha20-poly1305@openssh.com",
                    "aes128-ctr",
                    "aes192-ctr",
                    "aes256-ctr",
                    "aes128-gcm@openssh.com",
                    "aes256-gcm@openssh.com",
                    "umac-64-etm@openssh.com",
                    "umac-128-etm@openssh.com",
                    "hmac-sha2-256-etm@openssh.com",
                    "hmac-sha2-512-etm@openssh.com",
                    "hmac-sha1-etm@openssh.com",
                    "umac-64@openssh.com",
                    "umac-128@openssh.com",
                    "hmac-sha2-256",
                    "hmac-sha2-512",
                    "hmac-sha1",
                    "none",
                    "zlib@openssh.com"]

IDSTRINGS = {
    "SSH-2.0-OpenSSH_5.1p1 Debian-5" : OPENSSH_51_CRYPTO,
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2" : OPENSSH_60_CRYPTO,
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4" : OPENSSH_60_CRYPTO,
    "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3" : OPENSSH_76_CRYPTO,
}

DEF_HOSTKEYS = {
    "SSH-2.0-OpenSSH_5.1p1 Debian-5" : ["DSA", "RSA"],
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2" : ["DSA", "RSA", "ECDSA"],
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4" : ["DSA", "RSA", "ECDSA"],
    "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3" : ["RSA", "ECDSA", "EdDSA / ED25519"],
}

RESPONSES = False

def connect(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    idStringMessage = sock.recv(2048)
    idString = idStringMessage.decode('utf-8').strip()

    return sock, idString


def checkidString(idString):
    print("\t* Identification string from target server: %s." % (idString))
    check = False

    if idString in COWRIE_IDSTRINGS:
        print("\t* WARNING: " +
        "Identification string is included to the default id strings list of Cowrie and might be an " +
        "indication of Cowrie honeypot.")
    else:
        print("\t* This identification string is the not a default Cowrie/Kippo string.")

    if not re.match("^SSH-(1.[0-9]+|2.0)-", idString):
        print("\t* WARNING: This target advertises a non valid SSH protocol version in its identification string.")
        return 0, 0, 0
    elif not re.match("^SSH-(1.[0-9]+|2.0)-OpenSSH_([0-7]{1}.[0-9]{1}|8.[0-3]{1})", idString):
        print("\t* WARNING: This target advertises a non valid OpenSSH version in its identification string.")
        return 0, 0, 0
    else:
        print("\t* Identification string looks like a valid (Open)SSH one.")

    if idString in DEF_HOSTKEYS.keys():
        hostkeys = DEF_HOSTKEYS[idString]
    else:
        hostkeys = 0
        print("* No default hostkeys found for this version of OpenSSH." +
        " If they are known, you can add them in the source code of this tool.")

    if idString in IDSTRINGS.keys():
        cryptoAlgorithms = IDSTRINGS[idString]
    else:
        cryptoAlgorithms = 0
        print("* No crypto algorithms found for this version of OpenSSH." +
        " If they are known, you can add them in the source code of this tool.")

    return cryptoAlgorithms, hostkeys, check


def checkAlgorithms(algorithms, checklist):
    check = False

    if algorithms:
        extraAlgorithms = [item for item in algorithms if item not in checklist]
        missingAlgorithms = [item for item in checklist if item not in algorithms]
        if (len(extraAlgorithms) != 0):
            check = True
            print("\t * Extra algorithms found for target.")

            if RESPONSES:
                print("! Extra algorithms supported by target: ")

                for item in extraAlgorithms:
                    print("\t -%s" % (item))
                print("\n")

        else:
            print("\t * No extra supported algorithms found for target.")

        if (len(missingAlgorithms) != 0):
            check = True
            print("\t * Missing algorithms found for target.")

            if RESPONSES:
                print("! Missing algorithms in target as should be advertised according to the version in the identification string: ")

                for item in missingAlgorithms:
                    print("\t -%s" % (item))
                print("\n")

        else:
            print("\t * No missing supported algorithms found for target.")
    else:
        check = True
        print("\t * Missing supported algorithms found for target.")

        if RESPONSES:
            print("! Missing algorithms in target as should be advertised according to the version in the identification string: ")

            for item in checklist:
                print("\t -%s" % (item))
            print("\n")

    return check


def checkHostkeys(hostkeys, checklist):
    check = False

    if hostkeys:
        extraHostkeys = [item for item in hostkeys if item not in checklist]
        missingHostkeys = [item for item in checklist if item not in hostkeys]

        for item in checklist:
            if " / " in item:
                orList = re.split(" / ", item)
                extraHostkeys = [item for item in extraHostkeys if item not in orList]
                missingHostkeys = [item for item in missingHostkeys if orList[0] and orList[1] not in item]

        if (len(extraHostkeys) != 0):
            check = True
            print("\t * Extra hostkeys found for target.")

            if RESPONSES:
                print("Extra hostkeys supported by target: ")

                for item in extraHostkeys:
                    print("\t -%s" % (item))
                print("\n")

        else:
            print("\t * No extra hostkeys found for target.")

        if (len(missingHostkeys) != 0):
            check = True
            print("\t * Missing hostkeys found for target.")

            if RESPONSES:
                print("Missing hostkeys in target as should be advertised according to the version in the identification string: ")

                for item in missingHostkeys:
                    print("\t -%s" % (item))
                print("\n")

        else:
            print("\t * No missing hostkeys found for target.")
    else:
        check = True
        print("\t * No supported hostkeys found for target.")

        if RESPONSES:
            print("WARNING: missing hostkeys found for target.")
            print("Missing hostkeys in target as should be advertised according to the version in the identification string: ")

            for item in checklist:
                print("\t -%s" % (item))
            print("\n")

    return check


def parseAlgorithmsNmap(algorithms):
    splittedList = algorithms.split("\n")
    algorithmList = [line[6:] for line in splittedList if re.match("      ", line)]
    # print("Algorithms parsed: " + str(algorithmList))

    return algorithmList


def nmapAlgorithmScan(host, port):
    print("\n* CHECK 2: Scanning with nmap to find supported algorithms by target...")

    scan = nmap.PortScanner()
    scanOutput = scan.scan(host, port, arguments='--script=/usr/share/nmap/scripts/ssh2-enum-algos.nse -sV')
    algorithms = (scanOutput['scan'][host]['tcp'][int(port)]['script']['ssh2-enum-algos'])

    if RESPONSES:
        print("! Supported Algorithms: %s \n" % (algorithms))

    return parseAlgorithmsNmap(algorithms)


def parseHostkeysNmap(hostkeys):
    splittedList = hostkeys.split("\n")
    hostkeyList = [line.split(" ")[-1].strip("()") for line in splittedList if line[:2] == "  "]

    if RESPONSES:
        print("! Hostkeys parsed: " + str(hostkeyList))

    if len(hostkeyList) != 0:
        return hostkeyList
    else:
        return 0


def nmapHostkeyScan(host, port):
    print("\n* CHECK 3: Scanning with nmap to find host keys used by target...")

    scan = nmap.PortScanner()
    scanOutput = scan.scan(host, port, arguments='--script=/usr/share/nmap/scripts/ssh-hostkey.nse -sV')
    hostkeys = (scanOutput['scan'][host]['tcp'][int(port)]['script']['ssh-hostkey'])

    if RESPONSES:
        print("! Host keys: %s \n" % (hostkeys))

    return parseHostkeysNmap(hostkeys)


def versionResponse(host, port):
    sock, idString = connect(host, port)
    print("\n* CHECK 1: Checking response for non valid version...")

    try:
        sock.sendall("SSH-300\n".encode('utf-8'))
    except Exception as err:
        print("ERROR\n")

    response = sock.recv(2048)
    sock.close()

    if RESPONSES:
        print("response: %s" % (response))

    if not b"Protocol mismatch." in response:
        print("\t * Got non valid response, which looks like a honeypot.")
        return True
    else:
        print("\t* Packet is handled as an OpenSSH service.")
        return False


def sendValididString(sock):
    try:
        sock.sendall(VALID_OPENSSH_IDSTRING.encode('utf-8'))
    except Exception as err:
        print("Error sending identification string: %s" % str(err))

    return


def sendAlgorithms(sock):
    try:
        sock.sendall("curve25519-sha256\n;hmac-sha2-512\nzlib,none\n".encode('utf-8'))
    except Exception as err:
        print("Error sending key exchange algorithms %s" % str(err))

    response = sock.recv(2048)
    sock.close()

    if RESPONSES:
        print("response: %s" % (response))


def sendInvalidNewLine(host, port):
    sock, idString = connect(host, port)
    print("\n* CHECK 4: Sending an identification string with invalid new line to target server...")
    idString = VALID_OPENSSH_IDSTRING + "\n" + "anything"
    try:
        sock.sendall(idString.encode('utf-8'))
    except Exception as err:
        print("Error sending idString: %s" % str(err))

    response = sock.recv(2048)
    sock.close()

    if RESPONSES:
        print("response: %s" % (response))

    if b"Protocol mismatch" in response:
        print("\t * Packet is handled as a honeypot service.\n")
        return True
    elif response[-15:] == b"Packet corrupt\n":
        print("\t * Packet is handled as a honeypot service.\n")
        return True
    else:
        print("\t * Packet handled as an OpenSSH service.")
        return False


def sendLargeidString(host, port):
    print("\n* CHECK 5: Sending too many characters in idString to target server...")
    characters = "\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000055555\n\""
    try:
        response = subprocess.check_output("echo -e %s | nc %s %s" % (str(characters), str(host), str(port)), shell=True)
    except Exception as err:
        print("Error sending idString: %s" % str(err))

    if RESPONSES:
        print("response: %s" % (response))

    if b"Protocol mismatch" in response:
        print("\t * Packet is handled as a honeypot service.\n")
        return True
    else:
        print("\t * Packet handled as an OpenSSH service.")
        return False


def checkForHoneypot(host, port):
    print("* Start performing checks for honeypot...")
    score = 0

    if versionResponse (host, port):
        score += 1

    sock, idString = connect(host, port)
    checklistAlgos, checklistHostkeys, check = checkidString(idString)

    if checklistAlgos == 0:
        print("**This target is not a valid target.**")
        return "invalid"

    sendValididString(sock)
    sendAlgorithms(sock)

    # if RESPONSES:
    print("- Current score = %s" % (str(score)[:3]))

    foundAlgorithms = nmapAlgorithmScan(host, str(port))
    if checklistAlgos != 0 and checkAlgorithms(foundAlgorithms, checklistAlgos):
        score += 0.4

    # if RESPONSES:
    print("- Current score = %s" % (str(score)[:3]))

    foundHostkeys = nmapHostkeyScan(host, str(port))
    if checklistHostkeys != 0 and checkHostkeys(foundHostkeys, checklistHostkeys):
        score += 0.4

    # if RESPONSES:
    print("- Current score = %s" % (str(score)[:3]))

    if sendInvalidNewLine(host, port):
        score += 1

    # if RESPONSES:
    print("- Current score = %s" % (str(score)[:3]))

    if sendLargeidString(host, port):
        score += 1

    # if RESPONSES:
    print("- Current score = %s" % (str(score)[:3]))

    return score


if __name__ == '__main__':
    try:
        host = sys.argv[1]
        port = int(sys.argv[2])
    except Exception as err:
        print("Error parsing arguments: %f" % str(err))

    score = checkForHoneypot(host, port)

    if score != "invalid":
        print("\n The final score for this target is %s." % (str(score)[:3]))

        if score >= 1:
            print("** This target behaves as an SSH honeypot! **")
        else:
            print("** This target does behave as an OpenSSH server. **")
