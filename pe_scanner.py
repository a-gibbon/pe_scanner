#!/usr/bin/python3


import argparse
import configparser
import os
import string
import sys

from binascii import hexlify
from configparser import ConfigParser
from datetime import datetime

from lib.entropy import BarGraph
from lib.namespace import as_namespace
from lib.pescan import PeScan, conv


FG_BLACK = "\033[38;5;232m"
BG_WHITE = "\033[48;5;255m"
BG_GRAYS = "\033[48;5;244m"
BG_AMBER = "\033[48;5;214m"
RESET    = "\033[0m"
NL       = "\n"


SUSPICIOUS = FG_BLACK + BG_AMBER + "%s" + RESET
HEADER     = FG_BLACK + BG_WHITE + "%s" + RESET
SUBHEADER  = FG_BLACK + BG_GRAYS + "%s" + RESET


def arguments():
    parser = argparse.ArgumentParser(
        description=
            "Scans Portable Executable (PE) files for "
            "suspicous characteristics")
    parser.add_argument(
        "-f", 
        "--file",
        help="file to scan", 
        required=True,
        dest="FILE")

    subparsers  = parser.add_subparsers(
        required=True,
        dest="")

    scan = subparsers.add_parser("scan")
    scan.set_defaults(func=suspicious_characteristics)

    yara = subparsers.add_parser("yara")
    yara.set_defaults(func=yara_signatures)

    scan.add_argument(
        "--show-all-resources",
        help="show all resources",
        action="store_true",
        default=False,
        dest="SHOW_ALL_RESOURCES")

    yara.add_argument(
        "-s",
        "--signature",
        help="path to Yara signature file",
        required=True,
        dest="SIGNATURE")
    
    return parser.parse_args()


def is_file(var):
    if not os.path.isfile(var):
        raise OSError(f"{var} is not a file")
    elif not os.access(var, os.R_OK):
        raise OSError(f"{var} is not readable")
    elif not os.path.getsize(var) > 0:
        raise OSError(f"{var} is an empty file")
    else:
        return os.path.abspath(var)


def suspicious_characteristics(options):
    WIN32_API_FILE = "lib/win32api.alerts"

    if not os.path.exists(WIN32_API_FILE):
        raise OSError(f"Cannot find WIN32_API_FILE '{WIN32_API_FILE}'")

    WIN32_API_ALERTS = ConfigParser(allow_no_value=True)

    with open(WIN32_API_FILE, 'r') as fp:
        WIN32_API_ALERTS.read_file(fp)

    pe = PeScan(name=options.FILE)

    EXP_FORMAT = "{0:<15} {1} ({2})"
    SEC_FORMAT = "{0:<10} {1:<10} {2:<10} {3:<10} {4:<10} {5}"
    RES_FORMAT = "{0:<20} {1:<10} {2:<10} {3:<25} {4}"

    print(HEADER % "[METADATA]")

    print(f"{{:<20}} {os.path.basename(options.FILE)}".format("File"))
    print(f"{{:<20}} {pe.FILE_SIZE:,d} bytes".format("Size"))
    print(f"{{:<20}} {pe.FILETYPE}".format("Filetype"))
    print(f"{{:<20}} {pe.MD5_HASH}".format("MD5"))
    print(f"{{:<20}} {pe.SHA1_HASH}".format("SHA1"))
    print(f"{{:<20}} {pe.SHA256_HASH}".format("SHA256"))
    print(f"{{:<20}} {pe.IMPORT_HASH}".format("Import Hash"))
    print(f"{{:<20}} {pe.PDB_PATH}".format("PDB Path"))

    try:
        date_time = datetime.fromisoformat(pe.DATE_TIMESTAMP)
        that_year = date_time.year
        this_year = datetime.now().year
    except ValueError:
        print(SUSPICIOUS % f"{{:<20}} {pe.DATE_TIMESTAMP} UTC".format("Compile Date"))
    else:
        # 2000 is an arbitrary year
        if that_year < 2000 or that_year > this_year:
            print(SUSPICIOUS % f"{{0:<20}} {pe.DATE_TIMESTAMP} UTC".format("Compile Date"))
        else:
            print(f"{{:<20}} {pe.DATE_TIMESTAMP} UTC".format("Compile Date"))

    pe.CRC_CHECKSUM = as_namespace(pe.CRC_CHECKSUM)

    if pe.CRC_CHECKSUM.Verified:
        print(f"{{:<20}} {pe.CRC_CHECKSUM.Actual}".format("CRC"))
    else:
        # Alert if generated CRC checksum does not match with CRC checksum
        # in the OPTIONAL_HEADER
        print(SUSPICIOUS % f"{{:<20}} {pe.CRC_CHECKSUM.Claimed} \u2260 {pe.CRC_CHECKSUM.Actual}".format("CRC"))

    print(NL + HEADER % "[ENTRY POINT]")

    if pe.ENTRY_POINT is not None:
        pe.ENTRY_POINT = as_namespace(pe.ENTRY_POINT)

        EP = (
            f"{pe.ENTRY_POINT.Name} "
            f"{pe.ENTRY_POINT.Position:d}/{pe.ENTRY_POINT.NumberOfSections}; "
            f"RVA: {pe.ENTRY_POINT.RVA}; "
            f"RAW: {pe.ENTRY_POINT.Raw}")

    if pe.ENTRY_POINT is None or pe.ENTRY_POINT.Position == 0:
        print(f"None")
    elif pe.ENTRY_POINT.Name not in ['.text', '.code', 'CODE', 'INIT', 'PAGE']:
        # Alert if the EP section is not a known good section 
        print(SUSPICIOUS % EP)
    elif pe.ENTRY_POINT.Position != 1:
        # Alert if the EP section is not the first PE section
        print(SUSPICIOUS % EP)
    else:
        print(EP)

    # Build an entropy graph
    print(NL + HEADER % "[ENTROPY GRAPH]")
    graph = BarGraph(data=pe.__data__)
    graph.build(X_AXIS=128)
    graph.display()

    if pe.TLS_CALLBACKS:
        print(NL + HEADER % "[TLS CALLBACKS]")

        for callback in pe.TLS_CALLBACKS:
            print(callback)

    if pe.IMPORTED_LIBRARIES:
        KERNEL_DLLs = [
            "HAL.DLL",
            "NTDLL.DLL",
            "NTOSKRNL.EXE"]

        print(NL + HEADER % "[IMPORTED LIBRARIES]")

        ALERTS = []

        for DLL in pe.IMPORTED_LIBRARIES:
            if DLL in KERNEL_DLLs:
                print(SUSPICIOUS % f"{DLL:<30}")
            else:
                print(DLL)
            if DLL not in WIN32_API_ALERTS:
                continue
            APIs = pe.IMPORTED_LIBRARIES[DLL]
            for API in APIs:
                # Alert if the PE file is calling any user-defined Win33 API 
                # functions or any Native API functions exported by ntdll.dll
                # There is functionality provided in Native API that is not 
                # exposed to Win32 API however most programs will not call the 
                # Native API directly.
                for alert in WIN32_API_ALERTS[DLL]:
                    if API.lower().startswith(alert):
                        ALERTS.append(API)

        if ALERTS:
            print(NL + HEADER % "[API ALERTS]")

            for alert in ALERTS:
                print(alert)

    if pe.EXPORTED_LIBRARIES:
        print(NL + HEADER % "[EXPORTED LIBRARIES]")
        print(SUBHEADER % EXP_FORMAT.format(
            "VirtAddr", "Name", "Ordinal"))

        for exports in pe.EXPORTED_LIBRARIES:
            print(EXP_FORMAT.format(*exports))

    print(NL + HEADER % "[SECTIONS]")
    print(SUBHEADER % SEC_FORMAT.format(
        "Name", "VirtAddr", "VirtSize", "RawSize", "Entropy", "Characteristics"))

    for section in pe.SECTIONS:
        if section[3] == 0:
            # Alert if RawSize == 0
            print(SUSPICIOUS % SEC_FORMAT.format(*section))
        elif 0 < section[4] < 1:
            # Alert if Entropy is below 1
            print(SUSPICIOUS % SEC_FORMAT.format(*section))
        elif section[4] > 7:
            # Alert if Entropy is above 7
            print(SUSPICIOUS % SEC_FORMAT.format(*section))
        else:
            print(SEC_FORMAT.format(*section))

    print(NL + HEADER % "[RESOURCES]")
    print(SUBHEADER % RES_FORMAT.format(
        "Name", "RVA", "Size", "Language", "Filetype"))

    flag = False
    for resource in pe.RESOURCE_ENTRIES:
        if resource[4].startswith('PE32+'):
            print(SUSPICIOUS % RES_FORMAT.format(*resource))
            flag = True
        elif options.SHOW_ALL_RESOURCES:
            print(RES_FORMAT.format(*resource))
            flag = True
        elif not resource[0].startswith('RT_'):
            print(RES_FORMAT.format(*resource))
            flag = True

    if not flag:
        print("No resources displayed. Try '--show-all-resources'")

    print(NL + HEADER % "[VERSION INFORMATION]")

    for information in pe.VERSION_INFORMATION:
        print(f"{information[0]:<20} {information[1]}")


def yara_signatures(options):
    try:
        import yara
    except ImportError:
        exit("yara-python is not installed")

    print(HEADER % "[YARA SIGNATURES]")

    YARA_COMPILE = True

    try:
        rules = yara.compile(options.SIGNATURE)
    except SyntaxError:
        YARA_COMPILE = False

    if not rules or not YARA_COMPILE:
        exit(f"Yara file '{options.SIGNATURE}' could not be compiled")

    matches = rules.match(options.FILE)

    if not matches:
        exit(f"No matches found in Yara file '{options.SIGNATURE}'")

    for hit in rules.match(options.FILE):
        print(SUBHEADER % f"Rule: {hit.rule}")
        for (key, name, value) in hit.strings:
            pair = (hex(key), conv(value))
            if not all(c in string.printable for c in pair[1]):
                pair = (hex(key), conv(binascii.hexlify(value)))
            print("{0:>3} -> {1}".format(*pair))
        print()

if __name__ == '__main__':
    try:
        options = arguments()
    except TypeError as e:
        raise argparse.ArgumentError(e)

    options.func(options)

