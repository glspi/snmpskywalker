import sys, ipaddress
from typing import Dict
from dataclasses import dataclass

from pyasn1.type.univ import OctetString
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
    nextCmd,
    bulkCmd,
)


# Used for misc global dictionaries
@dataclass
class SnmpInfo:
    data: Dict


# OID's
HOST = "10.254.254.1"
COMMUNITY = "gPublic"
IFDESCR = "1.3.6.1.2.1.2.2.1.2"
IFTYPE = "1.3.6.1.2.1.2.2.1.3"
CDPNEIGHBOR = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDPADDRESS = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"


def build_iterator(host: str, community: str, oid: str):
    iterator = bulkCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, 161), timeout=1, retries=5),
        ContextData(),
        0,
        100,  # non-repeaters, max-repetitions
        ObjectType(ObjectIdentity(oid)),
        lookupMib=False,
        lexicographicMode=False,
    )
    return iterator


def snmp_build_dict(request, oid_descr: str, data) -> None:
    response = []
    for errorIndication, errorStatus, errorIndex, snmp_response in request:
        oid = snmp_response[0][0].prettyPrint()
        index = oid.split(".")[-1]  # u.x.y.z.index
        if oid_descr == "cdpCacheAddress":  # Convert crap to ipv4
            value = ".".join([str(x) for x in snmp_response[0][1].asNumbers()])
        else:
            value = snmp_response[0][1].prettyPrint()

        new_dict = {oid_descr: value}

        if index not in data.data:
            data.data[index] = new_dict
        else:
            data.data[index].update(new_dict)

    return None


def do_interface_data_stuff():
    my_intf_data = SnmpInfo({})

    # BUILD INTERFACE INDEXES
    request = build_iterator(HOST, COMMUNITY, IFDESCR)
    snmp_build_dict(request=request, oid_descr="ifDescr", data=my_intf_data)

    # BUILD INTERFACE TYPES
    request = build_iterator(HOST, COMMUNITY, IFTYPE)
    snmp_build_dict(request=request, oid_descr="ifType", data=my_intf_data)

    # Print out Dict
    for index in my_intf_data.data:
        print(
            f"index: {index}\tifDescr: {my_intf_data.data[index]['ifDescr']}\tifType: {my_intf_data.data[index]['ifType']}"
        )


def do_cdp_data_stuff():
    my_cdp_data = SnmpInfo({})

    # BUILD CDP NEIGHBORS
    request = build_iterator(HOST, COMMUNITY, CDPNEIGHBOR)
    snmp_build_dict(request=request, oid_descr="cdpCacheDeviceId", data=my_cdp_data)

    # BUILD CDP ADDRESSES
    request = build_iterator(HOST, COMMUNITY, CDPADDRESS)
    snmp_build_dict(request=request, oid_descr="cdpCacheAddress", data=my_cdp_data)

    # Print out Dict
    for index in my_cdp_data.data:
        print(
            f"index: {index}\tcdpCacheDeviceId: {my_cdp_data.data[index]['cdpCacheDeviceId']}\tcdpCacheAddress: {my_cdp_data.data[index]['cdpCacheAddress']}"
        )


def main():

    print("Interface stuff: ")
    do_interface_data_stuff()
    print("Interface stuff:\t^^^^^\n")
    print("CDP Stuff:")
    do_cdp_data_stuff()
    print("CDP Stuff:\t^^^^^^\n")


if __name__ == "__main__":
    main()
