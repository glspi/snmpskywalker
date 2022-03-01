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


def build_iterator(host: str, community: str, oid: str):  # -> iterator?!
    """
    Builds 'iterator' -- can also add multiple OID's in one iterator but not implemented here due to bulkCmd use/maybe unnecessary?!
    """
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


def snmp_build_dict(request, oid_descr: str, mydata) -> None:
    """
    builds/updates a dict (dataclass sent in as 'mydata' and updated based on new info pulled
    correlates to existing data (one dataclass instance for interface stuff, one for cdp neighbors, etc?)
    """
    response = []
    for errorIndication, errorStatus, errorIndex, snmp_response in request:
        oid = snmp_response[0][0].prettyPrint()
        index = oid.split(".")[-1]  # w.x.y.z.index
        if (
            oid_descr == "cdpCacheAddress"
        ):  # Convert crap to ipv4 for (so far) only this value
            value = ".".join([str(x) for x in snmp_response[0][1].asNumbers()])
        else:
            value = snmp_response[0][1].prettyPrint()

        new_dict = {oid_descr: value}

        # Add new or update/add to existing based on 'index/key'
        if index not in mydata.data:
            mydata.data[index] = new_dict
        else:
            mydata.data[index].update(new_dict)

    return None  # Dict already updated


def do_interface_data_stuff():
    my_intf_data = SnmpInfo({})

    # BUILD INTERFACE INDEXES
    request = build_iterator(HOST, COMMUNITY, IFDESCR)
    snmp_build_dict(  # Grabs ALL ifdescr's
        request=request, oid_descr="ifDescr", mydata=my_intf_data
    )

    # BUILD INTERFACE TYPES
    request = build_iterator(HOST, COMMUNITY, IFTYPE)
    snmp_build_dict(  # Grabs ALL iftypes
        request=request, oid_descr="ifType", mydata=my_intf_data
    )

    # Print out Dict, already correlated
    for index in my_intf_data.data:
        print(
            f"index: {index}\tifDescr: {my_intf_data.data[index]['ifDescr']}\tifType: {my_intf_data.data[index]['ifType']}"
        )


def do_cdp_data_stuff():
    my_cdp_data = SnmpInfo({})

    # BUILD CDP NEIGHBORS
    request = build_iterator(HOST, COMMUNITY, CDPNEIGHBOR)
    snmp_build_dict(  # Grabs ALL CDP Neighbor Hostnames
        request=request,
        oid_descr="cdpCacheDeviceId",
        mydata=my_cdp_data,
    )

    # BUILD CDP ADDRESSES
    request = build_iterator(HOST, COMMUNITY, CDPADDRESS)
    snmp_build_dict(  # Grabs ALL CDP Neighbor IP Addresses
        request=request, oid_descr="cdpCacheAddress", mydata=my_cdp_data
    )

    # Print out Dict, already correlated
    for index in my_cdp_data.data:
        print(
            f"index: {index}\tcdpCacheDeviceId: {my_cdp_data.data[index]['cdpCacheDeviceId']}\tcdpCacheAddress: {my_cdp_data.data[index]['cdpCacheAddress']}"
        )


def do_ip_route_stuff():
    print("hi")


def do_ospf_stuff():
    print("there")


def main():

    print("Interface stuff: ")
    do_interface_data_stuff()
    print("Interface stuff:\t^^^^^\n")

    print("CDP Stuff:")
    do_cdp_data_stuff()
    print("CDP Stuff:\t^^^^^^\n")

    print("ip route Stuff:")
    do_ip_route_stuff()
    print("ip route Stuff:\t^^^^^^\n")

    print("OSPF Stuff:")
    do_ospf_stuff()
    print("OSPFStuff:\t^^^^^^\n")


if __name__ == "__main__":
    main()
