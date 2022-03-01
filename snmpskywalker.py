import sys, re
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
ROUTETABLE = "1.3.6.1.2.1.4.24.4.1.1"
ROUTEMASK = "1.3.6.1.2.1.4.24.4.1.2"
ROUTENEXTHOP = "1.3.6.1.2.1.4.24.4.1.4"
ROUTEPROTO = "1.3.6.1.2.1.4.24.4.1.7"
OSPFNEIGHBOR = "1.3.6.1.2.1.14.10.1.1"


def print_dict(mydict: Dict) -> None:
    for k, index in mydict.items():
        for k, v in index.items():
            print(
                f"{k}: {v}", end="\t\t"
            )  # Print each 'index' key/value pair all on one line separated by tabs
        print()


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


def snmp_build_dict(request, oid: str, oid_descr: str, mydata: Dict) -> None:
    """
    builds/updates a dict (dataclass sent in as 'mydata' and updated based on new info pulled
    correlates to existing data (one dataclass instance for interface stuff, one for cdp neighbors, etc?)
    """

    response = []
    for errorIndication, errorStatus, errorIndex, snmp_response in request:
        _ = snmp_response[0][0].prettyPrint()
        # index = _.split(".")[-1]  # w.x.y.z.index -- old, not usable with iproute/etc
        index = _.replace(oid, "").strip(
            "."
        )  # strip anything at end of oid (and the last .) this is the 'index'

        if (
            oid_descr == "cdpCacheAddress"
        ):  # Convert crap to ipv4 for (so far) only this value which is returned as 'almost/kinda/not really' hex so must get useable value here rather than later
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
    request = build_iterator(host=HOST, community=COMMUNITY, oid=IFDESCR)
    snmp_build_dict(  # Grabs ALL ifdescr's
        request=request, oid=IFDESCR, oid_descr="ifDescr", mydata=my_intf_data
    )

    # BUILD INTERFACE TYPES
    request = build_iterator(HOST, COMMUNITY, IFTYPE)
    snmp_build_dict(  # Grabs ALL iftypes
        request=request, oid=IFTYPE, oid_descr="ifType", mydata=my_intf_data
    )

    # Print out Dict, already correlated
    print_dict(my_intf_data.data)


def do_cdp_data_stuff():
    my_cdp_data = SnmpInfo({})

    # BUILD CDP NEIGHBORS
    request = build_iterator(HOST, COMMUNITY, CDPNEIGHBOR)
    snmp_build_dict(  # Grabs ALL CDP Neighbor Hostnames
        request=request,
        oid=CDPNEIGHBOR,
        oid_descr="cdpCacheDeviceId",
        mydata=my_cdp_data,
    )

    # BUILD CDP ADDRESSES
    request = build_iterator(HOST, COMMUNITY, CDPADDRESS)
    snmp_build_dict(  # Grabs ALL CDP Neighbor IP Addresses
        request=request, oid=CDPADDRESS, oid_descr="cdpCacheAddress", mydata=my_cdp_data
    )

    # Print out Dict, already correlated
    print_dict(my_cdp_data.data)


def do_ip_route_stuff():
    my_route_data = SnmpInfo({})

    # BUILD ROUTE DESTINATIONS
    request = build_iterator(HOST, COMMUNITY, ROUTETABLE)
    snmp_build_dict(  # Grabs ALL route's
        request=request,
        oid=ROUTETABLE,
        oid_descr="ipCidrRouteDest",
        mydata=my_route_data,
    )
    # BUILD ROUTE MASKS
    request = build_iterator(HOST, COMMUNITY, ROUTEMASK)
    snmp_build_dict(  # Grabs ALL route's
        request=request,
        oid=ROUTEMASK,
        oid_descr="ipCidrRouteMask",
        mydata=my_route_data,
    )
    # BUILD ROUTE NEXT HOPS
    request = build_iterator(HOST, COMMUNITY, ROUTENEXTHOP)
    snmp_build_dict(  # Grabs ALL route's
        request=request,
        oid=ROUTENEXTHOP,
        oid_descr="ipCidrRouteNextHop",
        mydata=my_route_data,
    )
    # BUILD ROUTE PROTOCOL
    request = build_iterator(HOST, COMMUNITY, ROUTEPROTO)
    snmp_build_dict(  # Grabs ALL route's
        request=request,
        oid=ROUTEPROTO,
        oid_descr="ipCidrRouteProto",
        mydata=my_route_data,
    )

    # Print out Dict, already correlated
    print_dict(my_route_data.data)


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
