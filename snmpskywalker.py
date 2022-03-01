import sys
from typing import Dict

from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget,\
                         ContextData, ObjectType, ObjectIdentity, getCmd, nextCmd, bulkCmd

MYDICT = {}

HOST = "10.254.254.1"
IFDESCR = "1.3.6.1.2.1.2.2.1.2"
IFTYPE = "1.3.6.1.2.1.2.2.1.3"


def build_iterator(host: str, community: str, oid: str):
    iterator = bulkCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, 161), timeout=1, retries=5),
            ContextData(),
            0,100,  # non-repeaters, max-repetitions
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False,
            lexicographicMode=False
        )
    return iterator


def snmp_build_dict(request, oid_descr: str) -> None:
    # Utilizes global MYDICT
    response = []
    for errorIndication, errorStatus, errorIndex, snmp_response in request:
        oid = snmp_response[0][0].prettyPrint()
        index = oid.split('.')[-1]    # x.y.z.index
        value = snmp_response[0][1].prettyPrint()

        new_dict = {oid_descr:value}

        if index not in MYDICT:
            MYDICT[index] = new_dict
        else:
            MYDICT[index].update(new_dict)

    return None


def main():

    # BUILD INTERFACE INDEXES
    request = build_iterator(HOST, "gPublic", IFDESCR)
    snmp_build_dict(request=request, oid_descr="ifDescr")

    # BUILD INTERFACE TYPES
    request = build_iterator(HOST, "gPublic", IFTYPE)
    snmp_build_dict(request=request, oid_descr="ifType")   


    # Print out Dict

    for index in MYDICT:
        print(f"index: {index}\tifDescr: {MYDICT[index]['ifDescr']}\tifType: {MYDICT[index]['ifType']}")




if __name__ == "__main__":
    main()
