import sys

from typing import Dict

from easysnmp import Session
from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget,\
                         ContextData, ObjectType, ObjectIdentity, getCmd, nextCmd, bulkCmd


HOST = "10.254.254.1"
IFTABLE = "1.3.6.1.2.1.2.2"
IFDESCR = "1.3.6.1.2.1.2.2.1.2"
IFTYPE = "1.3.6.1.2.1.2.2.1.3"

def snmp_get():
    pass

def get_interfaces():
    pass

def build_iterator(host:str, community:str, oid:str):
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

# nextCmd crazy slower than bulkCmd (above)
#
# def build_iterator(host:str, community:str, oid:str):
#     iterator = nextCmd(
#             SnmpEngine(),
#             CommunityData(community, mpModel=1),
#             UdpTransportTarget((host, 161), timeout=1, retries=5),
#             ContextData(),
#             #0,50,
#             ObjectType(ObjectIdentity(oid)),
#             #lookupMib=False,
#             lexicographicMode=False
#         )
#     return iterator



def my_snmp_get(request:str, temp_type:str) -> Dict:
    response = []
    for errorIndication, errorStatus, errorIndex, snmp_response in request:
        oid = snmp_response[0][0].prettyPrint()
        index = oid.split('.')[-1]    # x.y.z.index
        value = snmp_response[0][1].prettyPrint()
        
        values = {"ifIndex":index, temp_type:value}
        response.append(values)
    return response

def main():
    # Why do all examples use next(iterator) instead of a for loop?
    #
    #count = 0
    # while(count < 500):
    #     try:
    #         errorIndication, errorStatus, errorIndex, snmp_response = next(iterator)
    #         print(snmp_response[0].prettyPrint())
    #     except StopIteration:
    #         break
    #     #count += 1

    # BUILD INTERFACE INDEXES
    request = build_iterator(HOST, "gPublic", IFDESCR)
    ifdescrs = my_snmp_get(request=request, temp_type="ifDescr")
    for interface in ifdescrs:
        print(f"ifIndex- {interface['ifIndex']}\tifDescr- {interface['ifDescr']}") 
    
    # BUILD INTERFACE TYPES
    request = build_iterator(HOST, "gPublic", IFTYPE)
    iftypes = my_snmp_get(request=request, temp_type="ifType")   

    for iftype in iftypes:
        print(f"ifIndex- {iftype['ifIndex']}\tifType- {iftype['ifType']}") 

    def search_list(mylist, search_for):
        for i,d in enumerate(mylist):
            if search_for in d["ifIndex"]:
                return (i)
            
        return None

    # Add to big dictionary
    #mydict = ifdescrs.update(ift)
    print("\nLogic time!\n")

    my_not_dict = ifdescrs

    for iftype in iftypes:

        ifindex = iftype["ifIndex"]

        index_exists = search_list(my_not_dict, ifindex)

        if index_exists:
            my_not_dict[index_exists].update(iftype)
        else:
            print(f"error?! no index: {ifindex}, iftype: {iftype}")

    print(my_not_dict)    

    for d in my_not_dict:
        iftype = d.get("ifType")
        print(f"index: {d['ifIndex']}\tifDescr: {d['ifDescr']}\tifType: {iftype}")


if __name__ == "__main__":
    main()
