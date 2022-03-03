package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	g "github.com/gosnmp/gosnmp"
)

var IFDESCR string = "1.3.6.1.2.1.2.2.1.2"
var IFTYPE string = "1.3.6.1.2.1.2.2.1.3"
var CDPNEIGHBOR string = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
var CDPADDRESS string = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
var ROUTEDEST string = "1.3.6.1.2.1.4.24.4.1.1"
var ROUTEMASK string = "1.3.6.1.2.1.4.24.4.1.2"
var ROUTENEXTHOP string = "1.3.6.1.2.1.4.24.4.1.4"
var ROUTEPROTO string = "1.3.6.1.2.1.4.24.4.1.7"

var myenv = SnmpEnv{
	target:    "10.254.254.1",
	port:      "161",
	community: "gPublic",
}

type SnmpEnv struct {
	target    string
	port      string
	community string
}

type SnmpData struct {
	d map[string]string
}

func bulkWalkAll(env SnmpEnv, oid string, oid_descr string, temp map[string]map[string]string) map[string]map[string]string {
	port, _ := strconv.ParseUint(env.port, 10, 16)
	snmpObject := &g.GoSNMP{
		Target:    env.target,
		Port:      uint16(port),
		Community: env.community,
		Version:   g.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		//Logger:    g.NewLogger(log.New(os.Stdout, "", 0)),
	}

	err := snmpObject.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer snmpObject.Conn.Close()

	//err2 := params.BulkWalk(oid, printValue)

	// DO THE WALKY WALK
	results, err2 := snmpObject.BulkWalkAll(oid)
	if err2 != nil {
		log.Fatalf("Get() err: %v", err2)
	}

	// update map
	for _, result := range results {
		index := result.Name
		test := strings.Replace(index, oid, "", -1)
		index = strings.Trim(test, ".")
		var value string
		temp2 := make(map[string]string)

		switch oid_descr {
		// friggin cdp address values still screwy
		case "cdpCacheAddress":
			value = string(result.Value.([]byte))
			test := []byte(value)
			octettemp := [4]int{}
			for k, v := range test {
				octettemp[k] = int(v)
			}
			value = fmt.Sprintf("%d.%d.%d.%d", octettemp[0], octettemp[1], octettemp[2], octettemp[3])
		default:
			switch result.Type {
			case g.Integer:
				value = fmt.Sprintf("%d", result.Value)
			default:
				value = fmt.Sprintf("%s", result.Value)
			}
		}

		// create inner map (ifdescr: value)
		temp2[oid_descr] = value

		// check if index exists, if not create index and value(inner map), if so, add new key to existing inner map
		_, ok := temp[index]
		if ok == true {
			temp[index][oid_descr] = value
		} else {
			temp[index] = temp2
		}
	}

	return temp
}

// print my map, so pretty
func print_map(mymap map[string]map[string]string) {
	for _, innermap := range mymap {
		for k, v := range innermap {
			//fmt.Print(index, ": ", k, ": ", v, "\t")
			fmt.Print(k, ": ", v, "\t\t")
		}
		fmt.Printf("\n")
	}
}

func do_interface_stuff() {

	temp := make(map[string]map[string]string)
	my_interface_data := bulkWalkAll(myenv, IFDESCR, "ifDescr", temp)

	my_interface_data2 := bulkWalkAll(myenv, IFTYPE, "ifType", my_interface_data)
	print_map(my_interface_data2)
}

func do_cdp_stuff() {

	temp := make(map[string]map[string]string)
	my_cdp_data := bulkWalkAll(myenv, CDPNEIGHBOR, "cdpCacheDeviceId", temp)

	my_cdp_data2 := bulkWalkAll(myenv, CDPADDRESS, "cdpCacheAddress", my_cdp_data)
	print_map(my_cdp_data2)
}

func do_ip_route_stuff() {

	temp := make(map[string]map[string]string)
	my_route_data := bulkWalkAll(myenv, ROUTEDEST, "ipCidrRouteDest", temp)

	my_route_data2 := bulkWalkAll(myenv, ROUTEMASK, "ipCidrRouteMask", my_route_data)
	my_route_data3 := bulkWalkAll(myenv, ROUTENEXTHOP, "ipCidrRouteNextHop", my_route_data2)
	my_route_data4 := bulkWalkAll(myenv, ROUTEPROTO, "ipCidrRouteProto", my_route_data3)
	print_map(my_route_data4)
}

func main() {
	do_interface_stuff()
	do_cdp_stuff()
	do_ip_route_stuff()

}
