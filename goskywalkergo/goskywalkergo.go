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

// func defaultSnmp() {
// 	g.Default.Target = "10.254.254.1"
// 	g.Default.Community = "gPublic"
// 	err := g.Default.Connect()
// 	if err != nil {
// 		log.Fatalf("Connect() err: %v", err)
// 	}
// 	defer g.Default.Conn.Close()

// 	oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
// 	result, err2 := g.Default.Get(oids) // Get() accepts up to g.MAX_OIDS
// 	if err2 != nil {
// 		log.Fatalf("Get() err: %v", err2)
// 	}

// 	for i, variable := range result.Variables {
// 		fmt.Printf("%d: oid: %s ", i, variable.Name)

// 		// the Value of each variable returned by Get() implements
// 		// interface{}. You could do a type switch...
// 		switch variable.Type {
// 		case g.OctetString:
// 			bytes := variable.Value.([]byte)
// 			fmt.Printf("string: %s\n", string(bytes))
// 		default:
// 			// ... or often you're just interested in numeric values.
// 			// ToBigInt() will return the Value as a BigInt, for plugging
// 			// into your calculations.
// 			fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
// 		}
// 	}
// }

// func printValue(pdu gosnmp.SnmpPDU) error {
// 	fmt.Printf("%s = ", pdu.Name)

// 	switch pdu.Type {
// 	case gosnmp.OctetString:
// 		b := pdu.Value.([]byte)
// 		fmt.Printf("STRING: %s\n", string(b))
// 	default:
// 		fmt.Printf("TYPE %d: %d\n", pdu.Type, gosnmp.ToBigInt(pdu.Value))
// 	}
// 	return nil
// }

// func snmpGet(env SnmpEnv, oid string, d SnmpData) map[string]map[string]string {
// 	if len(env.target) <= 0 {
// 		log.Fatalf("environment variable not set: GOSNMP_TARGET")
// 	}
// 	if len(env.port) <= 0 {
// 		log.Fatalf("environment variable not set: GOSNMP_PORT")
// 	}
// 	port, _ := strconv.ParseUint(env.port, 10, 16)

// 	// Build our own GoSNMP struct, rather than using g.Default.
// 	// Do verbose logging of packets.
// 	params := &g.GoSNMP{
// 		Target:    env.target,
// 		Port:      uint16(port),
// 		Community: env.community,
// 		Version:   g.Version2c,
// 		Timeout:   time.Duration(2) * time.Second,
// 		//Logger:    g.NewLogger(log.New(os.Stdout, "", 0)),
// 	}
// 	err := params.Connect()
// 	if err != nil {
// 		log.Fatalf("Connect() err: %v", err)
// 	}
// 	defer params.Conn.Close()

// 	// Function handles for collecting metrics on query latencies.
// 	var sent time.Time
// 	params.OnSent = func(x *g.GoSNMP) {
// 		sent = time.Now()
// 	}
// 	params.OnRecv = func(x *g.GoSNMP) {
// 		log.Println("Query latency in seconds:", time.Since(sent).Seconds())
// 	}

// 	//oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
// 	oids := []string{oid}
// 	result, err2 := params.Get(oids) // Get() accepts up to g.MAX_OIDS
// 	if err2 != nil {
// 		log.Fatalf("Get() err: %v", err2)
// 	}

// 	temp := make(map[string]map[string]string)
// 	temp2 := make(map[string]string)
// 	for i, variable := range result.Variables {
// 		fmt.Printf("%d: oid: %s ", i, variable.Name)
// 		// the Value of each variable returned by Get() implements
// 		// interface{}. You could do a type switch...
// 		switch variable.Type {
// 		case g.OctetString:
// 			fmt.Printf("string: %s\n", string(variable.Value.([]byte)))
// 			temp2[variable.Name] = string(variable.Value.([]byte))
// 			temp[variable.Name] = temp2
// 		default:
// 			// ... or often you're just interested in numeric values.
// 			// ToBigInt() will return the Value as a BigInt, for plugging
// 			// into your calculations.
// 			fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
// 			temp2[variable.Name] = g.ToBigInt(variable.Value).String()
// 			temp[variable.Name] = temp2
// 		}
// 	}
// 	return temp
// }

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
	results, err2 := snmpObject.BulkWalkAll(oid)
	if err2 != nil {
		log.Fatalf("Get() err: %v", err2)
	}

	for _, result := range results {
		index := result.Name
		test := strings.Replace(index, oid, "", -1)
		index = strings.Trim(test, ".")
		var value string
		temp2 := make(map[string]string)

		switch result.Type {
		case g.OctetString:
			value = string(result.Value.([]byte))
			test := []byte(value)
			//test2, _ := strconv.Atoi(string(test))
			fmt.Printf("bytes = %b\n", test)
		default:
			value = fmt.Sprintf("%s", result.Value)
		}

		temp2[oid_descr] = value

		_, ok := temp[index]
		if ok == true {
			temp[index][oid_descr] = value
		} else {
			temp[index] = temp2
		}
	}

	return temp
}

func print_map(mymap map[string]map[string]string) {
	for _, innermap := range mymap {
		for k, v := range innermap {
			//fmt.Print(index, ": ", k, ": ", v, "\t")
			fmt.Print(k, ": ", v, "\t")
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
