package main

import (
	"fmt"
	"log"
	"strconv"
	"time"

	g "github.com/gosnmp/gosnmp"
)

var IFDESCR string = "1.3.6.1.2.1.2.2.1.2" //.1"
var IFTYPE string = "1.3.6.1.2.1.2.2.1.3"  //.1"

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

type SnmpDataOld struct {
	s string
}

type SnmpData struct {
	d map[string]string
}

func defaultSnmp() {
	g.Default.Target = "10.254.254.1"
	g.Default.Community = "gPublic"
	err := g.Default.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer g.Default.Conn.Close()

	oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
	result, err2 := g.Default.Get(oids) // Get() accepts up to g.MAX_OIDS
	if err2 != nil {
		log.Fatalf("Get() err: %v", err2)
	}

	for i, variable := range result.Variables {
		fmt.Printf("%d: oid: %s ", i, variable.Name)

		// the Value of each variable returned by Get() implements
		// interface{}. You could do a type switch...
		switch variable.Type {
		case g.OctetString:
			bytes := variable.Value.([]byte)
			fmt.Printf("string: %s\n", string(bytes))
		default:
			// ... or often you're just interested in numeric values.
			// ToBigInt() will return the Value as a BigInt, for plugging
			// into your calculations.
			fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
		}
	}
}

func customSnmp(env SnmpEnv, oid string, d SnmpData) map[string]string {
	if len(env.target) <= 0 {
		log.Fatalf("environment variable not set: GOSNMP_TARGET")
	}
	if len(env.port) <= 0 {
		log.Fatalf("environment variable not set: GOSNMP_PORT")
	}
	port, _ := strconv.ParseUint(env.port, 10, 16)

	// Build our own GoSNMP struct, rather than using g.Default.
	// Do verbose logging of packets.
	params := &g.GoSNMP{
		Target:    env.target,
		Port:      uint16(port),
		Community: env.community,
		Version:   g.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		//Logger:    g.NewLogger(log.New(os.Stdout, "", 0)),
	}
	err := params.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer params.Conn.Close()

	// Function handles for collecting metrics on query latencies.
	var sent time.Time
	params.OnSent = func(x *g.GoSNMP) {
		sent = time.Now()
	}
	params.OnRecv = func(x *g.GoSNMP) {
		log.Println("Query latency in seconds:", time.Since(sent).Seconds())
	}

	//oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
	oids := []string{oid}
	result, err2 := params.Get(oids) // Get() accepts up to g.MAX_OIDS
	if err2 != nil {
		log.Fatalf("Get() err: %v", err2)
	}

	temp := make(map[string]string)
	for i, variable := range result.Variables {
		fmt.Printf("%d: oid: %s ", i, variable.Name)
		// the Value of each variable returned by Get() implements
		// interface{}. You could do a type switch...
		switch variable.Type {
		case g.OctetString:
			fmt.Printf("string: %s\n", string(variable.Value.([]byte)))
			temp[variable.Name] = string(variable.Value.([]byte))
		default:
			// ... or often you're just interested in numeric values.
			// ToBigInt() will return the Value as a BigInt, for plugging
			// into your calculations.
			fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
			temp[variable.Name] = g.ToBigInt(variable.Value).String()
		}
	}
	return temp
}

func do_interface_stuff() {

	my_interface_data := SnmpData{
		make(map[string]string),
	}

	m := customSnmp(myenv, IFDESCR, my_interface_data)
	fmt.Printf("Here's M:\n")
	fmt.Println(m)
	fmt.Printf("\n")

	m = customSnmp(myenv, IFTYPE, my_interface_data)
	fmt.Printf("Here's M:\n")
	fmt.Println(m)
	fmt.Printf("\n")
}

func main() {
	//defaultSnmp()
	//customSnmp()

	// var oids [2]string
	// oids[0] = IFDESCR
	// oids[1] = IFTYPE

	do_interface_stuff()
}
