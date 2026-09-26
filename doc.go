// Package asname provides fast, in-memory IP address, hostname, and Autonomous System (ASN) intelligence.
//
// It resolves IP addresses to ASNs, AS names, countries, cities, network categories,
// and registry netblocks with sub-microsecond local lookups using an optimized radix trie.
//
// # Basic Usage
//
//	package main
//
//	import (
//		"fmt"
//		"log"
//
//		"github.com/flyingllama87/asname"
//	)
//
//	func main() {
//		client, err := asname.New()
//		if err != nil {
//			log.Fatalf("failed to initialize asname: %v", err)
//		}
//		defer client.Close()
//
//		results, err := client.Lookup("8.8.8.8")
//		if err != nil {
//			log.Fatalf("lookup failed: %v", err)
//		}
//
//		for _, r := range results {
//			fmt.Printf("IP: %s | ASN: %s | Name: %s | Country: %s\n",
//				r.IP, r.ASN, r.Name, r.Country)
//		}
//	}
//
// # Direct IP Lookup
//
//	res, err := client.LookupIP(net.ParseIP("1.1.1.1"))
//	if err == nil {
//		fmt.Println("ASN:", res.ASN, "Name:", res.Name)
//	}
//
// # Looking up an Autonomous System
//
//	res, err := client.LookupASN(15169)
//	if err == nil {
//		fmt.Println("Owner:", res.Name)
//		fmt.Println("Announced Prefixes:", res.Prefixes)
//	}
package asname
