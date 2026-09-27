// Package fixture writes small databases for tests.
package fixture

import (
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// CityNetwork places a network in a city, as a DB-IP city database does.
type CityNetwork struct {
	CIDR    string
	City    map[string]string // names by language
	Region  string            // English name
	Country string            // ISO code
}

// WriteCityDB writes networks to a MaxMind DB city database at path.
func WriteCityDB(path string, networks []CityNetwork) error {
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "DBIP-City-Lite", RecordSize: 28})
	if err != nil {
		return err
	}
	for _, n := range networks {
		_, ipNet, err := net.ParseCIDR(n.CIDR)
		if err != nil {
			return err
		}
		names := mmdbtype.Map{}
		for lang, name := range n.City {
			names[mmdbtype.String(lang)] = mmdbtype.String(name)
		}
		rec := mmdbtype.Map{
			"city":    mmdbtype.Map{"names": names},
			"country": mmdbtype.Map{"iso_code": mmdbtype.String(n.Country)},
		}
		if n.Region != "" {
			rec["subdivisions"] = mmdbtype.Slice{mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String(n.Region)}}}
		}
		if err := tree.Insert(ipNet, rec); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := tree.WriteTo(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
