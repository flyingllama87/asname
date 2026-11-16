package sources

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

// With a MaxMind account, the city update also writes MaxMind's city
// database (GeoLite2 City, free with an account, or a paid GeoIP2 City
// edition) next to DB-IP's, and lookups give both: two independent
// estimates, which agree or do not. Both are MaxMind DB files with the
// same layout.
const (
	MaxMindAccountEnvVar  = "ASNAME_MAXMIND_ACCOUNT_ID"
	MaxMindKeyEnvVar      = "ASNAME_MAXMIND_LICENSE_KEY"
	MaxMindEditionEnvVar  = "ASNAME_MAXMIND_EDITION"
	MaxMindCityEnvVar     = "ASNAME_MAXMIND_CITY"
	MaxMindCityFilename   = "maxmind-city.mmdb"
	maxMindDefaultEdition = "GeoLite2-City"

	// MaxMindSourceName names MaxMind among the city database's sources.
	MaxMindSourceName = "MaxMind"
)

// MaxMind's download URLs: the current one takes the account ID and key as
// HTTP basic auth; the older one takes the key alone, which keys issued
// since 2024 are refused on. Tests point them elsewhere.
var (
	maxMindDownload       = "https://download.maxmind.com/geoip/databases/%s/download?suffix=tar.gz"
	maxMindLegacyDownload = "https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz"
)

// MaxMindCredentials reads the MaxMind account from the environment. ok is
// false without a licence key.
func MaxMindCredentials() (account, key string, ok bool) {
	key = strings.TrimSpace(os.Getenv(MaxMindKeyEnvVar))
	account = strings.TrimSpace(os.Getenv(MaxMindAccountEnvVar))
	return account, key, key != ""
}

// maxMindEdition is the edition to download: $ASNAME_MAXMIND_EDITION, else
// GeoLite2-City.
func maxMindEdition() string {
	if e := strings.TrimSpace(os.Getenv(MaxMindEditionEnvVar)); e != "" {
		return e
	}
	return maxMindDefaultEdition
}

// updateMaxMindCity downloads edition and replaces path with the .mmdb
// inside the archive, once it opens as a city database. The key never
// appears in what it logs or returns.
func updateMaxMindCity(ctx context.Context, cfg Config, path, account, key, edition string) error {
	scrub := func(err error) error {
		if err == nil {
			return nil
		}
		msg := err.Error()
		for _, s := range []string{key, url.QueryEscape(key)} {
			if s != "" {
				msg = strings.ReplaceAll(msg, s, "…")
			}
		}
		return errors.New(msg)
	}
	var link string
	if account != "" {
		link = fmt.Sprintf(maxMindDownload, url.PathEscape(edition))
		ctx = withBasicAuth(ctx, account, key)
	} else {
		link = fmt.Sprintf(maxMindLegacyDownload, url.QueryEscape(edition), url.QueryEscape(key))
	}
	cache := cfg.CacheDir()
	f, err := openCached(ctx, cache, link, "")
	if err != nil {
		if account == "" && strings.Contains(err.Error(), "401") {
			return fmt.Errorf("MaxMind refused the licence key on its own; set %s to your account ID too", MaxMindAccountEnvVar)
		}
		return scrub(err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		dropCached(cache, link)
		return fmt.Errorf("decompressing the %s download: %v", edition, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	tmp := path + ".new"
	defer os.Remove(tmp)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			dropCached(cache, link)
			return fmt.Errorf("reading the %s download: %v", edition, err)
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".mmdb") {
			continue
		}
		if _, err := StreamFileAtomic(tmp, tr); err != nil {
			return err
		}
		found = true
		break
	}
	if !found {
		dropCached(cache, link)
		return fmt.Errorf("the %s download holds no .mmdb file", edition)
	}
	db, err := maxminddb.Open(tmp)
	if err != nil {
		return fmt.Errorf("the %s download is not a MaxMind database: %v", edition, err)
	}
	kind := db.Metadata.DatabaseType
	db.Close()
	if !strings.Contains(kind, "City") {
		return fmt.Errorf("%s is a %s database, not a city database; set %s to a City edition", edition, kind, MaxMindEditionEnvVar)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	var size int64
	if info, err := os.Stat(path); err == nil {
		size = info.Size()
	}
	logf(ctx, "asname: wrote %s (%s, %d bytes)\n", path, kind, size)
	noteSource(ctx, MaxMindSourceName, 0, edition)
	return nil
}

// CityProvider names who made a city database, from its own metadata:
// "DB-IP", "MaxMind GeoLite2" or "MaxMind GeoIP2".
func CityProvider(db *maxminddb.Reader) string {
	if db == nil {
		return ""
	}
	t := db.Metadata.DatabaseType
	switch {
	case strings.HasPrefix(t, "GeoLite2"):
		return "MaxMind GeoLite2"
	case strings.HasPrefix(t, "GeoIP2"):
		return "MaxMind GeoIP2"
	case strings.HasPrefix(strings.ToUpper(t), "DBIP"), t == "":
		return "DB-IP"
	default:
		return t
	}
}
