package redhat

import (
	"fmt"
	"os"
	"strconv"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/goval-dictionary/fetcher/util"
)

// FetchFiles fetch OVAL from RedHat
func FetchFiles(versions []string) (map[string][]util.FetchResult, error) {
	results := map[string][]util.FetchResult{}
	for _, v := range versions {
		n, err := strconv.Atoi(v)
		if err != nil {
			log15.Warn("Skip unknown redhat.", "version", v)
			continue
		}

		result, err := fetchFilesFromLocal(v)
		if err != nil {
			return nil, xerrors.Errorf("Failed to read. err: %w", err)
		}
		results[v] = append(results[v], result)

		if n < 6 {
			log15.Warn("Skip redhat because no vulnerability information provided.", "version", v)
			continue
		}

		reqs := []util.FetchRequest{{
			Target:   v,
			URL:      fmt.Sprintf("https://access.redhat.com/security/data/oval/v2/RHEL%s/rhel-%s.oval.xml.bz2", v, v),
			MIMEType: util.MIMETypeBzip2,
		}}

		rs, err := util.FetchFeedFiles(reqs)
		if err != nil {
			return nil, xerrors.Errorf("Failed to fetch. err: %w", err)
		}
		results[v] = append(results[v], rs...)
	}
	if len(results) == 0 {
		return nil, xerrors.New("There are no versions to fetch")
	}
	return results, nil
}

func fetchFilesFromLocal(version string) (util.FetchResult, error) {
	buf, err := os.ReadFile(fmt.Sprintf("data/oval/rhel/com.redhat.rhsa-RHEL%s.xml", version))
	if err != nil {
		return util.FetchResult{}, err
	}

	result := util.FetchResult{
		Body: buf,
		URL:  fmt.Sprintf("https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL%s.xml.bz2", version),
	}

	return result, nil
}
