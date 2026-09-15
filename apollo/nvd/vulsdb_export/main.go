// Command vulsdb-nvd-export reads CVE IDs from stdin and emits NDJSON NVD
// enrichment rows from a local vuls2 BoltDB (vuls.db).
//
// Fields include CVSS/CWE/refs plus EPSS, KEV, exploit maturity, and sample CPEs.
//
// Usage:
//
//	echo CVE-2021-44228 | vulsdb-nvd-export -db /var/lib/vuls/vuls.db
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	bolt "go.etcd.io/bbolt"
)

const maxCPEs = 12

// Preferred NVD sources (highest first). Matches Vuls detector preference.
var nvdSourcePreference = []sourceTypes.SourceID{
	sourceTypes.NVDAPICVE,
	sourceTypes.NVDFeedCVEv2,
	sourceTypes.NVDFeedCVEv1,
}

type row struct {
	CveID           string     `json:"cve_id"`
	Description     *string    `json:"description"`
	CvssV2Score     *string    `json:"cvss_v2_score"`
	CvssV2Vector    *string    `json:"cvss_v2_vector"`
	CvssV3Score     *string    `json:"cvss_v3_score"`
	CvssV3Vector    *string    `json:"cvss_v3_vector"`
	CvssV4Score     *string    `json:"cvss_v4_score"`
	CvssV4Vector    *string    `json:"cvss_v4_vector"`
	CWE             *string    `json:"cwe"`
	Refs            []refItem  `json:"refs"`
	EpssScore       *string    `json:"epss_score"`
	EpssPercentile  *string    `json:"epss_percentile"`
	ExploitMaturity *string    `json:"exploit_maturity"`
	ExploitCount    int        `json:"exploit_count"`
	KevListed       bool       `json:"kev_listed"`
	KevDateAdded    *time.Time `json:"kev_date_added"`
	KevDueDate      *time.Time `json:"kev_due_date"`
	KevRansomware   *string    `json:"kev_ransomware"`
	CPEs            []string   `json:"cpes"`
	PublishedAt     *time.Time `json:"published_at"`
	LastModifiedAt  *time.Time `json:"last_modified_at"`
	SourceID        string     `json:"source_id,omitempty"`
	Missing         bool       `json:"missing,omitempty"`
	Error           string     `json:"error,omitempty"`
}

type refItem struct {
	URL    string `json:"url"`
	Source string `json:"source,omitempty"`
}

func main() {
	dbPath := flag.String("db", "/var/lib/vuls/vuls.db", "path to vuls2 BoltDB")
	flag.Parse()

	if err := run(*dbPath, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "vulsdb-nvd-export: %v\n", err)
		os.Exit(1)
	}
}

func run(dbPath string, in io.Reader, out io.Writer) error {
	opts := *bolt.DefaultOptions
	opts.ReadOnly = true

	s, err := (session.Config{
		Type:      "boltdb",
		Path:      dbPath,
		Options:   session.StorageOptions{BoltDB: &opts},
		WithCache: false,
	}).New()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	if err := s.Storage().Open(); err != nil {
		return fmt.Errorf("open %s: %w", dbPath, err)
	}
	defer s.Storage().Close()

	meta, err := s.Storage().GetMetadata()
	if err != nil {
		return fmt.Errorf("metadata: %w", err)
	}
	if meta == nil {
		return errors.New("metadata is nil")
	}
	sv, err := session.SchemaVersion("boltdb")
	if err != nil {
		return err
	}
	if meta.SchemaVersion != sv {
		return fmt.Errorf("schema version mismatch: db=%d tool=%d", meta.SchemaVersion, sv)
	}

	enc := json.NewEncoder(out)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		cveID := strings.TrimSpace(sc.Text())
		if cveID == "" || strings.HasPrefix(cveID, "#") {
			continue
		}
		if err := enc.Encode(lookup(s, cveID)); err != nil {
			return err
		}
	}
	return sc.Err()
}

func lookup(s *session.Session, cveID string) row {
	r := row{CveID: cveID}
	vm, err := s.Storage().GetVulnerability(vulnerabilityContentTypes.VulnerabilityID(cveID))
	if err != nil {
		if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
			r.Missing = true
			return r
		}
		r.Error = err.Error()
		return r
	}

	content, sourceID, ok := pickNVDContent(vm)
	if !ok {
		// Still try EPSS/KEV/CPE even if NVD body missing.
		fillEnrichment(&r, s, cveID, vm, vulnerabilityContentTypes.Content{})
		if r.EpssScore == nil && !r.KevListed && len(r.CPEs) == 0 {
			r.Missing = true
		}
		return r
	}
	r.SourceID = string(sourceID)

	if content.Description != "" {
		d := content.Description
		r.Description = &d
	}
	r.PublishedAt = content.Published
	r.LastModifiedAt = content.Modified

	for _, sev := range content.Severity {
		switch sev.Type {
		case severityTypes.SeverityTypeCVSSv2:
			if sev.CVSSv2 != nil && r.CvssV2Vector == nil {
				r.CvssV2Vector = strPtr(sev.CVSSv2.Vector)
				r.CvssV2Score = scorePtr(sev.CVSSv2.BaseScore)
			}
		case severityTypes.SeverityTypeCVSSv30:
			if sev.CVSSv30 != nil && r.CvssV3Vector == nil {
				r.CvssV3Vector = strPtr(sev.CVSSv30.Vector)
				r.CvssV3Score = scorePtr(sev.CVSSv30.BaseScore)
			}
		case severityTypes.SeverityTypeCVSSv31:
			if sev.CVSSv31 != nil {
				r.CvssV3Vector = strPtr(sev.CVSSv31.Vector)
				r.CvssV3Score = scorePtr(sev.CVSSv31.BaseScore)
			}
		case severityTypes.SeverityTypeCVSSv40:
			if sev.CVSSv40 != nil && r.CvssV4Vector == nil {
				r.CvssV4Vector = strPtr(sev.CVSSv40.Vector)
				r.CvssV4Score = scorePtr(sev.CVSSv40.Score)
			}
		}
	}

	var cwes []string
	seenCWE := map[string]struct{}{}
	for _, c := range content.CWE {
		for _, id := range c.CWE {
			if id == "" {
				continue
			}
			if !strings.HasPrefix(id, "CWE-") {
				id = "CWE-" + id
			}
			if _, ok := seenCWE[id]; ok {
				continue
			}
			seenCWE[id] = struct{}{}
			cwes = append(cwes, id)
		}
	}
	if len(cwes) > 0 {
		joined := strings.Join(cwes, ", ")
		r.CWE = &joined
	}

	for _, rf := range content.References {
		if rf.URL == "" {
			continue
		}
		r.Refs = append(r.Refs, refItem{URL: rf.URL, Source: rf.Source})
	}
	if len(r.Refs) == 0 {
		r.Refs = nil
	}

	fillEnrichment(&r, s, cveID, vm, content)
	return r
}

func fillEnrichment(
	r *row,
	s *session.Session,
	cveID string,
	vm map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability,
	nvdContent vulnerabilityContentTypes.Content,
) {
	// EPSS / KEV / exploit metadata may live on NVD content or sibling sources.
	applyContentEnrichment(r, nvdContent)
	for sid, roots := range vm {
		if sid == sourceTypes.NVDAPICVE || sid == sourceTypes.NVDFeedCVEv2 || sid == sourceTypes.NVDFeedCVEv1 {
			continue
		}
		for _, vulns := range roots {
			for _, v := range vulns {
				applyContentEnrichment(r, v.Content)
			}
		}
	}

	if r.ExploitMaturity == nil {
		r.ExploitMaturity = strPtr(exploitMaturityFromVector(ptrStr(r.CvssV3Vector)))
	}

	r.CPEs = collectCPEs(s, cveID)
	if len(r.CPEs) == 0 {
		r.CPEs = nil
	}
}

func applyContentEnrichment(r *row, c vulnerabilityContentTypes.Content) {
	if c.EPSS != nil && r.EpssScore == nil {
		r.EpssScore = scorePtr(c.EPSS.EPSS)
		if c.EPSS.Percentile != nil {
			r.EpssPercentile = scorePtr(*c.EPSS.Percentile)
		}
	}
	if c.KEV != nil {
		r.KevListed = true
		if r.KevDateAdded == nil && !c.KEV.DateAdded.IsZero() {
			t := c.KEV.DateAdded
			r.KevDateAdded = &t
		}
		if r.KevDueDate == nil && !c.KEV.DueDate.IsZero() {
			t := c.KEV.DueDate
			r.KevDueDate = &t
		}
		if c.KEV.KnownRansomwareCampaignUse != "" {
			cur := ptrStr(r.KevRansomware)
			incoming := c.KEV.KnownRansomwareCampaignUse
			if cur == "" || (strings.EqualFold(incoming, "Known") && !strings.EqualFold(cur, "Known")) {
				r.KevRansomware = strPtr(incoming)
			}
		}
	}
	if len(c.Exploit) > 0 {
		r.ExploitCount += len(c.Exploit)
		if r.ExploitMaturity == nil {
			// Presence of exploit records ⇒ at least PoC-level maturity.
			r.ExploitMaturity = strPtr("Proof-of-Concept")
		}
	}
}

func exploitMaturityFromVector(vector string) string {
	if vector == "" {
		return "Unproven"
	}
	for _, part := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(part, ":")
		if !ok || k != "E" {
			continue
		}
		switch v {
		case "U", "X", "":
			return "Unproven"
		case "P":
			return "Proof-of-Concept"
		case "F":
			return "Functional"
		case "H":
			return "High"
		default:
			return v
		}
	}
	return "Unproven"
}

func collectCPEs(s *session.Session, cveID string) []string {
	data, err := s.GetVulnerabilityDataByVulnerabilityID(
		vulnerabilityContentTypes.VulnerabilityID(cveID),
		dbTypes.Filter{
			Contents: []dbTypes.FilterContentType{
				dbTypes.FilterContentTypeDetections,
			},
			Ecosystems: []ecosystemTypes.Ecosystem{ecosystemTypes.Ecosystem("cpe")},
		},
	)
	if err != nil {
		return nil
	}

	seen := map[string]struct{}{}
	var out []string
	for _, det := range data.Detections {
		if !strings.HasPrefix(string(det.Ecosystem), "cpe") {
			continue
		}
		for _, bySource := range det.Contents {
			for _, conditions := range bySource {
				for _, cond := range conditions {
					walkCriteriaCPEs(cond.Criteria, seen, &out)
					if len(out) >= maxCPEs {
						return out
					}
				}
			}
		}
	}
	return out
}

func walkCriteriaCPEs(c criteriaTypes.Criteria, seen map[string]struct{}, out *[]string) {
	for _, nested := range c.Criterias {
		walkCriteriaCPEs(nested, seen, out)
		if len(*out) >= maxCPEs {
			return
		}
	}
	for _, cr := range c.Criterions {
		if cr.Type != criterionTypes.CriterionTypeCPE || cr.CPE == nil {
			continue
		}
		addCPE(string(cr.CPE.CPE), seen, out)
		for _, m := range cr.CPE.CPEMatches {
			addCPE(string(m), seen, out)
			if len(*out) >= maxCPEs {
				return
			}
		}
		if len(*out) >= maxCPEs {
			return
		}
	}
}

func addCPE(cpe string, seen map[string]struct{}, out *[]string) {
	cpe = strings.TrimSpace(cpe)
	if cpe == "" {
		return
	}
	if _, ok := seen[cpe]; ok {
		return
	}
	seen[cpe] = struct{}{}
	*out = append(*out, cpe)
}

func pickNVDContent(
	vm map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability,
) (vulnerabilityContentTypes.Content, sourceTypes.SourceID, bool) {
	try := func(sid sourceTypes.SourceID) (vulnerabilityContentTypes.Content, bool) {
		roots, ok := vm[sid]
		if !ok {
			return vulnerabilityContentTypes.Content{}, false
		}
		for _, vulns := range roots {
			for _, v := range vulns {
				if v.Content.ID != "" || v.Content.Description != "" || len(v.Content.Severity) > 0 {
					return v.Content, true
				}
			}
		}
		return vulnerabilityContentTypes.Content{}, false
	}

	for _, sid := range nvdSourcePreference {
		if c, ok := try(sid); ok {
			return c, sid, true
		}
	}
	for sid := range vm {
		if !strings.Contains(string(sid), "nvd") {
			continue
		}
		if c, ok := try(sid); ok {
			return c, sid, true
		}
	}
	return vulnerabilityContentTypes.Content{}, "", false
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ptrStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func scorePtr(score float64) *string {
	s := strconv.FormatFloat(score, 'f', -1, 64)
	return &s
}
