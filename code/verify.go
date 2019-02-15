package code

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	log "github.com/Sirupsen/logrus"
	"time"
	"bufio"
	"github.com/jmoiron/jsonq"
	"github.com/zmap/zlint"
	"regexp"
	"github.com/zmap/zcrypto/x509"
	"encoding/base64"
	"runtime"
	"strconv"
)

/**
 * USAGE: ./verify <path> <csv-out> <nlines>
 *
 * with path    = path of the json snapshot
 *      csv-out = path of the created csv file
 */
func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	log.SetLevel(log.DebugLevel)
	if len(os.Args) != 4 {
		usage()
		return
	}
	filePath := os.Args[1]
	csvPath := os.Args[2]
	nlines, err := strconv.Atoi(os.Args[3])
	if err != nil || nlines < 1 {
		log.Fatalf("Invalid integer %s: %s", os.Args[3], err.Error())
		return
	}
	log.Infof("Processing %s, Write to %s, Write packets of %d lines", filePath, csvPath, nlines)
	csv, err := os.Create(csvPath)
	if err != nil {
		log.Fatalf("Unable to create file %s: %s", filePath, err.Error())
		return
	}
	defer csv.Close()
	start(filePath, csv, nlines)
}

func start(filePath string, csvFile *os.File, nlines int) {
	low, err := time.Parse(time.RFC3339, "2017-07-23T00:00:00Z")
	if err != nil {
		log.Fatalf("Unable to parse timestamp: %s", err.Error())
		return
	}
	up, err := time.Parse(time.RFC3339, "2017-07-23T23:59:59Z")
	if err != nil {
		log.Fatalf("Unable to parse timestamp: %s", err.Error())
		return
	}
	var ins = []string{} /* use in-memory buffer, we have plenty of RAM */
	var linec = 0
	var i = 0
	const maxCapacity = 46 * 1000 * 1000
	ins = append(ins, "fingerprint,errors_present,warnings_present,fatals_present,notices_present,issuing_certificate_url,issuer_org,organizationalunit,country,domaincomponent,emailaddress,givenname,surname,serialnumber,organization,added_at,is_ca,valid_start,valid_end,e_dnsname_not_valid_tld,e_ext_authority_key_identifier_missing,e_dnsname_bad_character_in_label,e_ext_san_missing,e_subject_common_name_not_from_san,e_ext_san_uniform_resource_identifier_present,w_ext_subject_key_identifier_missing_sub_cert,w_ext_key_usage_not_critical,w_ext_cert_policy_explicit_text_not_utf8,w_ext_cert_policy_contains_noticeref,w_sub_cert_aia_does_not_contain_issuing_ca_url,w_sub_cert_eku_extra_values,e_ext_san_rfc822_name_present,updated_at\n")
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Cannot open file: %s", filePath)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)
	for scanner.Scan() {
		i++
		line := scanner.Bytes()
		if len(line) == 0 {
			if err != nil {
				log.Errorf("Failed to read line: %s", err.Error())
			}
		}
		data := map[string]interface{}{}
		dec := json.NewDecoder(strings.NewReader(string(line)))
		dec.Decode(&data)
		jq := jsonq.NewQuery(data)
		raw, err := jq.String("raw")
		if err != nil {
			log.Errorf("%d unable to parse raw: %s", i, err.Error())
			continue
		}
		addedAt, err := jq.String("metadata", "added_at")
		if err != nil {
			log.Errorf("%d unable to parse added_at: %s", i, err.Error())
			continue
		}
		updatedAt, err := jq.String("metadata", "updated_at")
		if err != nil {
			log.Errorf("%d unable to parse updated_at: %s", i, err.Error())
			continue
		}
		ts, err := time.Parse(time.RFC3339, strings.Replace(addedAt, " ", "T", 1)+"Z")
		if err != nil {
			log.Errorf("%d unable to parse date: %s", i, err.Error())
			continue
		}
		if ts.After(up) {
			continue
		}
		asn1Data, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			log.Errorf("%d unable to parse base64: %s", i, err.Error())
			continue
		}
		c, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			parseStatus, _ := jq.String("metadata", "parse_status")
			if parseStatus == "fail" {
				continue
			}
			log.Errorf("%d unable to parse certificate: %s", i, err.Error())
			continue
		}
		if inside(c.NotBefore, c.NotAfter, low, up) == false {
			continue
		}
		zLintOverview := zlint.LintCertificate(c)
		zLintResult := zLintOverview.Results
		ins = append(ins, fmt.Sprintf("%s,%t,%t,%t,%t,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%t,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			c.FingerprintSHA256.Hex(),
			zLintOverview.ErrorsPresent,
			zLintOverview.WarningsPresent,
			zLintOverview.FatalsPresent,
			zLintOverview.NoticesPresent,
			f(strings.Join(c.IssuingCertificateURL,"")),
			f(strings.Join(c.Issuer.Organization, "")),
			f(strings.Join(c.Issuer.OrganizationalUnit, "")),
			f(strings.Join(c.Issuer.Country, "")),
			f(strings.Join(c.Issuer.DomainComponent, "")),
			f(strings.Join(c.Issuer.EmailAddress, "")),
			f(strings.Join(c.Issuer.GivenName, "")),
			f(strings.Join(c.Issuer.Surname, "")),
			f(c.Issuer.SerialNumber),
			f(c.Issuer.CommonName),
			addedAt,
			c.IsCA,
			c.NotBefore.Format(time.RFC3339),
			c.NotAfter.Format(time.RFC3339),
			f(zLintResult["e_dnsname_not_valid_tld"].Status.String()),
			f(zLintResult["e_ext_authority_key_identifier_missing"].Status.String()),
			f(zLintResult["e_dnsname_bad_character_in_label"].Status.String()),
			f(zLintResult["e_ext_san_missing"].Status.String()),
			f(zLintResult["e_subject_common_name_not_from_san"].Status.String()),
			f(zLintResult["e_ext_san_uniform_resource_identifier_present"].Status.String()),
			f(zLintResult["w_ext_subject_key_identifier_missing_sub_cert"].Status.String()),
			f(zLintResult["w_ext_key_usage_not_critical"].Status.String()),
			f(zLintResult["w_ext_cert_policy_explicit_text_not_utf8"].Status.String()),
			f(zLintResult["w_ext_cert_policy_contains_noticeref"].Status.String()),
			f(zLintResult["w_sub_cert_aia_does_not_contain_issuing_ca_url"].Status.String()),
			f(zLintResult["w_sub_cert_eku_extra_values"].Status.String()),
			f(zLintResult["e_ext_san_rfc822_name_present"].Status.String()),
			updatedAt))
		linec++
		if linec%nlines == 0 {
			err = insert(ins, csvFile)
			if err != nil {
				log.Infof("%d/%d unable to insert: %s", linec, i, err.Error())
			} else {
				ins = []string{}
			}
		}
	}
	/* write the rest */
	err = insert(ins, csvFile)
	if err != nil {
		log.Infof("%d/%d unable to insert: %s", linec, i, err.Error())
	} else {
		ins = []string{}
	}

	log.Infof("Processed %d/%d entries", linec, i)
}

func insert(slice []string, csv *os.File) error {
	w := bufio.NewWriter(csv)
	n, err := w.WriteString(strings.Join(slice, ""))
	if err != nil {
		log.Errorf("Error with insert: %s", err.Error())
		return err
	}
	w.Flush()
	log.Debugf("Wrote %d bytes", n)
	return nil
}

func f(input string) string {
	r, err := regexp.Compile("[^a-zA-Z0-9.-_ ]+")
	if err != nil {
		log.Fatal(err)
	}
	return r.ReplaceAllString(input, "")
}

func inside(start time.Time, end time.Time, low time.Time, up time.Time) bool {
	if end.Before(low) {
		return false
	}
	if start.After(up) {
		return false
	}
	return true
}

func usage() {
	log.Infof("USAGE: ./verify <json-in> <csv-out> <nlines>\n\n" +
		"json-in:\tjson-snapshot from censys" +
		"csv-out:\tcsv-table output file\n" +
		"nlines: \tnumber of lines the application should batch-write, must integer > 0 (depending on your RAM)\n")
}
