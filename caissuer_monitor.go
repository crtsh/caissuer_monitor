/* crt.sh: caissuer_monitor - Authority Info Access CA Issuers Monitor
 * Written by Rob Stradling
 * Copyright (C) 2020 Sectigo Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/lib/pq"
	"github.com/miekg/dns"
	"go.mozilla.org/pkcs7"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type config struct {
	// Common configuration parameters shared by all processors.
	ConnInfo string
	ConnOpen int
	ConnIdle int
	ConnLife duration
	Interval duration
	Batch int
	Concurrent int
	// Processor-specific config.
	HTTPTimeout duration
}

type Work struct {
	c *config
	db *sql.DB
	dns_config *dns.ClientConfig
	timeout time.Duration
	transport http.Transport
	http_client http.Client
	import_cert_statement *sql.Stmt
}

type WorkItem struct {
	ca_id int32
	ca_issuer_url string
	result string
	content_type string
	ca_certificate_ids []int64
	start_time time.Time
}

func checkRedirectURL(req *http.Request, via []*http.Request) error {
	// Fixup incorrectly encoded redirect URLs
	req.URL.RawQuery = strings.Replace(req.URL.RawQuery, " ", "%20", -1)
	return nil
}

// tomlConfig.DefineCustomFlags() and tomlConfig.PrintCustomFlags()
// Specify command-line flags that are specific to this processor.
func (c *config) DefineCustomFlags() {
	flag.DurationVar(&c.HTTPTimeout.Duration, "httptimeout", c.HTTPTimeout.Duration, "HTTP timeout")
}
func (c *config) PrintCustomFlags() string {
	return fmt.Sprintf("httptimeout:%s", c.HTTPTimeout.Duration)
}

func (w *Work) Init(c *config) {
	w.c = c
	w.transport = http.Transport { TLSClientConfig: &tls.Config { InsecureSkipVerify: true } }
	w.http_client = http.Client { CheckRedirect: checkRedirectURL, Timeout: w.timeout, Transport: &w.transport }

	var err error
	w.dns_config, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	checkErr(err)

	w.import_cert_statement, err = w.db.Prepare(`
SELECT import_cert($1)
`)
	checkErr(err)
}

// Work.Begin
// Do any DB stuff that needs to happen before a batch of work.
func (w *Work) Begin(db *sql.DB) {
}

// Work.End
// Do any DB stuff that needs to happen after a batch of work.
func (w *Work) End() {
}

// Work.Exit
// One-time program exit code.
func (w *Work) Exit() {
	w.import_cert_statement.Close()
}

// Work.Prepare()
// Prepare the driving SELECT query.
func (w *Work) SelectQuery(batch_size int) string {
	return fmt.Sprintf(`
SELECT cais.CA_ID, cais.URL
	FROM ca_issuer cais
	WHERE cais.NEXT_CHECK_DUE < now() AT TIME ZONE 'UTC'
		AND cais.IS_ACTIVE
	ORDER BY cais.NEXT_CHECK_DUE
	LIMIT %d
`, batch_size)
}

// WorkItem.Parse()
// Parse one SELECTed row to configure one work item.
func (wi *WorkItem) Parse(rs *sql.Rows) error {
	return rs.Scan(&wi.ca_id, &wi.ca_issuer_url)
}

func (wi *WorkItem) logResult(action string, outcome string) {
	wi.result = outcome
	log.Printf("%v,%v,\"%s\",\"%s\",%d,\"%s\",\"%v\"\n", time.Now().UTC(), time.Now().UTC().Sub(wi.start_time), action, wi.ca_issuer_url, wi.ca_id, outcome, wi.ca_certificate_ids)
}

func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}

// WorkItem.Perform()
// Do the work for one item.
func (wi *WorkItem) Perform(db *sql.DB, w *Work) {
	wi.start_time = time.Now().UTC()

	switch strings.ToLower(strings.Split(wi.ca_issuer_url, ":")[0]) {
		case "http": case "https": break
		default:
			wi.logResult("ERROR", "Protocol not supported")
			return
	}

	req, err := http.NewRequest("GET", wi.ca_issuer_url, nil)
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "crt.sh")
	resp, err := w.http_client.Do(req)
	if err != nil {
		err_string := err.Error()
		if _, ok := err.(net.Error); ok {
			for i := 0; i < len(w.dns_config.Servers); i++ {
				err_string = strings.ReplaceAll(err_string, w.dns_config.Servers[i], "[redacted]")
			}
			if external_ip, eerr := externalIP(); eerr == nil {
				err_string = strings.ReplaceAll(err_string, external_ip, "[redacted]")
			}
		}
		wi.logResult("ERROR", err_string)
		return
	}
	defer resp.Body.Close()

	wi.content_type = resp.Header.Get("Content-Type")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		wi.logResult("ERROR", fmt.Sprintf("%v", err))
		return
	}

	var cert *x509.Certificate

	block, _ := pem.Decode(body)
	if block == nil {
		cert, err = x509.ParseCertificate(body)
		wi.result = "DER X.509"
	} else {
		cert, err = x509.ParseCertificate(block.Bytes)
		wi.result = "PEM X.509"
	}

	if err == nil {				// Certificate decoded successfully.
		var certificate_id int64
		if err = w.import_cert_statement.QueryRow(cert.Raw).Scan(&certificate_id); err != nil {
			wi.result = fmt.Sprintf("%v", err)
		} else {
			wi.ca_certificate_ids = append(wi.ca_certificate_ids, certificate_id)
		}

		wi.logResult("DONE", wi.result)
		return
	}

	var p7 *pkcs7.PKCS7
	var p7err error
	if block == nil {
		p7, p7err = pkcs7.Parse(body)
		wi.result = "DER CMS"
	} else {
		p7, p7err = pkcs7.Parse(block.Bytes)
		wi.result = "PEM CMS"
	}

	if p7err == nil {			// PKCS#7 decoded successfully.
		// TODO: A valid "certs-only" CMS message must have the SignedData content type.
		// A valid "certs-only" CMS message must contain one or more certificates in the "certificates" portion of the signedData.
		if len(p7.Certificates) < 1 {
			wi.logResult("DONE", wi.result + " with no certificates")
			return
		} else {
			var certificate_id int64
			for _, cert := range p7.Certificates {
				if err = w.import_cert_statement.QueryRow(cert.Raw).Scan(&certificate_id); err != nil {
					wi.result = fmt.Sprintf("%v", err)
				} else {
					wi.ca_certificate_ids = append(wi.ca_certificate_ids, certificate_id)
				}
			}
		}
		// A valid "certs-only" CMS message must have no signerInfo.
		if len(p7.Signers) > 0 {
			wi.result += " with signerInfo"
		}
		// TODO: A valid "certs-only" CMS message must have empty encapsulatedContentInfo.

	} else if resp.StatusCode != 200 {
		wi.result = fmt.Sprintf("HTTP %d", resp.StatusCode)
	} else if wi.content_type == "application/pkcs7-mime" {
		wi.result = fmt.Sprintf("%v", p7err)
	} else {
		wi.result = fmt.Sprintf("%v", err)
	}

	wi.logResult("DONE", wi.result)
}

// Work.UpdateStatement()
// Prepare the UPDATE statement to be run after processing each work item.
func (w *Work) UpdateStatement() string {
	return `
UPDATE ca_issuer
	SET LAST_CHECKED=now() AT TIME ZONE 'UTC',
		NEXT_CHECK_DUE=now() AT TIME ZONE 'UTC' + interval '1 hour',
		RESULT=$1,
		CONTENT_TYPE=$2,
		CA_CERTIFICATE_IDS=$3
	WHERE CA_ID=$4
		AND URL=$5
`
}

// WorkItem.Update()
// Update the DB with the results of the work for this item.
func (wi *WorkItem) Update(update_statement *sql.Stmt) (sql.Result, error) {
	return update_statement.Exec(wi.result, wi.content_type, pq.Array(wi.ca_certificate_ids), wi.ca_id, wi.ca_issuer_url)
}
