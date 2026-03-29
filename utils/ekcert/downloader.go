package ekcert

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/loicsikidi/attest/endorsement"
	"github.com/loicsikidi/attest/internal/utils"
	crlutil "github.com/loicsikidi/attest/internal/utils/crl"
	httputil "github.com/loicsikidi/attest/internal/utils/http"

	"github.com/loicsikidi/sentinel"
)

var ErrDownloaderDisabled = sentinel.BadParameter("downloader is disabled")

const DefaultDownloadTimeout = 2 * time.Second

// httpClient interface is used essentially to mock [http.Client] in tests
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// CRL interface is duplicate here to avoid a reference to an internal package (i.e. crlutil)
type CRL crlutil.CRL

type Downloader interface {
	// DownloadCRL downloads a Certificate Revocation List (CRL) from the specified URL.
	DownloadCRL(ctx context.Context, url *url.URL) (CRL, error)
	// DownloadCRLSigner downloads the signer certificate for a CRL from the specified URL.
	DownloadCRLSigner(ctx context.Context, url *url.URL) (*x509.Certificate, error)
	// DownloadEKCertificate downloads the Endorsement Key (EK) certificate from the specified URL.
	DownloadEKCertificate(ctx context.Context, ekURL *url.URL) (*x509.Certificate, error)
	// SetTimeout sets the timeout for HTTP requests made by the downloader.
	//
	// Note: implementation should ensure that the timeout is applied to all HTTP requests
	// made by the downloader. It's easy doable because each function takes a context.
	SetTimeout(timeout time.Duration)
}

type downloader struct {
	client  httpClient
	timeout time.Duration
}

type intelEKCertResponse struct {
	Pubhash     string `json:"pubhash"`
	Certificate string `json:"certificate"`
}

func newDefaultDownloader() Downloader {
	return &downloader{
		client:  http.DefaultClient,
		timeout: DefaultDownloadTimeout,
	}
}

func (d *downloader) DownloadCRL(ctx context.Context, url *url.URL) (CRL, error) {
	ctx, cancel := utils.WithTimeout(ctx, d.timeout)
	defer cancel()

	crlBytes, err := httputil.HttpGET(ctx, d.client, url.String())
	if err != nil {
		return nil, sentinel.Wrap(err, "failed retrieving CRL from %q", url)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, sentinel.Wrap(err, "failed parsing CRL from %q", url)
	}

	return crlutil.NewCRL(crl)
}

func (d *downloader) DownloadCRLSigner(ctx context.Context, url *url.URL) (*x509.Certificate, error) {
	ctx, cancel := utils.WithTimeout(ctx, d.timeout)
	defer cancel()

	certBytes, err := httputil.HttpGET(ctx, d.client, url.String())
	if err != nil {
		return nil, sentinel.Wrap(err, "failed retrieving certificate from %q", url)
	}

	// RFC 5280 section 4.2.2.1 states that the certificate
	// is expected to be in DER format in HTTP/FTP.
	crl, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, sentinel.Wrap(err, "failed parsing certificate from %q", url)
	}

	return crl, nil
}

// DownloadEKCertificate attempts to download the EK certificate from ekURL.
func (d *downloader) DownloadEKCertificate(ctx context.Context, ekURL *url.URL) (*x509.Certificate, error) {
	ctx, cancel := utils.WithTimeout(ctx, d.timeout)
	defer cancel()

	body, err := httputil.HttpGET(ctx, d.client, ekURL.String())
	if err != nil {
		return nil, sentinel.Wrap(err, "failed retrieving EK certificate from %q", ekURL)
	}

	var ekCert *x509.Certificate
	switch {
	case strings.Contains(ekURL.String(), endorsement.IntelEKCertServiceURL):
		var c intelEKCertResponse
		if err := json.Unmarshal(body, &c); err != nil {
			return nil, sentinel.Wrap(err, "failed decoding EK certificate response")
		}
		cb, err := base64.RawURLEncoding.DecodeString(strings.ReplaceAll(c.Certificate, "%3D", "")) // strip padding; decode raw
		if err != nil {
			return nil, sentinel.Wrap(err)
		}
		ekCert, err = endorsement.ParseEKCertificate(cb)
		if err != nil {
			return nil, sentinel.Wrap(err)
		}
	case strings.Contains(ekURL.String(), endorsement.AmdEKCertServiceURL):
		ekCert, err = endorsement.ParseEKCertificate(body)
		if err != nil {
			return nil, sentinel.Wrap(err)
		}
	// Also see https://learn.microsoft.com/en-us/mem/autopilot/networking-requirements#tpm
	default:
		ekCert, err = endorsement.ParseEKCertificate(body)
		if err != nil {
			return nil, sentinel.Wrap(err)
		}
	}
	return ekCert, nil
}

func (d *downloader) SetTimeout(timeout time.Duration) {
	d.timeout = timeout
}
