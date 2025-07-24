package http

import (
	"crypto/tls"
	"net/http"
	"time"

	"fapictl/pkg/logger"
)

type Client struct {
	httpClient *http.Client
}

type ClientOptions struct {
	Timeout   time.Duration
	MTLSCert  string
	MTLSKey   string
	UserAgent string
	Logger    *logger.Logger
}

func NewClient(opts ClientOptions) (*Client, error) {
	var transport http.RoundTripper = &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// Configure mutual TLS if certificates are provided
	if opts.MTLSCert != "" && opts.MTLSKey != "" {
		cert, err := tls.LoadX509KeyPair(opts.MTLSCert, opts.MTLSKey)
		if err != nil {
			return nil, err
		}
		transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	// Wrap with logging transport if logger is provided
	if opts.Logger != nil {
		transport = NewLoggingTransport(transport, opts.Logger)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = "fapictl/1.0"
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return &Client{
		httpClient: client,
	}, nil
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

func (c *Client) Get(url string) (*http.Response, error) {
	return c.httpClient.Get(url)
}

func (c *Client) Post(url, contentType string, body interface{}) (*http.Response, error) {
	// Implementation will be added based on specific needs
	return nil, nil
}

// HTTPClient returns the underlying http.Client for testing purposes
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
