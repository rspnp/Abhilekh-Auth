package utilities

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/supabase/auth/internal/conf"
)

// GetIPAddress returns the real IP address of the HTTP request.
//
// It prefers single-value headers set by a trusted edge proxy — Cloudflare's
// CF-Connecting-IP, then X-Real-IP — because they carry exactly one
// authoritative client IP. It falls back to the first entry of the
// order-sensitive X-Forwarded-For header (which intermediate proxies append
// to), and finally to the direct connection's RemoteAddr.
func GetIPAddress(r *http.Request) string {
	if r.Header != nil {
		for _, header := range []string{"CF-Connecting-IP", "X-Real-IP"} {
			if v := strings.TrimSpace(r.Header.Get(header)); v != "" {
				if parsed := net.ParseIP(v); parsed != nil {
					return parsed.String()
				}
			}
		}

		xForwardedFor := r.Header.Get("X-Forwarded-For")
		if xForwardedFor != "" {
			ips := strings.Split(xForwardedFor, ",")
			for i := range ips {
				ips[i] = strings.TrimSpace(ips[i])
			}

			for _, ip := range ips {
				if ip != "" {
					parsed := net.ParseIP(ip)
					if parsed == nil {
						continue
					}

					return parsed.String()
				}
			}
		}
	}

	ipPort := r.RemoteAddr
	ip, _, err := net.SplitHostPort(ipPort)
	if err != nil {
		return ipPort
	}

	return ip
}

// GetBodyBytes reads the whole request body properly into a byte array.
func GetBodyBytes(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}

	originalBody := req.Body
	defer SafeClose(originalBody)

	buf, err := io.ReadAll(originalBody)
	if err != nil {
		return nil, err
	}

	req.Body = io.NopCloser(bytes.NewReader(buf))

	return buf, nil
}

func GetReferrer(r *http.Request, config *conf.GlobalConfiguration) string {
	// try get redirect url from query or post data first
	reqref := getRedirectTo(r)
	if IsRedirectURLValid(config, reqref) {
		return reqref
	}

	// instead try referrer header value
	reqref = r.Referer()
	if IsRedirectURLValid(config, reqref) {
		return reqref
	}

	return config.SiteURL
}

func IsRedirectURLValid(config *conf.GlobalConfiguration, redirectURL string) bool {
	if redirectURL == "" {
		return false
	}

	base, berr := url.Parse(config.SiteURL)
	refurl, rerr := url.Parse(redirectURL)

	// As long as the referrer came from the site, we will redirect back there
	if berr == nil && rerr == nil && base.Hostname() == refurl.Hostname() {
		return true
	}

	// For case when user came from mobile app or other permitted resource - redirect back
	for _, pattern := range config.URIAllowListMap {
		if pattern.Match(redirectURL) {
			return true
		}
	}

	return false
}

// getRedirectTo tries extract redirect url from header or from query params
func getRedirectTo(r *http.Request) (reqref string) {
	reqref = r.Header.Get("redirect_to")
	if reqref != "" {
		return
	}

	if err := r.ParseForm(); err == nil {
		reqref = r.Form.Get("redirect_to")
	}

	return
}
