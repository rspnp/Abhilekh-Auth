package provider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// Keycloak
type keycloakProvider struct {
	*oauth2.Config
	Host        string
	UserInfoURL string
}

// discoverOIDC resolves an OIDC provider via the issuer's discovery document.
// go-oidc requires the discovered "issuer" to match the argument exactly; some
// IdPs (e.g. Authentik) advertise the issuer WITH a trailing slash while Keycloak
// does not, so we try the URL as given and then with the slash toggled.
func discoverOIDC(ctx context.Context, issuer string) (*oidc.Provider, error) {
	p, err := oidc.NewProvider(ctx, issuer)
	if err == nil {
		return p, nil
	}
	if strings.HasSuffix(issuer, "/") {
		return oidc.NewProvider(ctx, strings.TrimSuffix(issuer, "/"))
	}
	return oidc.NewProvider(ctx, issuer+"/")
}

type keycloakUser struct {
	Name          string                 `json:"name"`
	Sub           string                 `json:"sub"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	RawClaims     map[string]interface{} `json:"-"`
}

func (u *keycloakUser) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &u.RawClaims); err != nil {
		return err
	}

	// Extract known fields
	if v, ok := u.RawClaims["name"].(string); ok {
		u.Name = v
	}
	if v, ok := u.RawClaims["sub"].(string); ok {
		u.Sub = v
	}
	if v, ok := u.RawClaims["email"].(string); ok {
		u.Email = v
	}
	if v, ok := u.RawClaims["email_verified"].(bool); ok {
		u.EmailVerified = v
	}

	return nil
}

// NewKeycloakProvider creates a Keycloak (or any OIDC-compliant IdP) provider.
//
// Endpoints are resolved via OIDC discovery (the issuer's
// /.well-known/openid-configuration), so this works with non-Keycloak providers
// such as Authentik whose endpoints are not under Keycloak's
// /protocol/openid-connect/* paths. If the issuer does not serve a discovery
// document, we fall back to the legacy Keycloak path layout for backwards
// compatibility with existing Keycloak deployments.
func NewKeycloakProvider(ctx context.Context, ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	// "openid" is required: it marks this as an OIDC request so the IdP issues a
	// token that can read userinfo. Authentik (strict OIDC) returns 403 from
	// /userinfo without it; Keycloak is lenient but openid is still correct.
	oauthScopes := []string{
		"openid",
		"profile",
		"email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	if ext.URL == "" {
		return nil, errors.New("unable to find URL for the Keycloak provider")
	}

	issuer := ext.URL
	host := strings.TrimSuffix(ext.URL, "/")

	// Legacy Keycloak defaults (fallback when discovery is unavailable).
	authURL := host + "/protocol/openid-connect/auth"
	tokenURL := host + "/protocol/openid-connect/token"
	userInfoURL := host + "/protocol/openid-connect/userinfo"

	// Prefer standards-based OIDC discovery.
	if p, err := discoverOIDC(ctx, issuer); err == nil {
		authURL = p.Endpoint().AuthURL
		tokenURL = p.Endpoint().TokenURL
		var meta struct {
			UserInfoURL string `json:"userinfo_endpoint"`
		}
		if err := p.Claims(&meta); err == nil && meta.UserInfoURL != "" {
			userInfoURL = meta.UserInfoURL
		}
	}

	return &keycloakProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		Host:        host,
		UserInfoURL: userInfoURL,
	}, nil
}

func (g keycloakProvider) GetOAuthToken(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return g.Exchange(ctx, code, opts...)
}

func (g keycloakProvider) RequiresPKCE() bool {
	return false
}

func (g keycloakProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u keycloakUser

	if err := makeRequest(ctx, tok, g.Config, g.UserInfoURL, &u); err != nil {
		return nil, err
	}

	customClaims := make(map[string]interface{})
	standardClaims := map[string]bool{
		"name": true, "sub": true, "email": true, "email_verified": true,
	}

	for k, v := range u.RawClaims {
		if !standardClaims[k] {
			customClaims[k] = v
		}
	}

	data := &UserProvidedData{}
	if u.Email != "" {
		data.Emails = []Email{{
			Email:    u.Email,
			Verified: u.EmailVerified,
			Primary:  true,
		}}
	}

	data.Metadata = &Claims{
		Issuer:        g.Host,
		Subject:       u.Sub,
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		CustomClaims:  customClaims,

		// To be deprecated
		FullName:   u.Name,
		ProviderId: u.Sub,
	}

	return data, nil

}
