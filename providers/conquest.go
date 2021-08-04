package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	// "github.com/bitly/go-simplejson"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// ConquestProvider represents an Conquest based Identity Provider
type ConquestProvider struct {
	*ProviderData
	Tenant string
}

var _ Provider = (*ConquestProvider)(nil)

const (
	conquestProviderName = "Conquest"
	conquestDefaultScope = "openid"
)

var (
	// Default Login URL for Conquest.
	// Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/authorize.
	conquestDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "services-dev.conquest-solutions.com.au",
		Path:   "/identity/connect/authorize",
	}

	// Default Redeem URL for Conquest.
	// Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/token.
	conquestDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "services-dev.conquest-solutions.com.au",
		Path:   "/identity/connect/token",
	}

	// Default Profile URL for Conquest.
	// Pre-parsed URL of https://graph.microsoft.com/v1.0/me.
	conquestDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "services-dev.conquest-solutions.com.au",
		Path:   "/identity/connect/userinfo",
	}

	// Default ProtectedResource URL for Conquest.
	// Pre-parsed URL of https://graph.microsoft.com.
	conquestDefaultProtectResourceURL = &url.URL{
		Scheme: "https",
		Host:   "graph.microsoft.com",
	}
)

// NewConquestProvider initiates a new ConquestProvider
func NewConquestProvider(p *ProviderData) *ConquestProvider {
	p.setProviderDefaults(providerDefaults{
		name:        conquestProviderName,
		loginURL:    conquestDefaultLoginURL,
		redeemURL:   conquestDefaultRedeemURL,
		profileURL:  conquestDefaultProfileURL,
		validateURL: nil,
		scope:       conquestDefaultScope,
	})

	if p.ProtectedResource == nil || p.ProtectedResource.String() == "" {
		p.ProtectedResource = conquestDefaultProtectResourceURL
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}

	return &ConquestProvider{
		ProviderData: p,
		Tenant:       "common",
	}
}

// Configure defaults the ConquestProvider configuration options
func (p *ConquestProvider) Configure(tenant string) {
	if tenant == "" || tenant == "common" {
		// tenant is empty or default, remain on the default "common" tenant
		return
	}

	// Specific tennant specified, override the Login and RedeemURLs
	p.Tenant = tenant
	overrideTenantURL(p.LoginURL, conquestDefaultLoginURL, tenant, "authorize")
	overrideTenantURL(p.RedeemURL, conquestDefaultRedeemURL, tenant, "token")
}

// func overrideTenantURL(current, defaultURL *url.URL, tenant, path string) {
// 	if current == nil || current.String() == "" || current.String() == defaultURL.String() {
// 		*current = url.URL{
// 			Scheme: "https",
// 			Host:   "login.microsoftonline.com",
// 			Path:   "/" + tenant + "/oauth2/" + path}
// 	}
// }

func (p *ConquestProvider) GetLoginURL(redirectURI, state, _ string) string {
	extraParams := url.Values{}
	a := *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("response_type", "code")
	params.Set("client_id", p.ClientID)
	params.Set("scope", p.Scope)
	params.Set("state", state)
	params.Set("redirect_uri", redirectURI)
	for n, p := range extraParams {
		for _, v := range p {
			params.Add(n, v)
		}
	}
	a.RawQuery = params.Encode()
	return a.String()
}



// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *ConquestProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	params, err := p.prepareRedeem(redirectURL, code)
	if err != nil {
		return nil, err
	}
	
	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	session := &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		RefreshToken: jsonResponse.RefreshToken,
	}
	session.CreatedAtNow()
	session.SetExpiresOn(time.Unix(jsonResponse.ExpiresOn, 0))

	email, err := p.verifyTokenAndExtractEmail(ctx, session.IDToken)

	// https://github.com/oauth2-proxy/oauth2-proxy/pull/914#issuecomment-782285814
	// https://github.com/ConquestAD/conquest-activedirectory-library-for-java/issues/117
	// due to above issues, id_token may not be signed by AAD
	// in that case, we will fallback to access token
	if err == nil && email != "" {
		session.Email = email
	} else {
		logger.Printf("unable to get email claim from id_token: %v", err)
	}

	if session.Email == "" {
		email, err = p.verifyTokenAndExtractEmail(ctx, session.AccessToken)
		if err == nil && email != "" {
			session.Email = email
		} else {
			logger.Printf("unable to get email claim from access token: %v", err)
		}
	}

	return session, nil
}

// EnrichSession finds the email to enrich the session state
func (p *ConquestProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if s.Email != "" {
		return nil
	}

	email, err := p.getEmailFromProfileAPI(ctx, s.AccessToken)
	if err != nil {
		return fmt.Errorf("unable to get email address: %v", err)
	}
	if email == "" {
		return errors.New("unable to get email address")
	}
	s.Email = email

	return nil
}

func (p *ConquestProvider) prepareRedeem(redirectURL, code string) (url.Values, error) {
	params := url.Values{}
	if code == "" {
		return params, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return params, err
	}
	
	params.Set("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("response_type", "authorization_code")
	// if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
	// 	params.Add("resource", p.ProtectedResource.String())
	// }
	return params, nil
}

// verifyTokenAndExtractEmail tries to extract email claim from either id_token or access token
// when oidc verifier is configured
func (p *ConquestProvider) verifyTokenAndExtractEmail(ctx context.Context, token string) (string, error) {
	email := ""

	if token != "" && p.Verifier != nil {
		token, err := p.Verifier.Verify(ctx, token)
		// due to issues mentioned above, id_token may not be signed by AAD
		if err == nil {
			claims, err := p.getClaims(token)
			if err == nil {
				email = claims.Email
			} else {
				logger.Printf("unable to get claims from token: %v", err)
			}
		} else {
			logger.Printf("unable to verify token: %v", err)
		}
	}

	return email, nil
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *ConquestProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	return true, nil
}

func (p *ConquestProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("response_type", "authorization_token")

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return err
	}

	s.AccessToken = jsonResponse.AccessToken
	s.IDToken = jsonResponse.IDToken
	s.RefreshToken = jsonResponse.RefreshToken

	s.CreatedAtNow()
	s.SetExpiresOn(time.Unix(jsonResponse.ExpiresOn, 0))

	email, err := p.verifyTokenAndExtractEmail(ctx, s.IDToken)

	// https://github.com/oauth2-proxy/oauth2-proxy/pull/914#issuecomment-782285814
	// https://github.com/ConquestAD/conquest-activedirectory-library-for-java/issues/117
	// due to above issues, id_token may not be signed by AAD
	// in that case, we will fallback to access token
	if err == nil && email != "" {
		s.Email = email
	} else {
		logger.Printf("unable to get email claim from id_token: %v", err)
	}

	if s.Email == "" {
		email, err = p.verifyTokenAndExtractEmail(ctx, s.AccessToken)
		if err == nil && email != "" {
			s.Email = email
		} else {
			logger.Printf("unable to get email claim from access token: %v", err)
		}
	}

	return nil
}

func makeConquestHeader(accessToken string) http.Header {
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, nil)
}

// func getEmailFromJSON(json *simplejson.Json) (string, error) {
// 	var email string
// 	var err error

// 	email, err = json.Get("mail").String()

// 	if err != nil || email == "" {
// 		otherMails, otherMailsErr := json.Get("otherMails").Array()
// 		if len(otherMails) > 0 {
// 			email = otherMails[0].(string)
// 		}
// 		err = otherMailsErr
// 	}

// 	if err != nil || email == "" {
// 		email, err = json.Get("userPrincipalName").String()
// 		if err != nil {
// 			logger.Errorf("unable to find userPrincipalName: %s", err)
// 			return "", err
// 		}
// 	}

// 	return email, err
// }

func (p *ConquestProvider) getEmailFromProfileAPI(ctx context.Context, accessToken string) (string, error) {
	if accessToken == "" {
		return "", errors.New("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeConquestHeader(accessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return "", err
	}

	return getEmailFromJSON(json)
}

// ValidateSession validates the AccessToken
func (p *ConquestProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeConquestHeader(s.AccessToken))
}
