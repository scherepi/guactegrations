// guactegrations is a Go package that makes integrating with various Hack Club tools easy.
// It provides a number of functions for connecting to and retrieving data from both Hack Club Auth and Hackatime.
// It was made by Guac, initially for his backend work on Glassrib. I hope it finds and serves you well.
package guactegrations

import (
	"context"
	"encoding/json"
	"bytes"
	"time"
	"io"
	"fmt"
	"strings"
	"net"
	"net/http"
	"net/url"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// HCA constants
const HCA_BASE_URL string = "https://auth.hackclub.com"
const HCA_TOKEN_URL string = "https://auth.hackclub.com/oauth/token"
const HCA_AUTH_URL string = "https://auth.hackclub.com/oauth/authorize"

type AuthManager struct {
	hcactx context.Context
	// env variables, these are provided by HCA
	clientID string
	clientSecret string
	callbackURL string // the callback URL to provide for calls to HCA - make sure this is set in the HCA settings as well
	// connections to other components
	HTTPClient *http.Client // provided during init, used for POST requests
}

func InitAuthManager(hcactx context.Context, clientID string, clientSecret string, callbackURL string, HTTPClient *http.Client) *AuthManager {
	return &AuthManager{hcactx: hcactx, clientID: clientID, clientSecret: clientSecret, callbackURL: callbackURL, HTTPClient: HTTPClient}
}

// A quick struct to map to the raw OAuth token response provided by Hack Club Auth
type userAuthIdentity struct {
	accessToken string
	refreshToken string
}

// IDVStatus enum, represents a user's IDV verification status
type IDVStatus int;
const (
	NEEDS_SUBMISSION IDVStatus = iota
	PENDING
	VERIFIED
	INELIGIBLE
)

var idvStatusName = map[IDVStatus]string {
	NEEDS_SUBMISSION: "needs_submission",
	PENDING: "pending",
	VERIFIED: "verified",
	INELIGIBLE: "ineligible",
};

func (idv IDVStatus) String() string {
	return idvStatusName[idv];
}

// represents a user's real-world address as provided by Hack Club Auth. a user can have multiple addresses listed.
type HCAAddress struct {
	Id string `json:"id"`
	FirstName string `json:"first_name"`
	LastName string `json:"last_name"`
	Line1 string `json:"line_1"`
	Line2 string `json:"line_2"`
	City string `json:"city"`
	State string `json:"state"`
	PostalCode string `json:"postal_code"` // initially held as an int but i think string is safer
	Country string `json:"country"`
	PhoneNumber string `json:"phone_number"` // this is already verified!
	Primary bool `json:"primary"` // true if this is the user's primary address
}
// represents a user's Hack Club Auth identity as provided by the /api/v1/me endpoint.
type HCAIdentity struct {
	id string
	ysws_eligible bool
	idv_status IDVStatus
	first_name string
	last_name string
	primary_email string
	slack_id string
	phone_number string
	birthday string
	addresses []HCAAddress
}

// blank struct used only for the purposes of prepping our POST request
type authCode struct {}

// used to automagically decode JSON into a struct we can pull the values from
type hcaTokenResponse struct {
	AccessToken string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// parses an OAuth token response from Hack Club Auth. 
func (am AuthManager) parseAuthResponse(parseCTX context.Context, token_response *http.Response) (newIdentity *userAuthIdentity, identityErr error) {
	defer token_response.Body.Close();

	if err := parseCTX.Err(); err != nil {
		return nil, fmt.Errorf("context already done before parsing HCA response: %w", err);
	}

	if token_response.StatusCode < 200 || token_response.StatusCode > 299 {
		bodyBytes, _ := io.ReadAll(token_response.Body);
		return nil, fmt.Errorf("token exchange returned a non-success status code: %d, body: %s", token_response.StatusCode, string(bodyBytes));
	}

	var parsed hcaTokenResponse
	if err := json.NewDecoder(token_response.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding HCA token response: %w", err);
	}

	if parsed.AccessToken == "" {
		return nil, fmt.Errorf("token exchange succeeded but returned an empty access_token");
	}

	return &userAuthIdentity{
		accessToken: parsed.AccessToken,
		refreshToken: parsed.RefreshToken,
	}, nil;
}

// performs a GET request to an API url with a given access token, returns the raw response
// MAKE SURE TO CLOSE THE RESPONSE WHEN YOU GET IT.
func (am AuthManager) tokenGet(url, access_token string) (*http.Response, error) {
	getCTX, getCancel := context.WithTimeout(am.hcactx, time.Second * 5);
	defer getCancel()

	getReq, getErr := http.NewRequestWithContext(getCTX, "GET", url, http.NoBody)
	if getErr != nil {
		return nil, fmt.Errorf("failed to prep GET request to endpoint; %w", getErr)
	}
	getReq.Header.Set("Authorization", "Bearer " + access_token)
	getResp, respErr := am.HTTPClient.Do(getReq)
	if respErr != nil {
		return nil, fmt.Errorf("error when performing GET request with token: %w", respErr)
	}
	// IMPORTANT: make sure the receiving function calls .Close() otherwise we leak
	return getResp, nil;
}

// tries to get the client IP the most authoritative method first (proxy headers) from a request
func ClientIP(req *http.Request) string {
	if ip := req.Header.Get("X-Real-Ip"); ip != "" {
		return ip
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr // best we can do twin
	}
	return host
}

// Handles auth callbacks we use to get our auth tokens for users from HCA.
func (am AuthManager) AuthCallback(w http.ResponseWriter, req *http.Request) {
	// w is the responsewriter we interact with to respond to an HTTP request, req is a pointer to the request object itself
	// fmt.Fprintf(w, "hello\n") // we can just use standard fmt printf functions to write a response, the ResponseWriter formats everything for us
	parsed_url, err := url.Parse(req.URL.String());
	if err != nil {
		http.Error(w, "Hack Club Auth URL callback failed to parse an incoming URL.", 418);
		return;
	}
	parsed_query, parseErr := url.ParseQuery(parsed_url.RawQuery);

	auth_code := parsed_query.Get("code");
	if parseErr != nil {
		http.Error(w, "Hack Club Auth callback failed to parse the query in an incoming request URL.", 418);
		return;
	}
	// time to prep our POST request:
	authPostContext := context.WithValue(am.hcactx, &authCode{}, auth_code);

	// think fast! ten seconds to send the POST *and* read the response body -
	// one deadline on the request context covers the whole exchange.
	auth_reqctx, authReqCancel := context.WithTimeout(authPostContext, time.Second * 10);
	defer authReqCancel();

	token_req_body, marshalErr := json.Marshal(map[string]any{
		"client_id": am.clientID,
		"client_secret": am.clientSecret,
		"redirect_uri": am.callbackURL,
		"code": auth_code,
		"grant_type": "authorization_code",
	});

	if marshalErr != nil {
		http.Error(w, "Failed to marshal JSON to POST to Hack Club Auth.", http.StatusInternalServerError);
		return;
	}

	prepared_req, prepErr := http.NewRequestWithContext(auth_reqctx, "POST", HCA_TOKEN_URL, bytes.NewReader(token_req_body));
	if prepErr != nil {
		http.Error(w, "Failed to prepare token request to Hack Club Auth.", http.StatusInternalServerError);
		return;
	}
	prepared_req.Header.Set("Content-Type", "application/json");

	token_resp, responseErr := am.HTTPClient.Do(prepared_req);
	if responseErr != nil {
		http.Error(w, "Could not reach Hack Club Auth to exchange the code.", http.StatusBadGateway);
		return;
	}

	identity_tokens, identityError := am.parseAuthResponse(auth_reqctx, token_resp);
	if identityError != nil {
		http.Error(w, "Could not read the token response from Hack Club Auth.", http.StatusBadGateway);
		return;
	}

	hca_identity, err := am.getMe(identity_tokens.accessToken);
	if err != nil {
		http.Error(w, "couldn't get HCA data with returned tokens", http.StatusInternalServerError);
		return;
	}
	
	user_id, err := am.caverna.RegisterNewUser(hca_identity.slack_id, hca_identity.primary_email);
	if err != nil {
		am.connectedLogger.Error("couldn't register new user: " + err.Error())
		http.Error(w, "couldn't register new user", http.StatusInternalServerError)
		return;
	}
	am.caverna.RegisterAuthToken(user_id, identity_tokens.accessToken, identity_tokens.refreshToken);

	session_bytes := make([]byte, 32)
	rand.Read(session_bytes)
	session_token := base64.RawURLEncoding.EncodeToString(session_bytes)
	sum := sha256.Sum256([]byte(session_token))

	sessionCreateErr := am.caverna.RegisterNewSession(user_id, sum, req.UserAgent(), ClientIP(req))
	if sessionCreateErr != nil {
		am.connectedLogger.Error("failed to create new session in the database: " + sessionCreateErr.Error())
		http.Error(w, "failed to establish session in caverna", http.StatusInternalServerError)
	}
	http.SetCookie(w, &http.Cookie{Name: "glassrib-session", Value: session_token, HttpOnly: true})
	http.Redirect(w, req, "glassrib.hackclub.com/dashboard", http.StatusSeeOther)
}

// hits the /api/v1/me endpoint to get the user's identity data and returns it in our HCAIdentity struct
func (am AuthManager) getMe(access_token string) (*HCAIdentity, error) {
	meResp, meErr := am.tokenGet("https://auth.hackclub.com/api/v1/me", access_token)
	if meErr != nil {
		return nil, fmt.Errorf("failed to hit /me endpoint for identity data: %w", meErr)
	}
	defer meResp.Body.Close()
	if meResp.StatusCode < 200 || meResp.StatusCode > 299 {
		bodyBytes, _ := io.ReadAll(meResp.Body)
		return nil, fmt.Errorf("attempt to GET HCA identity data returned a non-success status code: %d", meResp.StatusCode)
	}
	type meResponse struct {
		Id string `json:"id"`
		Eligible bool `json:"ysws_eligible"`
		VerificationStatus string `json:"verification_status"`
		FirstName string `json:"first_name"`
		LastName string `json:"last_name"`
		PrimaryEmail string `json:"primary_email"`
		SlackID string `json:"slack_id"`
		PhoneNumber string `json:"phone_number"`
		Birthday string `json:"birthday"` // TODO: parse
		LegalFirstName string `json:"legal_first_name"`
		LegalLastName string `json:"legal_last_name"`
		Addresses []HCAAddress `json:"addresses"`
	}
	var envelope struct {
		Identity meResponse `json:"identity"`
	}

	if err := json.NewDecoder(meResp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decoding HCA /me response: %w", err)
	}
	parsed := envelope.Identity
	var verificationStatus IDVStatus;
	switch parsed.VerificationStatus {
	case "needs_submission":
		verificationStatus = NEEDS_SUBMISSION
	case "pending":
		verificationStatus = PENDING
	case "verified":
		verificationStatus = VERIFIED
	case "ineligible":
		verificationStatus = INELIGIBLE
	}

	return &HCAIdentity{
		id: parsed.Id,
		ysws_eligible: parsed.Eligible,
		idv_status: verificationStatus,
		first_name: parsed.FirstName,
		last_name: parsed.LastName,
		primary_email: parsed.PrimaryEmail,
		slack_id: parsed.SlackID,
		phone_number: parsed.PhoneNumber,
		birthday: parsed.Birthday,
		addresses: parsed.Addresses,
	}, nil;
}