// guactegrations is a Go package that makes integrating with various Hack Club tools easy.
// It provides a number of functions for connecting to and retrieving data from both Hack Club Auth and Hackatime.
// It was made by Guac, initially for his backend work on Glassrib. I hope it finds and serves you well.
package guactegrations
import (
	"context"
	"net/http"
	"net/url"
	"bytes"
	"fmt"
	"time"
	"strings"
	"encoding/json"
)

const HACKATIME_API_BASE = "hackatime.hackclub.com"

type HackatimeManager struct {
	hackatimeCTX context.Context // the context provided for this manager.
	hackatimeSecret string // our Hackatime application's client secret - this needs to STAY SERVERSIDE.
	hackatimeUID string // our Hackatime application's client ID.
	redirectURI string // the redirect URI provided to Hackatime for authentication callbacks
	scopes []string // a list of API scopes we're requesting access to from the Hackatime API.
	
	UserDestination string // The URL to send users to after a successful Hackatime authentication
	HTTPClient *http.Client // the HTTP client we're using for Hackatime API calls.
}

// An enum corresponding to a Hackatime user's active trust level - can be Red, Yellow, Blue, or Green based on their standing.
type HackatimeTrustFactor int;
const (
	BLUE HackatimeTrustFactor = iota
	RED
	GREEN
	YELLOW
)
var hackatimeTrustFactorName = map[HackatimeTrustFactor]string {
	RED: "Banned",
	YELLOW: "Suspicious",
	BLUE: "Normal", 
	GREEN: "Trusted",
}

func (tf HackatimeTrustFactor) String() string {
	return hackatimeTrustFactorName[tf];
}

// defines the basic parameters of a Hackatime user, as provided by the API
type HackatimeIdentity struct {
	access_token string // the API access token we use to make requests on behalf of this user
	id int64 // the long int id associated with this particular user
	emails []string // an array of at least one email associated with a Hackatime user
	slack_id string // the Slack ID corresponding to a particular user - THIS CAN BE EMPTY
	github_username string // the GitHub username corresponding to a particular user - THIS CAN BE EMPTY 
	trust_factor HackatimeTrustFactor // can be Red, Yellow, Blue, or Green for different levels of trust
}

// defines the basic parameters of a Hackatime project, as provided by the API
type HackatimeProject struct {
	name string // the project's name!
	author string // the author's Hackatime username
	totalSecs float64 // the total number of seconds of work on this project tracked with Hackatime
	languages []string // the languages this project was written in
	repoURL string // the URL for the GitHub repo this project is associated with
	first_heartbeat string // a date string representing the time and date of the first heartbeat associated with this project
	last_heartbeat string // date string representing the time and date of the last heartbeat recorded for this project
	archived bool // true if the project is archived, false otherwise
}

func InitHackatimeManager(htc context.Context, hts, htuid, redirectURI string, HTTPClient *http.Client) *HackatimeManager {
	return &HackatimeManager{hackatimeCTX: htc, hackatimeSecret: hts, hackatimeUID: htuid, redirectURI: redirectURI, HTTPClient: HTTPClient};
}

// constructs the URL we provide a user to get a callback with their auth token
func (htm HackatimeManager) getHackatimeRedirect() string {
	queryParams := url.Values{}
	queryParams.Set("client_id", htm.hackatimeUID)
	queryParams.Set("redirect_uri", htm.redirectURI)
	queryParams.Set("response_type", "code")
	// TODO: implement the 'state' parameter to ensure protection against CSRF attacks
	// set the scopes for our token, separated by spaces
	queryParams.Set("scope", strings.Join(htm.scopes, " "));
	url := url.URL{
		Scheme: "https",
		Host: HACKATIME_API_BASE,
		Path: "/oauth/authorize",
		RawQuery: queryParams.Encode(),
	}
	return url.String();
}


// used to have Go automagically decode JSON into a struct for us
type htTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (htm HackatimeManager) parseAuthResponse(parseCTX context.Context, token_response *http.Response) (newIdentity *HackatimeIdentity, identityError error) {
	defer token_response.Body.Close();
	
	if err := parseCTX.Err(); err != nil {
		return nil, fmt.Errorf("context already done before parsing response: %w", err);
	}

	var parsed htTokenResponse
	if err := json.NewDecoder(token_response.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding HT token response: %w", err);
	}
	
	// okay, OAuth is done, let's hit the /me endpoint to get the user's data from this token
	// 2 seconds max to grab the data from hackatime
	grabCTX, grabClose := context.WithTimeout(parseCTX, time.Second * 2);
	defer grabClose();

	// prep and send our GET request to Hackatime
	grab_req, grabErr := http.NewRequestWithContext(grabCTX, http.MethodGet, "https://hackatime.hackclub.com/api/v1/authenticated/me", http.NoBody)
	if grabErr != nil {
		return nil, fmt.Errorf("error prepping request to grab user's Hackatime data: %w", grabErr);
	}
	grab_req.Header.Set("Authorization", "Bearer " + parsed.AccessToken)
	grab_resp, respErr := htm.HTTPClient.Do(grab_req)
	if respErr != nil {
		return nil, fmt.Errorf("error sending request to grab user's Hackatime data: %w", respErr);
	}

	// send was successful, let's parse the response
	defer grab_resp.Body.Close()
	if grab_resp.StatusCode < 200 || grab_resp.StatusCode > 299 {
		return nil, fmt.Errorf("request to grab user's Hackatime data gave a non-success status code: %d", grab_resp.StatusCode)
	}

	type trustFactorResponse struct {
		TrustLevel string `json:"trust_level"`
		TrustValue int `json:"trust_value"`
	}

	type meResponse struct {
		Id int64 `json:"id"`
		Emails []string `json:"emails"`
		Slack string `json:"slack_id"`
		GHUsername string `json:"github_username"`
		Trust trustFactorResponse `json:"trust_factor"`
	}
	var parsedGet meResponse
	
	if err := json.NewDecoder(grab_resp.Body).Decode(&parsedGet); err != nil {
		return nil, fmt.Errorf("decoding HT identity response: %w", err);
	}

	return &HackatimeIdentity{
		access_token: parsed.AccessToken,
		id: parsedGet.Id,
		emails: parsedGet.Emails,
		slack_id: parsedGet.Slack,
		github_username: parsedGet.GHUsername,
		trust_factor: HackatimeTrustFactor(parsedGet.Trust.TrustValue),
	}, nil;
}

// performs an OAuth code exchange with Hackatime, finally returning a
func (htm HackatimeManager) ExchangeCode(ctx context.Context, auth_code string) (*HackatimeIdentity, error) {
	authPostContext := context.WithValue(ctx, &authCode{}, auth_code);

	auth_reqctx, authReqCancel := context.WithTimeout(authPostContext, time.Second * 10);
	defer authReqCancel();

	token_req_body, marshalErr := json.Marshal(map[string]any{
		"client_id": htm.hackatimeUID,
		"client_secret": htm.hackatimeSecret,
		"code": auth_code,
		"redirect_uri": htm.redirectURI,
		"grant_type": "authorization_code",
	});

	if marshalErr != nil {
		return nil, fmt.Errorf("Failed to marshal JSON to POST to Hackatime");
	}

	prepared_req, prepErr := http.NewRequestWithContext(auth_reqctx, "POST", "https://hackatime.hackclub.com/oauth/token", bytes.NewReader(token_req_body));
	if prepErr != nil {
		return nil, fmt.Errorf("Failed to prepare an HTTP request to Hackatime");
	}

	token_resp, responseErr := htm.HTTPClient.Do(prepared_req);
	if responseErr != nil {
		return nil, fmt.Errorf("Something went wrong trying to authenticate to Hackatime.");
	}

	parseCTX, parseCancel := context.WithTimeout(ctx, 2 * time.Second);
	defer parseCancel()

	parsed_identity, idErr := htm.parseAuthResponse(parseCTX, token_resp)

	if idErr != nil {
		return nil, fmt.Errorf("Error parsing HCA callback");
	}
	return parsed_identity, nil;
}

