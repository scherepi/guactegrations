// guactegrations is a Go package that makes integrating with various Hack Club tools easy.
// It provides a number of functions for connecting to and retrieving data from both Hack Club Auth and Hackatime.
// It was made by Guac, initially for his backend work on Glassrib. I hope it finds and serves you well.
package guactegrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A NOTE: this library provides functions for external applications seeking to fetch data from Hackatime's API.
// It is NOT designed for Hackatime clients that want to push heartbeats, and purposefully omits those API endpoints.

// this could change! worth keeping an eye on :)
const HACKATIME_API_BASE = "hackatime.hackclub.com"

type HackatimeManager struct {
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
	AccessToken string // the API access token we use to make requests on behalf of this user
	UserID int64 // the long int id associated with this particular user
	UserEmails []string // an array of at least one email associated with a Hackatime user
	SlackID string // the Slack ID corresponding to a particular user - THIS CAN BE EMPTY
	GithubUsername string // the GitHub username corresponding to a particular user - THIS CAN BE EMPTY 
	TrustFactor HackatimeTrustFactor // can be Red, Yellow, Blue, or Green for different levels of trust
}

// defines the basic parameters of a Hackatime project, as provided by the API
type HackatimeProject struct {
	Name string // the project's name!
	Author string // the author's Hackatime username
	TotalSeconds float64 // the total number of seconds of work on this project tracked with Hackatime
	Languages []string // the languages this project was written in
	RepoURL string // the URL for the GitHub repo this project is associated with
	FirstHeartbeat time.Time // a Time object representing the time and date of the first heartbeat associated with this project
	LastHeartbeat time.Time // Time object representing the time and date of the last heartbeat recorded for this project
	Archived bool // true if the project is archived, false otherwise
}

// Initializes a new HackatimeManager, which contains your app's credentials and 
func InitHackatimeManager(hts, htuid, redirectURI, userDestination string, scopes []string, HTTPClient *http.Client) *HackatimeManager {
	if HTTPClient == nil { HTTPClient = http.DefaultClient }
	return &HackatimeManager{hackatimeSecret: hts, hackatimeUID: htuid, redirectURI: redirectURI, UserDestination: userDestination, scopes: scopes, HTTPClient: HTTPClient};
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

func (htm HackatimeManager) parseAuthResponse(parseCTX context.Context, token_response *http.Response) (newIdentity *HackatimeIdentity, identityError error) {
	// make sure that no matter what, our body closes responsibly
	defer token_response.Body.Close();
	// double check our context is still valid
	if (parseCTX.Err() != nil) { return nil, fmt.Errorf("parse function was handed an invalid context: %w", parseCTX.Err())}
	
	
	if err := parseCTX.Err(); err != nil {
		return nil, fmt.Errorf("context already done before parsing response: %w", err);
	}

	// auto-magically decode JSON into a struct
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
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
		AccessToken: parsed.AccessToken,
		UserID: parsedGet.Id,
		UserEmails: parsedGet.Emails,
		SlackID: parsedGet.Slack,
		GithubUsername: parsedGet.GHUsername,
		TrustFactor: HackatimeTrustFactor(parsedGet.Trust.TrustValue),
	}, nil;
}

// performs an OAuth code exchange with Hackatime, finally returning a Hackatime identity for the user
func (htm HackatimeManager) ExchangeCode(ctx context.Context, auth_code string) (*HackatimeIdentity, error) {
	if (ctx.Err() != nil) { return nil, fmt.Errorf("context provided was invalid: %w", ctx.Err())};
	
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
		return nil, fmt.Errorf("Failed to marshal JSON to POST to Hackatime: %w", marshalErr);
	}

	prepared_req, prepErr := http.NewRequestWithContext(auth_reqctx, "POST", "https://hackatime.hackclub.com/oauth/token", bytes.NewReader(token_req_body));
	if prepErr != nil {
		return nil, fmt.Errorf("Failed to prepare an HTTP request to Hackatime: %w", prepErr);
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

// hits the /api/v1/authenticated/hours endpoint to get the user's total seconds coding for a given range. start_date and end_date are in YYYY-MM-DD format
// requires that your application have the `read` scope.
func (htm HackatimeManager) GetHours(ctx context.Context, identity HackatimeIdentity, start_date, end_date string) (int64, error){
	// check that the context is still valid
	if (ctx.Err() != nil) { return -1, fmt.Errorf("context was invalid: %w", ctx.Err())}
	
	// check that the start_date and end_date are valid
	var start, end time.Time;
	start, timeErr := time.Parse(time.DateOnly, start_date);
	if (timeErr != nil) { return -1, fmt.Errorf("start_date argument is not a valid date in YYYY-MM-DD format: %w", timeErr); }
	end, timeErr = time.Parse(time.DateOnly, end_date);
	if (timeErr != nil) { return -1, fmt.Errorf("end_date argument is not a valid date in YYYY-MM-DD format: %w", timeErr); }
	
	// idiot-proof timerange requested
	if (end.Before(start)) { return -1, fmt.Errorf("end_date %q is before start_date %q", end_date, start_date); }

	u := url.URL{
		Scheme: "https",
		Host: HACKATIME_API_BASE,
		Path: "/api/v1/authenticated/hours",
	}
	queryParams := url.Values{};
	queryParams.Add("start_date", start_date);
	queryParams.Add("end_date", end_date);
	u.RawQuery = queryParams.Encode();
	// quick! ten seconds to prep and send the GET request
	reqCTX, cancel := context.WithTimeout(ctx, time.Second * 10);
	defer cancel()
	getreq, reqErr := http.NewRequestWithContext(reqCTX, http.MethodGet, u.String(), http.NoBody);
	if (reqErr != nil) { return -1, fmt.Errorf("failed to prepare GET request for hours: %w", reqErr); }
	
	// add our OAuth token so we can actually get the data
	getreq.Header.Add("Authorization", "Bearer " + identity.AccessToken);

	hourData, getErr := htm.HTTPClient.Do(getreq);
	if (getErr != nil) { return -1, fmt.Errorf("failed to make GET request for hour data: %w", getErr); }
	defer hourData.Body.Close();
	switch (hourData.StatusCode) {
	case 403:
		return -1, fmt.Errorf("Hackatime gave a 403 - your application doesn't have the right scopes to access hour data.");
	case 401:
		return -1, fmt.Errorf("Hackatime reported a 401 - your OAuth access token is missing or invalid, or your authenticated user is banned.");
	}
	if (hourData.StatusCode != 200) { return -1, fmt.Errorf("Something has gone very wrong - Hackatime gave an improper status code (%d)", hourData.StatusCode)}
	
	var parsed struct {
		TotalSeconds float64 `json:"total_seconds"`
	}
	parseErr := json.NewDecoder(hourData.Body).Decode(&parsed)
	if (parseErr != nil) { return -1, fmt.Errorf("error parsing JSON response from Hackatime: %w", parseErr)}
	return int64(parsed.TotalSeconds), nil;
}
