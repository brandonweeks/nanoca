package abm

import (
	"io"
	"math"
	"net/http"
	"strconv"
	"time"
)

const (
	// maxRateLimitRetries is how many times a request is retried after a
	// 429.
	maxRateLimitRetries = 3

	// maxRetryAfter is the longest wait after a 429. A longer Retry-After
	// returns the 429 to the caller instead.
	maxRetryAfter = time.Minute
)

// Transport is an http.RoundTripper that authorizes requests with a token
// from Source.
//
// Apple asks clients to get a new token after a 401, so on a 401 it expires
// the token and retries the request once. On a 429 it waits as long as the
// Retry-After header says, or backs off exponentially without one, and
// retries up to 3 times. It returns the 429 instead if the wait is over a
// minute or would pass the request's deadline. A request whose body cannot
// be replayed (GetBody is nil) is not retried.
type Transport struct {
	Source *TokenSource

	// Base is the underlying RoundTripper. If nil, http.DefaultTransport
	// is used.
	Base http.RoundTripper
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	tok, err := t.Source.TokenContext(ctx)
	if err != nil {
		closeBody(req)
		return nil, err
	}

	replayable := req.Body == nil || req.GetBody != nil
	resp, err := t.send(req, req.Body, tok.AccessToken)
	refreshed := false
	for rateLimited := 0; ; {
		if err != nil {
			return nil, err
		}

		switch {
		case resp.StatusCode == http.StatusUnauthorized && !refreshed:
			t.Source.Expire(tok)
			if !replayable {
				return resp, nil
			}
			refreshed = true
			discard(resp)
			if tok, err = t.Source.TokenContext(ctx); err != nil {
				return nil, err
			}

		case resp.StatusCode == http.StatusTooManyRequests && replayable && rateLimited < maxRateLimitRetries:
			wait := retryDelay(resp.Header.Get("Retry-After"), rateLimited, time.Now())
			if wait > maxRetryAfter {
				return resp, nil
			}
			if deadline, ok := ctx.Deadline(); ok && time.Now().Add(wait).After(deadline) {
				return resp, nil
			}
			rateLimited++
			discard(resp)
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}

		default:
			return resp, nil
		}

		var body io.ReadCloser
		if req.GetBody != nil {
			if body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		resp, err = t.send(req, body, tok.AccessToken)
	}
}

// retryDelay returns how long to wait before retrying after a 429. It uses
// the Retry-After header, either delay-seconds or an HTTP date, and falls
// back to 1s, 2s, 4s, ... for the given attempt.
func retryDelay(retryAfter string, attempt int, now time.Time) time.Duration {
	if secs, err := strconv.ParseInt(retryAfter, 10, 64); err == nil && secs >= 0 {
		return time.Duration(min(secs, math.MaxInt64/int64(time.Second))) * time.Second
	}
	if at, err := http.ParseTime(retryAfter); err == nil {
		return max(at.Sub(now), 0)
	}
	return time.Second << attempt
}

func (t *Transport) send(req *http.Request, body io.ReadCloser, accessToken string) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Body = body
	r.Header.Set("Authorization", "Bearer "+accessToken)
	return t.base().RoundTrip(r)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func discard(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
