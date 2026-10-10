package email

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// A whole request (HTML, base64 attachments, JSON) stays under 3 MiB: Graph refuses around 4 MB.
	// Beyond that a draft in the mailbox would be needed, which this sender does not create.
	graphMaxRequest = 3 << 20
	// Attachment weight a Graph email can carry. Base64 leaves about 350 KB for the HTML.
	GraphMaxAttachmentBytes = 2 << 20
	// Above this size the request carries attachments or a very long text, whose weight a visitor decides.
	graphLightBytes = 64 << 10

	// Graph quotas per mailbox: four concurrent requests, 150 MB per five-minute slice, otherwise 429.
	// An abandoned request still counts on Graph's side, hence three slots. Heavy requests get one slot
	// and a limited volume, so light ones always have room.
	// The window is fixed: two consecutive windows stay under 150 MB, hence 70 MiB.
	graphSlots       = 3
	graphHeavySlots  = 2
	graphVolume      = 70 << 20
	graphHeavyVolume = 50 << 20
	graphWindow      = 5 * time.Minute

	// A slow renewal must not hold the lock against other sends.
	graphTokenTimeout = 10 * time.Second
	// Renewed this long before expiry, or at mid-life if the token lives less than twice that.
	graphTokenMargin = 5 * time.Minute
	// After Entra refuses (4xx: expired secret, unknown application), it is not asked again during this
	// delay. An outage or a network error is not remembered.
	graphTokenRetry = 30 * time.Second
	// Pause after a 429: the first applies when Microsoft does not say how long, the second is the cap.
	graphThrottleDefault = 30 * time.Second
	graphThrottleMax     = 10 * time.Minute
	// Exchange caps the subject at 255 characters.
	graphSubjectMax = 255
)

// A sender returns these errors without sending anything when it cannot carry the message as is.
// Once lightened, the message can go out.
var (
	// ErrTooLarge: resending it unchanged would fail the same way.
	ErrTooLarge = errors.New("message trop lourd pour un envoi")
	ErrVolume   = errors.New("volume d'envoi atteint pour cette période")
)

// Graph sends through Microsoft Graph, with the client credentials flow and the Mail.Send permission.
//
// The message goes out via sendMail, without a copy in sent items. Heavier attachments would need a
// draft, hence a write permission and a copy of the submission: they are refused.
type Graph struct {
	// Replaceable in tests, never taken from the configuration. The client does not follow redirects:
	// a 307 or 308 would replay the body, hence the message or the secret.
	Client   *http.Client
	LoginURL string
	APIURL   string

	tenantID, clientID, clientSecret, mailbox string

	slots, heavy chan struct{}
	// A channel rather than sync.Mutex: whoever waits for another's renewal keeps its own deadline.
	refresh chan struct{}

	mu             sync.Mutex
	token          string
	tokenUntil     time.Time
	tokenErr       error
	tokenErrUntil  time.Time
	throttledUntil time.Time
	windowStart    time.Time
	sent           int // bytes sent since windowStart
}

func NewGraph(o Options) *Graph {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// Without this probe, a dead HTTP/2 connection stays in use and each send waits for its timeout for nothing.
	tr.HTTP2 = &http.HTTP2Config{SendPingTimeout: 15 * time.Second, PingTimeout: 10 * time.Second}
	return &Graph{
		Client: &http.Client{
			Transport: tr,
			// The caller's context sets the deadlines; this cap applies to callers that set none.
			Timeout:       2 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		LoginURL: "https://login.microsoftonline.com",
		APIURL:   "https://graph.microsoft.com",

		tenantID: o.GraphTenantID, clientID: o.GraphClientID,
		clientSecret: o.GraphClientSecret, mailbox: o.GraphMailbox,

		slots:   make(chan struct{}, graphSlots),
		heavy:   make(chan struct{}, graphHeavySlots),
		refresh: make(chan struct{}, 1),
	}
}

// Ping requests a token. It proves that the application and its secret are recognized, but neither
// the permission to send nor the existence of the mailbox.
func (g *Graph) Ping(ctx context.Context) error {
	_, err := g.accessToken(ctx)
	return err
}

type graphRecipient struct {
	EmailAddress struct {
		Address string `json:"address"`
	} `json:"emailAddress"`
}

type graphAttachment struct {
	Type         string `json:"@odata.type"`
	Name         string `json:"name"`
	ContentType  string `json:"contentType"`
	ContentBytes []byte `json:"contentBytes"`
}

type graphSendMail struct {
	Message struct {
		Subject string `json:"subject"`
		Body    struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"body"`
		ToRecipients []graphRecipient  `json:"toRecipients"`
		ReplyTo      []graphRecipient  `json:"replyTo,omitempty"`
		Attachments  []graphAttachment `json:"attachments,omitempty"`
	} `json:"message"`
	SaveToSentItems bool `json:"saveToSentItems"`
}

func graphRecipients(addrs ...string) []graphRecipient {
	out := make([]graphRecipient, len(addrs))
	for i, addr := range addrs {
		out[i].EmailAddress.Address = addr
	}
	return out
}

// graphRequest encodes the message for sendMail. If it is too large, it returns ErrTooLarge.
func graphRequest(m Message) ([]byte, error) {
	// Measured before encoding: a refused message does not cost its base64 copy.
	size := len(m.HTML)
	for _, a := range m.Attachments {
		size += base64.StdEncoding.EncodedLen(len(a.Data))
	}
	if size > graphMaxRequest {
		return nil, fmt.Errorf("graph: %w", ErrTooLarge)
	}

	var payload graphSendMail
	payload.Message.Subject = clipRunes(sanitizeHeader(m.Subject), graphSubjectMax)
	payload.Message.Body.ContentType = "HTML"
	payload.Message.Body.Content = m.HTML
	payload.Message.ToRecipients = graphRecipients(m.To...)
	if m.ReplyTo != "" {
		payload.Message.ReplyTo = graphRecipients(m.ReplyTo)
	}
	for _, a := range m.Attachments {
		// An empty file goes out as an empty string: nil would be written as "null".
		data := a.Data
		if data == nil {
			data = []byte{}
		}
		// As with SMTP, the type announced by the visitor is not reused.
		payload.Message.Attachments = append(payload.Message.Attachments, graphAttachment{
			Type: "#microsoft.graph.fileAttachment", Name: a.Name,
			ContentType: "application/octet-stream", ContentBytes: data,
		})
	}
	var body bytes.Buffer
	body.Grow(size + 1<<10)
	enc := json.NewEncoder(&body)
	// encoding/json's HTML escaping writes <, > and & on six bytes: HTML would grow several times its weight.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, fmt.Errorf("graph: composition du message: %w", err)
	}
	if body.Len() > graphMaxRequest {
		return nil, fmt.Errorf("graph: %w", ErrTooLarge)
	}
	return body.Bytes(), nil
}

// Send hands the message to Microsoft. It returns nil only on 202: accepted, not delivered (a later
// bounce comes back as a non-delivery report in the mailbox).
//
// The error quotes neither the secret, nor the token, nor the response body, whose text may name the
// mailbox or a recipient: only the step, the status, the error code and the AADSTS numbers.
func (g *Graph) Send(ctx context.Context, m Message) error {
	body, err := graphRequest(m)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		if wait := g.throttled(); wait > 0 {
			return fmt.Errorf("graph: envoi suspendu encore %d s, à la demande de Microsoft", int(wait.Seconds())+1)
		}
		token, err := g.accessToken(ctx)
		if err != nil {
			return err
		}
		status, detail, retryAfter, err := g.sendMail(ctx, token, body)
		switch {
		case err != nil:
			return err
		case status == http.StatusAccepted:
			return nil
		case status == http.StatusUnauthorized && attempt == 0:
			// Token revoked before its expiry: a new one, and a single retry.
			g.dropToken(token)
			continue
		case status == http.StatusTooManyRequests:
			// Under throttling each call still counts: stop calling.
			g.throttle(retryAfter)
		}
		return fmt.Errorf("graph: envoi refusé, HTTP %d%s", status, detail)
	}
}

// sendMail makes the call and returns the status, the detail of a refusal and the requested pause.
func (g *Graph) sendMail(ctx context.Context, token string, body []byte) (status int, detail, retryAfter string, err error) {
	release, err := g.acquire(ctx, len(body) > graphLightBytes)
	if err != nil {
		return 0, "", "", fmt.Errorf("graph: attente d'un créneau d'envoi: %w", err)
	}
	defer release()
	// Counted when leaving: a send stopped before (slot, pause, token refusal) costs nothing.
	if !g.spend(len(body)) {
		return 0, "", "", fmt.Errorf("graph: %w", ErrVolume)
	}

	target := g.APIURL + "/v1.0/users/" + url.PathEscape(g.mailbox) + "/sendMail"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, "", "", errors.New("graph: adresse d'envoi invalide")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.Client.Do(req)
	if err != nil {
		return 0, "", "", fmt.Errorf("graph: envoi: %w", transportCause(err))
	}
	defer drain(resp.Body)
	if resp.StatusCode == http.StatusAccepted {
		return resp.StatusCode, "", "", nil
	}
	var refusal struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	// An unreadable reply leaves the code empty: the status is enough.
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&refusal)
	return resp.StatusCode, graphErrorDetail(refusal.Error.Code, nil), resp.Header.Get("Retry-After"), nil
}

// acquire takes a send slot, and first a heavy slot for heavy requests. The wait stops with the context.
func (g *Graph) acquire(ctx context.Context, heavy bool) (release func(), err error) {
	if heavy {
		select {
		case g.heavy <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	select {
	case g.slots <- struct{}{}:
	case <-ctx.Done():
		if heavy {
			<-g.heavy
		}
		return nil, ctx.Err()
	}
	return func() {
		<-g.slots
		if heavy {
			<-g.heavy
		}
	}, nil
}

func (g *Graph) spend(n int) bool {
	limit := graphVolume
	if n > graphLightBytes {
		limit = graphHeavyVolume
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if now := time.Now(); now.Sub(g.windowStart) >= graphWindow {
		g.windowStart, g.sent = now, 0
	}
	if g.sent+n > limit {
		return false
	}
	g.sent += n
	return true
}

func (g *Graph) throttled() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	return time.Until(g.throttledUntil)
}

// throttle pauses sends according to Retry-After (in seconds), without shortening a pause in progress.
func (g *Graph) throttle(retryAfter string) {
	pause := graphThrottleDefault
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s > 0 {
		pause = min(time.Duration(s)*time.Second, graphThrottleMax)
	}
	g.mu.Lock()
	if until := time.Now().Add(pause); until.After(g.throttledUntil) {
		g.throttledUntil = until
	}
	g.mu.Unlock()
}

// cachedToken returns the valid token, or the recent refusal from Entra. Empty: one must be requested.
func (g *Graph) cachedToken() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.token != "" && now.Before(g.tokenUntil) {
		return g.token, nil
	}
	if g.tokenErr != nil && now.Before(g.tokenErrUntil) {
		return "", g.tokenErr
	}
	return "", nil
}

// dropToken forgets a token Graph refused, unless another send has already replaced it.
func (g *Graph) dropToken(token string) {
	g.mu.Lock()
	if g.token == token {
		g.token = ""
	}
	g.mu.Unlock()
}

// accessToken returns the access token, requested from Entra if there is no valid one. Concurrent
// sends go one at a time: the token obtained by the first serves the others, and so does its refusal
// by Entra.
func (g *Graph) accessToken(ctx context.Context) (string, error) {
	if token, err := g.cachedToken(); token != "" || err != nil {
		return token, err
	}
	select {
	case g.refresh <- struct{}{}:
	case <-ctx.Done():
		return "", fmt.Errorf("graph: attente du jeton: %w", ctx.Err())
	}
	defer func() { <-g.refresh }()
	if token, err := g.cachedToken(); token != "" || err != nil {
		return token, err
	}

	token, life, refused, err := g.requestToken(ctx)
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		if refused {
			g.tokenErr, g.tokenErrUntil = err, time.Now().Add(graphTokenRetry)
		}
		return "", err
	}
	g.token, g.tokenUntil, g.tokenErr = token, time.Now().Add(life-min(graphTokenMargin, life/2)), nil
	return token, nil
}

// requestToken asks Entra for a token and returns its lifetime. refused tells an application
// refusal (4xx) apart from an outage.
func (g *Graph) requestToken(ctx context.Context) (token string, life time.Duration, refused bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, graphTokenTimeout)
	defer cancel()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	target := g.LoginURL + "/" + url.PathEscape(g.tenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, false, errors.New("graph: adresse du jeton invalide")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.Client.Do(req)
	if err != nil {
		return "", 0, false, fmt.Errorf("graph: demande de jeton: %w", transportCause(err))
	}
	defer drain(resp.Body)
	var answer struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
		ErrorCodes  []int  `json:"error_codes"`
	}
	// The decoding error is not reported: it would quote the response.
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&answer)
	if resp.StatusCode != http.StatusOK {
		refused = resp.StatusCode >= 400 && resp.StatusCode < 500
		return "", 0, refused, fmt.Errorf("graph: jeton refusé, HTTP %d%s", resp.StatusCode, graphErrorDetail(answer.Error, answer.ErrorCodes))
	}
	if decodeErr != nil || answer.AccessToken == "" || answer.ExpiresIn <= 0 {
		return "", 0, false, errors.New("graph: réponse de jeton inexploitable")
	}
	return answer.AccessToken, time.Duration(answer.ExpiresIn) * time.Second, false, nil
}

// drain reads what remains of a response before closing it, so the connection can be reused.
func drain(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64<<10))
	_ = body.Close()
}

// transportCause reduces an HTTP client error to its cause: *url.Error quotes the called address,
// hence the tenant or the mailbox.
func transportCause(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

// graphErrorCode matches the shape of Graph codes ("ErrorAccessDenied") and Entra codes
// ("invalid_client"). Anything outside this shape is not reported.
var graphErrorCode = regexp.MustCompile(`^[A-Za-z0-9_.]{1,80}$`)

func graphErrorDetail(code string, aadsts []int) string {
	var parts []string
	if graphErrorCode.MatchString(code) {
		parts = append(parts, code)
	}
	for _, n := range aadsts {
		parts = append(parts, "AADSTS"+strconv.Itoa(n))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func clipRunes(s string, limit int) string {
	n := 0
	for i := range s {
		if n == limit {
			return s[:i]
		}
		n++
	}
	return s
}
