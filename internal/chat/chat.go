// Package chat pushes an alert to Slack, Teams and Discord (incoming webhooks) and Telegram (bot API).
//
// A webhook URL comes from the interface and the server is the one calling it: without a guard it
// could probe internal addresses. Only known hosts are called, over HTTPS, without redirects.
package chat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

type Channel string

const (
	Slack   Channel = "slack"
	Teams   Channel = "teams"
	Discord Channel = "discord"
	// Telegram has no incoming webhook: see SendTelegram.
	Telegram Channel = "telegram"
)

// builtinHosts are the official webhook hosts. A leading dot matches subdomains. Microsoft removed
// the Office 365 connectors, so only Workflows webhooks remain.
var builtinHosts = map[Channel][]string{
	Slack:   {"hooks.slack.com"},
	Teams:   {".api.powerplatform.com"},
	Discord: {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"},
}

// builtinPaths is the path shape required on a host that also serves more than webhooks. discord.com
// hosts the whole API: without this rule the instance could post to any address there.
var builtinPaths = map[Channel]*regexp.Regexp{
	Discord: regexp.MustCompile(`^/api(/v\d+)?/webhooks/\d+/[A-Za-z0-9_-]+$`),
}

var (
	ErrInvalidURL     = errors.New("adresse de webhook invalide")
	ErrHostNotAllowed = errors.New("hôte de webhook non autorisé")
)

type Field struct{ Name, Value string }

// Message is an alert, independent of the service receiving it.
type Message struct {
	Title     string
	Context   string
	Note      string
	Fields    []Field // empty = alert without content
	MoreNote  string  // shown when Fields was truncated
	LinkURL   string
	LinkLabel string
}

// These services refuse oversized messages.
const (
	maxFields     = 20
	maxValueRunes = 1000
	maxTotalRunes = 10000
)

type Notifier struct {
	Client *http.Client // must not follow redirects
	// TelegramAPI never comes from user input.
	TelegramAPI string
	extraHosts  []string
}

// New builds a Notifier. extraHosts is added to the official hosts ("chat.example.com", or
// ".example.com" for subdomains): the operator is responsible for them.
func New(extraHosts []string) *Notifier {
	return &Notifier{
		Client: &http.Client{
			Timeout: 10 * time.Second,
			// An allowed host must not redirect the call elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		TelegramAPI: "https://api.telegram.org",
		extraHosts:  extraHosts,
	}
}

// Validate checks that a webhook URL is acceptable for the service. On a nil Notifier, only the
// official hosts pass.
func (n *Notifier) Validate(ch Channel, raw string) error {
	_, err := n.parse(ch, raw)
	return err
}

func (n *Notifier) parse(ch Channel, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || len(raw) > 2000 {
		return nil, ErrInvalidURL
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if n != nil && matchHost(n.extraHosts, host) {
		return u, nil
	}
	if !matchHost(builtinHosts[ch], host) || (u.Port() != "" && u.Port() != "443") {
		return nil, ErrHostNotAllowed
	}
	// On the path as it will be sent: an encoded "/" must not get past the rule.
	if re := builtinPaths[ch]; re != nil && !re.MatchString(u.EscapedPath()) {
		return nil, ErrInvalidURL
	}
	return u, nil
}

func matchHost(allowed []string, host string) bool {
	for _, a := range allowed {
		if strings.HasPrefix(a, ".") {
			if strings.HasSuffix(host, a) && len(host) > len(a) {
				return true
			}
			continue
		}
		if host == a {
			return true
		}
	}
	return false
}

// Send posts the alert to the webhook, revalidated on each send. The error never contains the
// address, which is a secret.
func (n *Notifier) Send(ctx context.Context, ch Channel, rawURL string, m Message) error {
	if n == nil {
		return errors.New("alertes de discussion désactivées")
	}
	u, err := n.parse(ch, rawURL)
	if err != nil {
		return err
	}
	var payload any
	switch ch {
	case Slack:
		payload = slackPayload(m)
	case Teams:
		payload = teamsPayload(m)
	case Discord:
		payload = discordPayload(m)
	default:
		return fmt.Errorf("canal inconnu %q", ch)
	}
	return n.post(ctx, ch, u.String(), payload, nil)
}

// post sends the message as JSON. detail, optional, extracts from a failed response the reason to
// attach to the error. It must not reveal any secret.
func (n *Notifier) post(ctx context.Context, ch Channel, target string, payload any, detail func([]byte) string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return ErrInvalidURL
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.Client.Do(req)
	if err != nil {
		// *url.Error includes the called URL in its message: only keep the cause.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("%s: %w", ch, err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if detail != nil {
			if d := detail(answer); d != "" {
				return fmt.Errorf("%s: HTTP %d (%s)", ch, resp.StatusCode, d)
			}
		}
		return fmt.Errorf("%s: HTTP %d", ch, resp.StatusCode)
	}
	return nil
}

// fit brings the content back within alert bounds.
func fit(fields []Field) (out []Field, truncated bool) {
	total := 0
	for _, f := range fields {
		if len(out) == maxFields || total >= maxTotalRunes {
			return out, true
		}
		value := []rune(f.Value)
		if room := min(maxValueRunes, maxTotalRunes-total); len(value) > room {
			value = append(value[:room], '…')
			truncated = true
		}
		total += len(value)
		out = append(out, Field{Name: f.Name, Value: string(value)})
	}
	return out, truncated
}

// orDash: these services refuse an empty text block.
func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// The name comes from the visitor like the value, but must not crowd it out.
const fieldNameMax = 256

// markup describes a service's formatting: Markdown for Discord, HTML for Telegram. Lengths are
// counted in UTF-16 (an emoji counts as two), the strictest count.
type markup struct {
	clean  func(string) string // neutralizes free text before cutting
	cost   func(rune) int      // UTF-16 units of a character once escaped
	escape func(string) string // applied last, so its output is never cut
	bold   func(string) string
}

// text prepares free text bounded to limit units. Cutting happens before escaping, so an escaped
// sequence is never split.
func (k markup) text(s string, limit int) (string, bool) {
	s, cut := clipCost(k.clean(s), limit, k.cost)
	return k.escape(s), cut
}

// body assembles the note, fields, truncation notice and link (already formatted), separated by a
// blank line and kept under limit units.
func (k markup) body(m Message, link string, limit int) string {
	const sep = "\n\n"
	var parts []string
	if m.Note != "" {
		parts = append(parts, k.escape(k.clean(m.Note)))
	}
	more := k.escape(k.clean(m.MoreNote))
	// The link and the truncation notice are written by the application: their room is reserved
	// before the visitor's content is placed.
	room := limit - len16(strings.Join(parts, sep)) - len16(sep+more) - len16(sep+link)
	fields, truncated := fit(m.Fields)
	for _, f := range fields {
		name, cut := k.text(orDash(f.Name), fieldNameMax)
		truncated = truncated || cut
		label := k.bold(name) + "\n"
		// No room for the name and the start of a value.
		if room < len16(sep+label)+2 {
			truncated = true
			break
		}
		value, cut := k.text(orDash(f.Value), room-len16(sep+label))
		truncated = truncated || cut
		parts = append(parts, label+value)
		room -= len16(sep + label + value)
	}
	if truncated && more != "" {
		parts = append(parts, more)
	}
	if link != "" {
		parts = append(parts, link)
	}
	return strings.Join(parts, sep)
}

// clipCost cuts s under limit units without splitting a character.
func clipCost(s string, limit int, cost func(rune) int) (string, bool) {
	total := 0
	for _, r := range s {
		total += cost(r)
	}
	if total <= limit {
		return s, false
	}
	if limit <= 0 {
		return "", true
	}
	n := 0
	for i, r := range s {
		if n += cost(r); n > limit-1 { // one unit kept for the ellipsis
			return s[:i] + "…", true
		}
	}
	return s, false
}

func clip16(s string, limit int) (string, bool) { return clipCost(s, limit, utf16.RuneLen) }

func len16(s string) (n int) {
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// slackEscape neutralizes characters Slack interprets in mrkdwn text (links, <!channel>).
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackBlock struct {
	Type   string      `json:"type"`
	Text   *slackText  `json:"text,omitempty"`
	Fields []slackText `json:"fields,omitempty"`
}

type slackMessage struct {
	Text   string       `json:"text"` // fallback: notification, clients without blocks
	Blocks []slackBlock `json:"blocks"`
}

// slackPayload composes the Slack message. Visitor content goes in plain_text, where Slack interprets
// nothing: a submission can neither notify @channel nor disguise a link.
func slackPayload(m Message) slackMessage {
	head := "*" + slackEscape.Replace(m.Title) + "*"
	if m.Context != "" {
		head += "\n" + slackEscape.Replace(m.Context)
	}
	blocks := []slackBlock{{Type: "section", Text: &slackText{Type: "mrkdwn", Text: head}}}
	if m.Note != "" {
		blocks = append(blocks, slackBlock{Type: "section", Text: &slackText{Type: "plain_text", Text: m.Note}})
	}
	fields, truncated := fit(m.Fields)
	for _, f := range fields {
		blocks = append(blocks, slackBlock{Type: "section", Fields: []slackText{
			{Type: "plain_text", Text: orDash(f.Name)},
			{Type: "plain_text", Text: orDash(f.Value)},
		}})
	}
	if truncated && m.MoreNote != "" {
		blocks = append(blocks, slackBlock{Type: "section", Text: &slackText{Type: "plain_text", Text: m.MoreNote}})
	}
	if m.LinkURL != "" {
		link := "<" + slackEscape.Replace(m.LinkURL) + "|" + slackEscape.Replace(orDash(m.LinkLabel)) + ">"
		blocks = append(blocks, slackBlock{Type: "section", Text: &slackText{Type: "mrkdwn", Text: link}})
	}
	fallback := m.Title
	if m.Context != "" {
		fallback = "[" + m.Context + "] " + m.Title
	}
	return slackMessage{Text: fallback, Blocks: blocks}
}

// teamsText prepares free text for an adaptive card, which interprets a subset of Markdown. A
// zero-width space between "]" and "(" breaks the link, so a visitor cannot show a label pointing
// elsewhere. Line breaks are doubled, the only form Teams renders.
func teamsText(s string) string {
	s = strings.ReplaceAll(s, "](", "]\u200b(")
	return strings.ReplaceAll(orDash(s), "\n", "\n\n")
}

type teamsElement struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	Wrap     bool   `json:"wrap"`
	Weight   string `json:"weight,omitempty"`
	Size     string `json:"size,omitempty"`
	Spacing  string `json:"spacing,omitempty"`
	IsSubtle bool   `json:"isSubtle,omitempty"`
}

type teamsAction struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

type teamsCard struct {
	Schema  string         `json:"$schema"`
	Type    string         `json:"type"`
	Version string         `json:"version"`
	Body    []teamsElement `json:"body"`
	Actions []teamsAction  `json:"actions,omitempty"`
}

type teamsAttachment struct {
	ContentType string    `json:"contentType"`
	Content     teamsCard `json:"content"`
}

type teamsMessage struct {
	Type        string            `json:"type"`
	Attachments []teamsAttachment `json:"attachments"`
}

// teamsPayload composes the card expected by a Workflows webhook (trigger "When a Teams webhook
// request is received").
func teamsPayload(m Message) teamsMessage {
	body := []teamsElement{{Type: "TextBlock", Text: teamsText(m.Title), Wrap: true, Weight: "Bolder", Size: "Medium"}}
	if m.Context != "" {
		body = append(body, teamsElement{Type: "TextBlock", Text: teamsText(m.Context), Wrap: true, Spacing: "None", IsSubtle: true})
	}
	if m.Note != "" {
		body = append(body, teamsElement{Type: "TextBlock", Text: teamsText(m.Note), Wrap: true})
	}
	fields, truncated := fit(m.Fields)
	for _, f := range fields {
		body = append(body,
			teamsElement{Type: "TextBlock", Text: teamsText(f.Name), Wrap: true, Size: "Small", IsSubtle: true, Spacing: "Medium"},
			teamsElement{Type: "TextBlock", Text: teamsText(f.Value), Wrap: true, Spacing: "None"},
		)
	}
	if truncated && m.MoreNote != "" {
		body = append(body, teamsElement{Type: "TextBlock", Text: teamsText(m.MoreNote), Wrap: true, IsSubtle: true, Spacing: "Medium"})
	}
	card := teamsCard{
		Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
		Type:    "AdaptiveCard",
		Version: "1.4",
		Body:    body,
	}
	if m.LinkURL != "" {
		card.Actions = []teamsAction{{Type: "Action.OpenUrl", Title: orDash(m.LinkLabel), URL: m.LinkURL}}
	}
	return teamsMessage{
		Type:        "message",
		Attachments: []teamsAttachment{{ContentType: "application/vnd.microsoft.card.adaptive", Content: card}},
	}
}

// Discord limits in UTF-16 units: beyond them Discord refuses the message.
const (
	discordContentMax     = 2000
	discordDescriptionMax = 4096
)

// discordText neutralizes, with a zero-width space, "](" (misleading link) and "<" (mentions,
// emojis, timestamps) in free text. Formatting is still interpreted.
var discordText = strings.NewReplacer("](", "]\u200b(", "<", "<\u200b").Replace

var discordMarkup = markup{
	clean:  discordText,
	cost:   utf16.RuneLen,
	escape: func(s string) string { return s },
	bold:   func(s string) string { return "**" + s + "**" },
}

type discordEmbed struct {
	Description string `json:"description"`
}

type discordAllowedMentions struct {
	Parse []string `json:"parse"`
}

type discordMessage struct {
	Content         string                 `json:"content"`
	Embeds          []discordEmbed         `json:"embeds,omitempty"`
	AllowedMentions discordAllowedMentions `json:"allowed_mentions"`
}

// discordPayload composes the Discord message. The title goes in content, which triggers the
// notification; the rest goes in an embed. An empty allowed_mentions blocks every mention.
func discordPayload(m Message) discordMessage {
	k := discordMarkup
	// Title and context are bounded before bolding, so a cut cannot drop the closing "**".
	title, _ := k.text(m.Title, discordContentMax/2-4)
	head := k.bold(title)
	if m.Context != "" {
		context, _ := k.text(m.Context, discordContentMax/2-1)
		head += "\n" + context
	}
	msg := discordMessage{Content: head, AllowedMentions: discordAllowedMentions{Parse: []string{}}}

	link := ""
	if m.LinkURL != "" {
		link = "[" + discordText(orDash(m.LinkLabel)) + "](" + m.LinkURL + ")"
	}
	if body := k.body(m, link, discordDescriptionMax); body != "" {
		msg.Embeds = []discordEmbed{{Description: body}}
	}
	return msg
}

// Telegram counts the text without its tags: counting them too leaves a margin.
const (
	telegramTextMax = 4096
	telegramHeadMax = 500
)

var (
	ErrTelegramToken = errors.New("jeton de bot Telegram invalide")
	ErrTelegramChat  = errors.New("identifiant de discussion Telegram invalide")

	telegramToken = regexp.MustCompile(`^\d{1,20}:[A-Za-z0-9_-]{20,100}$`)
	// A public channel name is 5 to 32 characters.
	telegramChat = regexp.MustCompile(`^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
)

// ValidateTelegram checks the shape of the token and the chat ID. The token goes into the called
// URL path: its strict shape prevents pointing at anything other than a send.
func ValidateTelegram(token, chatID string) error {
	if !telegramToken.MatchString(token) {
		return ErrTelegramToken
	}
	if !telegramChat.MatchString(chatID) {
		return ErrTelegramChat
	}
	return nil
}

// telegramClean neutralizes @mentions, which would notify the named person. An "@" preceded by an
// ASCII letter or digit belongs to an email address and stays intact so it can be copied.
// Addresses, commands and hashtags stay clickable: their label is their destination.
func telegramClean(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}
	var b strings.Builder
	prev := ' '
	for _, r := range s {
		b.WriteRune(r)
		if r == '@' && !isASCIIAlnum(prev) {
			b.WriteRune('\u200b')
		}
		prev = r
	}
	return b.String()
}

func isASCIIAlnum(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z'
}

// telegramMarkup: Telegram receives HTML where only the application's tags exist. Escaped text can
// neither be formatted nor create a link.
var telegramMarkup = markup{
	clean: telegramClean,
	cost: func(r rune) int {
		switch r {
		case '&':
			return len("&amp;")
		case '<', '>':
			return len("&lt;")
		}
		return utf16.RuneLen(r)
	},
	escape: strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace,
	bold:   func(s string) string { return "<b>" + s + "</b>" },
}

type telegramPreview struct {
	IsDisabled bool `json:"is_disabled"`
}

type telegramMessage struct {
	ChatID             string          `json:"chat_id"`
	Text               string          `json:"text"`
	ParseMode          string          `json:"parse_mode"`
	LinkPreviewOptions telegramPreview `json:"link_preview_options"`
}

// telegramPayload composes the Telegram message. Link previews are disabled: otherwise Telegram
// would fetch every address the visitor wrote.
func telegramPayload(chatID string, m Message) telegramMessage {
	k := telegramMarkup
	title, _ := k.text(orDash(m.Title), telegramHeadMax)
	head := k.bold(title)
	if m.Context != "" {
		context, _ := k.text(m.Context, telegramHeadMax)
		head += "\n" + context
	}
	link := ""
	if m.LinkURL != "" {
		label, _ := k.text(orDash(m.LinkLabel), telegramHeadMax)
		link = `<a href="` + html.EscapeString(m.LinkURL) + `">` + label + `</a>`
	}
	const sep = "\n\n"
	text := head
	if body := k.body(m, link, telegramTextMax-len16(head+sep)); body != "" {
		text += sep + body
	}
	return telegramMessage{
		ChatID: chatID, Text: text, ParseMode: "HTML",
		LinkPreviewOptions: telegramPreview{IsDisabled: true},
	}
}

// SendTelegram posts the alert as the bot whose token is given, revalidated on each send. The error
// never contains the token, but carries Telegram's explanation ("chat not found").
func (n *Notifier) SendTelegram(ctx context.Context, token, chatID string, m Message) error {
	if n == nil {
		return errors.New("alertes de discussion désactivées")
	}
	if err := ValidateTelegram(token, chatID); err != nil {
		return err
	}
	target := n.TelegramAPI + "/bot" + token + "/sendMessage"
	return n.post(ctx, Telegram, target, telegramPayload(chatID, m), func(answer []byte) string {
		var r struct {
			Description string `json:"description"`
		}
		if json.Unmarshal(answer, &r) != nil {
			return ""
		}
		// Telegram may quote the token in its reply: its secret part, after the ":", is masked.
		secret := token[strings.IndexByte(token, ':')+1:]
		d, _ := clip16(strings.ReplaceAll(r.Description, secret, "…"), 200)
		return d
	})
}
