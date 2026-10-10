package ui

import (
	"context"
	"strconv"
	"strings"
	"time"

	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/submission"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

type Option struct{ Value, Label string }

type Pagination struct {
	Path       string
	Query      string // encoded filters, without a leading "page" or "?"
	Page       int    // current page (>= 1)
	TotalPages int    // total page count (>= 1)
}

func (p Pagination) Href(page int) string {
	q := "page=" + itoa(int64(page))
	if p.Query != "" {
		q = p.Query + "&" + q
	}
	return p.Path + "?" + q
}

func fmtDate(t time.Time) string { return t.Local().Format("02/01/2006") }

func fmtDateTime(t time.Time) string {
	return t.Local().Format("02/01/2006 15:04")
}

type UserRowVM struct {
	IDString    string
	Name        string
	Email       string
	Role        string
	Active      bool
	IsSelf      bool
	TotpEnabled bool
	SiteCount   int64
}

func roleLabel(ctx context.Context, role string) string {
	return T(ctx, "role."+role)
}

type SiteVM struct {
	User   *database.User
	Site   database.GetSiteScopedRow
	Forms  []database.ListFormsBySiteRow
	Owners []database.User // active accounts of the organisation, for transfer (org admin); empty otherwise
	// Read access granted on the site, and the accounts it can be granted to (org admin only).
	Readers   []database.ListSiteReadGrantsRow
	Grantable []database.ListGrantableUsersRow
	CSRF      string
	Flash     string
	ErrMsg    string

	Tokens   []database.ListAPITokensBySiteRow
	APIBase  string // API address (BASE_URL + /api/v1)
	NewToken string // token just created, shown only once
	TokenErr string
}

// Lifetimes offered when creating an API token, in days. 0: no expiry.
var TokenLifetimes = []int{7, 30, 90, 365, 0}

const defaultTokenLifetime = 30

func tokenLifetimeLabel(ctx context.Context, days int) string {
	if days == 0 {
		return T(ctx, "site.tokens.lifetime_never")
	}
	return T(ctx, "site.tokens.lifetime_days", days)
}

// Input as typed, shown back unchanged if validation rejects it.
type FormValues struct {
	Name           string
	Active         bool
	NotifyEmail    bool
	Recipients     string
	IncludeContent bool
	Store          bool
	RetentionDays  string
	Attachments    bool
	Captcha        bool
	RedirectURL    string

	SlackWebhookURL    string
	TeamsWebhookURL    string
	DiscordWebhookURL  string
	TelegramBotToken   string
	TelegramChatID     string
	ChatIncludeContent bool

	NotificationLang string
}

type FormEditVM struct {
	User        *database.User
	IsNew       bool
	SiteID      string
	SiteName    string
	FormID      string // empty when created
	FormName    string
	Values      FormValues
	CSRF        string
	ErrMsg      string
	Flash       string
	MailEnabled bool
	Encrypted   bool // retained submissions are encrypted at rest
	Files       FileLimits
}

// FileLimits: attachment limits of a submission, for display.
type FileLimits struct {
	MaxFiles int
	MaxMB    int64
	// Email size limit, if lower than MaxMB. 0: MaxMB.
	EmailMB int64
	Scanned bool // the instance has files scanned by an antivirus
}

func (vm FormEditVM) action() string {
	if vm.IsNew {
		return "/sites/" + vm.SiteID + "/forms"
	}
	return "/forms/" + vm.FormID + "/settings"
}

type SubmissionRowVM struct {
	ID         string
	CreatedAt  time.Time
	Unread     bool
	Fields     []submission.Field
	Unreadable bool // content that cannot be decrypted (key changed or data altered)
}

const previewFields = 3

func (r SubmissionRowVM) Preview() []submission.Field {
	out := make([]submission.Field, 0, previewFields)
	for _, f := range r.Fields {
		if f.Value == "" {
			continue
		}
		out = append(out, submission.Field{Name: f.Name, Value: truncate(f.Value, 80)})
		if len(out) == previewFields {
			break
		}
	}
	return out
}

// Collapses the text to one line (spaces folded), truncated to max characters.
func truncate(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

type FormVM struct {
	User        *database.User
	Form        database.GetFormScopedRow
	Rows        []SubmissionRowVM
	Total       int64
	Pg          Pagination
	Endpoint    string // public submission URL (BASE_URL + /submit)
	MailEnabled bool
	Files       FileLimits
	CSRF        string
	Flash       string
	// Retained submissions have files: the page offers an archive export.
	HasAttachments bool
	// In bytes. StorageMax of 0 means no quota.
	StorageUsed, StorageMax int64
	// What happens to submissions once the quota is reached. Empty while there is room.
	StorageNotice string
	// CaptchaUnsolved: browser submissions refused for lack of an anti-bot check
	// since the last verified submission.
	CaptchaUnsolved int
}

// HTMLSnippet renders the form to paste on the site. With the anti-bot check, it carries
// the attribute the script recognizes, followed by the script tag.
func HTMLSnippet(ctx context.Context, endpoint, accessKey string, attachments, captcha bool) string {
	enctype, fileInput, marker, script := "", "", "", ""
	if attachments {
		enctype = ` enctype="multipart/form-data"`
		fileInput = `
  <input type="file" name="attachment" multiple>`
	}
	if captcha {
		marker = ` data-naria-captcha`
		script = `

<!-- ` + T(ctx, "form.integration.captcha_comment") + ` -->
<script src="` + instanceURL(endpoint) + `/static/captcha.js" defer></script>`
	}
	return `<form action="` + endpoint + `" method="POST"` + enctype + marker + `>
  <input type="hidden" name="access_key" value="` + accessKey + `">

  <input type="text" name="name" required>
  <input type="email" name="email" required>
  <textarea name="message" required></textarea>` + fileInput + `

  <!-- ` + T(ctx, "form.integration.honeypot_comment") + ` -->
  <input type="checkbox" name="botcheck" style="display:none" tabindex="-1" autocomplete="off">

  <button type="submit">` + T(ctx, "form.integration.submit_label") + `</button>
</form>` + script
}

// Public address of the instance, derived from the submit address (see App.submitURL).
func instanceURL(endpoint string) string {
	return strings.TrimSuffix(endpoint, "/submit")
}

func (vm FormVM) htmlSnippet(ctx context.Context) string {
	return HTMLSnippet(ctx, vm.Endpoint, vm.Form.AccessKey, vm.Form.AcceptAttachments, vm.Form.Captcha)
}

// JavaScript variant: JSON response, no page reload.
func (vm FormVM) jsSnippet() string {
	return `const form = document.querySelector("form");
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await fetch("` + vm.Endpoint + `", {
    method: "POST",
    headers: { Accept: "application/json" },
    body: new FormData(form),
  });
  const { success, message } = await res.json();
  // success: true | false
});`
}

func retentionLabel(ctx context.Context, days int32) string {
	if days == 0 {
		return T(ctx, "form.retention.unlimited")
	}
	return T(ctx, "form.retention.days", days)
}

type SubmissionVM struct {
	User        *database.User
	Sub         database.GetSubmissionScopedRow
	Fields      []submission.Field
	Attachments []AttachmentVM
	Unreadable  bool
	CSRF        string
}

type AttachmentVM struct {
	ID   string
	Name string
	Size int64 // octets
}

func fmtSize(ctx context.Context, n int64) string {
	switch {
	case n < 1<<10:
		return T(ctx, "size.bytes", n)
	case n < 1<<20:
		return T(ctx, "size.kb", n>>10)
	}
	tenths := n * 10 >> 20
	return T(ctx, "size.mb", tenths/10, tenths%10)
}

func formEditTitle(ctx context.Context, vm FormEditVM) string {
	if vm.IsNew {
		return T(ctx, "form.new.title")
	}
	return T(ctx, "form.settings.title")
}

func unreadStyle(unread bool) string {
	if unread {
		return "font-weight:600"
	}
	return "font-weight:400"
}

// Configured channels: a nil pointer means not configured.
func alertChannels(slack, teams, discord, telegram *string) []string {
	var out []string
	for _, c := range []struct {
		name string
		set  bool
	}{{"Slack", slack != nil}, {"Teams", teams != nil}, {"Discord", discord != nil}, {"Telegram", telegram != nil}} {
		if c.set {
			out = append(out, c.name)
		}
	}
	return out
}
