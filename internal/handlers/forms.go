package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/justinas/nosurf"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/chat"
	"gitlab.com/detag_inno/naria/internal/crypto"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/i18n"
	"gitlab.com/detag_inno/naria/internal/submission"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

const (
	// defaultRetentionDays is the retention period offered at creation.
	defaultRetentionDays = 90
	// maxRetentionDays is the upper bound of the retention period (10 years).
	maxRetentionDays = 3650
	// maxRecipients is the number of recipients of a form.
	maxRecipients = 10
)

// formFor loads the form "{id}" within the user's scope.
// Out of scope or missing, it is the same 404. It writes the response itself on failure.
func (a *App) formFor(w http.ResponseWriter, r *http.Request) (database.GetFormScopedRow, bool) {
	u := web.UserFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, tr(r, "form.err.not_found"), http.StatusNotFound)
		return database.GetFormScopedRow{}, false
	}
	isAdmin, viewer := scope(u)
	form, err := a.Q.GetFormScoped(r.Context(), database.GetFormScopedParams{ID: id, IsAdmin: isAdmin, ViewerID: viewer})
	if err != nil {
		http.Error(w, tr(r, "form.err.not_found"), http.StatusNotFound)
		return database.GetFormScopedRow{}, false
	}
	return form, true
}

// formSettings is the validated input of a form.
type formSettings struct {
	Name           string
	Active         bool
	NotifyEmail    bool
	Recipients     []string
	IncludeContent bool
	Store          bool
	RetentionDays  int32
	Attachments    bool
	Captcha        bool
	RedirectURL    *string

	NotificationLang string

	// Webhook addresses in clear text (validated); empty means the channel is not configured.
	SlackURL   string
	TeamsURL   string
	DiscordURL string
	// Telegram bot token and chat ID, set
	// together or not at all.
	TelegramToken      string
	TelegramChatID     string
	ChatIncludeContent bool
}

// readFormSettings reads the settings form and always returns the submitted values,
// so the page can be shown again on error. lang is used when the input does not carry
// the notification language: the form's own, so that a request without this field keeps it.
func (a *App) readFormSettings(r *http.Request, siteDomains []string, lang string) (ui.FormValues, formSettings, string) {
	v := ui.FormValues{
		Name:           strings.TrimSpace(r.FormValue("name")),
		Active:         r.FormValue("active") != "",
		NotifyEmail:    r.FormValue("notify_email") != "",
		Recipients:     strings.TrimSpace(r.FormValue("recipients")),
		IncludeContent: r.FormValue("email_include_content") != "",
		Store:          r.FormValue("store_submissions") != "",
		RetentionDays:  strings.TrimSpace(r.FormValue("retention_days")),
		Attachments:    r.FormValue("accept_attachments") != "",
		Captcha:        r.FormValue("captcha") != "",
		RedirectURL:    strings.TrimSpace(r.FormValue("redirect_url")),

		SlackWebhookURL:    strings.TrimSpace(r.FormValue("slack_webhook_url")),
		TeamsWebhookURL:    strings.TrimSpace(r.FormValue("teams_webhook_url")),
		DiscordWebhookURL:  strings.TrimSpace(r.FormValue("discord_webhook_url")),
		TelegramBotToken:   strings.TrimSpace(r.FormValue("telegram_bot_token")),
		TelegramChatID:     strings.TrimSpace(r.FormValue("telegram_chat_id")),
		ChatIncludeContent: r.FormValue("chat_include_content") != "",

		NotificationLang: strings.TrimSpace(r.FormValue("notification_lang")),
	}
	if v.NotificationLang == "" {
		v.NotificationLang = lang
	}
	s, errMsg := a.validateFormSettings(r, v, siteDomains)
	return v, s, errMsg
}

// validateFormSettings checks an input coming from the settings page or the API.
func (a *App) validateFormSettings(r *http.Request, v ui.FormValues, siteDomains []string) (formSettings, string) {
	s := formSettings{
		Name: v.Name, Active: v.Active, NotifyEmail: v.NotifyEmail, Store: v.Store, IncludeContent: v.IncludeContent,
		Attachments: v.Attachments, Captcha: v.Captcha,
		SlackURL: v.SlackWebhookURL, TeamsURL: v.TeamsWebhookURL, DiscordURL: v.DiscordWebhookURL,
		ChatIncludeContent: v.ChatIncludeContent,
		TelegramToken:      v.TelegramBotToken, TelegramChatID: v.TelegramChatID,
		NotificationLang: v.NotificationLang,
	}

	if s.Name == "" || len(s.Name) > 120 {
		return s, tr(r, "form.err.name_required")
	}
	if !i18n.Supported(s.NotificationLang) {
		return s, tr(r, "form.err.notification_lang")
	}
	if !s.NotifyEmail && !s.Store {
		return s, tr(r, "form.err.no_destination")
	}

	recipients := []string{}
	for _, tok := range strings.FieldsFunc(v.Recipients, func(c rune) bool {
		return c == ',' || c == ';' || c == ' ' || c == '\n' || c == '\r' || c == '\t'
	}) {
		addr, ok := submission.ValidEmail(tok)
		if !ok {
			return s, tr(r, "form.err.recipient_invalid", tok)
		}
		recipients = append(recipients, auth.NormalizeEmail(addr))
	}
	recipients = dedupeNonEmpty(recipients)
	if len(recipients) > maxRecipients {
		return s, tr(r, "form.err.too_many_recipients", maxRecipients)
	}
	if s.NotifyEmail && len(recipients) == 0 {
		return s, tr(r, "form.err.recipients_required")
	}
	s.Recipients = recipients

	// An email without content points to the interface, which implies storage.
	if !s.Store {
		s.IncludeContent = true
	}

	s.RetentionDays = defaultRetentionDays
	if v.RetentionDays != "" {
		n, err := strconv.ParseInt(v.RetentionDays, 10, 32)
		if err != nil || n < 0 || n > maxRetentionDays {
			return s, tr(r, "form.err.retention_invalid", maxRetentionDays)
		}
		s.RetentionDays = int32(n)
	}

	if v.RedirectURL != "" {
		u, err := url.Parse(v.RedirectURL)
		if err != nil || len(v.RedirectURL) > 500 || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return s, tr(r, "form.err.redirect_invalid")
		}
		if !submission.HostAllowed(siteDomains, u.Hostname()) {
			return s, tr(r, "form.err.redirect_domain")
		}
		s.RedirectURL = &v.RedirectURL
	}

	// The server will call these addresses: they are only accepted on the
	// hosts of the relevant service (see chat.Notifier.Validate).
	if s.SlackURL != "" && a.Chat.Validate(chat.Slack, s.SlackURL) != nil {
		return s, tr(r, "form.err.slack_url")
	}
	if s.TeamsURL != "" && a.Chat.Validate(chat.Teams, s.TeamsURL) != nil {
		return s, tr(r, "form.err.teams_url")
	}
	if s.DiscordURL != "" && a.Chat.Validate(chat.Discord, s.DiscordURL) != nil {
		return s, tr(r, "form.err.discord_url")
	}
	if msg := telegramError(r, s.TelegramToken, s.TelegramChatID); msg != "" {
		return s, msg
	}
	return s, ""
}

// telegramError returns the refusal message for a Telegram setting, or "" if it is
// acceptable. The token and the chat ID go together.
func telegramError(r *http.Request, token, chatID string) string {
	if token == "" && chatID == "" {
		return ""
	}
	if token == "" || chatID == "" {
		return tr(r, "form.err.telegram_pair")
	}
	switch err := chat.ValidateTelegram(token, chatID); {
	case errors.Is(err, chat.ErrTelegramToken):
		return tr(r, "form.err.telegram_token")
	case err != nil:
		return tr(r, "form.err.telegram_chat")
	}
	return ""
}

// sealSecret encrypts a webhook address or a token. An empty value yields nil.
func sealSecret(c *crypto.Cipher, plain string) (*string, error) {
	if plain == "" {
		return nil, nil
	}
	enc, err := c.Encrypt(plain)
	if err != nil {
		return nil, err
	}
	return &enc, nil
}

// openSecret decrypts a stored secret. If it cannot be read (key changed), it counts as "not
// configured" and the incident is logged.
func openSecret(c *crypto.Cipher, stored *string, formID uuid.UUID) string {
	if stored == nil || *stored == "" {
		return ""
	}
	plain, err := c.Decrypt(*stored)
	if err != nil {
		log.Printf("ERROR webhook: secret d'alerte illisible formulaire=%s: %v", formID, err)
		return ""
	}
	return plain
}

// sealedWebhooks holds a form's encrypted secrets. nil means the channel is not configured.
type sealedWebhooks struct{ Slack, Teams, Discord, TelegramToken *string }

func (a *App) sealWebhooks(s formSettings) (out sealedWebhooks, err error) {
	if out.Slack, err = sealSecret(a.WebhookCrypto, s.SlackURL); err != nil {
		return sealedWebhooks{}, err
	}
	if out.Teams, err = sealSecret(a.WebhookCrypto, s.TeamsURL); err != nil {
		return sealedWebhooks{}, err
	}
	if out.Discord, err = sealSecret(a.WebhookCrypto, s.DiscordURL); err != nil {
		return sealedWebhooks{}, err
	}
	if out.TelegramToken, err = sealSecret(a.BotTokenCrypto, s.TelegramToken); err != nil {
		return sealedWebhooks{}, err
	}
	return out, nil
}

func (a *App) NewForm(w http.ResponseWriter, r *http.Request) {
	site, ok := a.siteFor(w, r)
	if !ok {
		return
	}
	u := web.UserFrom(r.Context())
	a.renderNewForm(w, r, site, ui.FormValues{
		Active: true, NotifyEmail: a.Mailer != nil, Recipients: u.Email,
		IncludeContent: true, Store: true, RetentionDays: strconv.Itoa(defaultRetentionDays),
		NotificationLang: ui.Lang(r.Context()),
	}, "")
}

func (a *App) renderNewForm(w http.ResponseWriter, r *http.Request, site database.GetSiteScopedRow, v ui.FormValues, errMsg string) {
	renderPage(w, r, ui.FormEditPage(ui.FormEditVM{
		User: web.UserFrom(r.Context()), IsNew: true,
		SiteID: site.ID.String(), SiteName: site.Name,
		Values: v, CSRF: nosurf.Token(r), ErrMsg: errMsg,
		MailEnabled: a.Mailer != nil, Encrypted: a.SubmissionCrypto.Enabled(),
		Files: a.fileLimits(),
	}))
}

func (a *App) CreateForm(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	site, ok := a.siteFor(w, r)
	if !ok {
		return
	}
	v, s, errMsg := a.readFormSettings(r, site.Domains, string(i18n.DefaultLocale))
	if errMsg != "" {
		w.WriteHeader(http.StatusBadRequest)
		a.renderNewForm(w, r, site, v, errMsg)
		return
	}
	form, err := a.createForm(r, u.ID, site.ID, s, uuid.Nil)
	if err != nil {
		log.Printf("ERROR formulaire: création site=%s: %v", site.ID, err)
		a.renderNewForm(w, r, site, v, tr(r, "form.err.create_failed"))
		return
	}
	web.Flash(a.Sessions, r, tr(r, "form.flash.created"))
	http.Redirect(w, r, "/forms/"+form.ID.String(), http.StatusSeeOther)
}

// createForm stores a validated input with a new access key, and records it
// in the audit log under actor. tokenID is uuid.Nil when called from the UI.
func (a *App) createForm(r *http.Request, actor, siteID uuid.UUID, s formSettings, tokenID uuid.UUID) (database.Form, error) {
	key, err := auth.GenerateAccessKey()
	if err != nil {
		return database.Form{}, err
	}
	hooks, err := a.sealWebhooks(s)
	if err != nil {
		return database.Form{}, err
	}
	form, err := a.Q.CreateForm(r.Context(), database.CreateFormParams{
		SiteID: siteID, Name: s.Name, AccessKey: key,
		NotifyEmail: s.NotifyEmail, Recipients: s.Recipients, EmailIncludeContent: s.IncludeContent,
		StoreSubmissions: s.Store, RetentionDays: s.RetentionDays, RedirectUrl: s.RedirectURL,
		SlackWebhookUrl: hooks.Slack, TeamsWebhookUrl: hooks.Teams, DiscordWebhookUrl: hooks.Discord,
		ChatIncludeContent: s.ChatIncludeContent,
		TelegramBotToken:   hooks.TelegramToken, TelegramChatID: nilIfEmpty(s.TelegramChatID),
		AcceptAttachments: s.Attachments, Captcha: s.Captcha, NotificationLang: s.NotificationLang,
	})
	if err != nil {
		return database.Form{}, err
	}
	meta := a.channelChanges(database.GetFormScopedRow{}, s)
	meta["name"], meta["site"], meta["ip"] = s.Name, siteID.String(), web.ClientIP(r)
	meta["chat_content"] = strconv.FormatBool(s.ChatIncludeContent)
	if tokenID != uuid.Nil {
		meta["token"] = tokenID.String()
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(actor),
		Action:   auditFormCreated,
		Entity:   auditEntityForm,
		EntityID: refUUID(form.ID),
		Meta:     meta,
	})
	return form, nil
}

func (a *App) FormSettings(w http.ResponseWriter, r *http.Request) {
	form, ok := a.formFor(w, r)
	if !ok {
		return
	}
	a.renderFormSettings(w, r, form, ui.FormValues{
		Name: form.Name, Active: form.Active, NotifyEmail: form.NotifyEmail,
		Recipients: strings.Join(form.Recipients, ", "), IncludeContent: form.EmailIncludeContent,
		Store: form.StoreSubmissions, RetentionDays: strconv.Itoa(int(form.RetentionDays)),
		Attachments:        form.AcceptAttachments,
		Captcha:            form.Captcha,
		RedirectURL:        deref(form.RedirectUrl),
		SlackWebhookURL:    openSecret(a.WebhookCrypto, form.SlackWebhookUrl, form.ID),
		TeamsWebhookURL:    openSecret(a.WebhookCrypto, form.TeamsWebhookUrl, form.ID),
		DiscordWebhookURL:  openSecret(a.WebhookCrypto, form.DiscordWebhookUrl, form.ID),
		TelegramBotToken:   openSecret(a.BotTokenCrypto, form.TelegramBotToken, form.ID),
		TelegramChatID:     deref(form.TelegramChatID),
		ChatIncludeContent: form.ChatIncludeContent,
		NotificationLang:   form.NotificationLang,
	}, "", "")
}

// renderFormSettings renders the settings page. Without a notice, the session's flash
// message is shown.
func (a *App) renderFormSettings(w http.ResponseWriter, r *http.Request, form database.GetFormScopedRow, v ui.FormValues, errMsg, notice string) {
	if notice == "" {
		notice = web.PopFlash(a.Sessions, r)
	}
	renderPage(w, r, ui.FormEditPage(ui.FormEditVM{
		User:   web.UserFrom(r.Context()),
		SiteID: form.SiteID.String(), SiteName: form.SiteName,
		FormID: form.ID.String(), FormName: form.Name,
		Values: v, CSRF: nosurf.Token(r), ErrMsg: errMsg, Flash: notice,
		MailEnabled: a.Mailer != nil, Encrypted: a.SubmissionCrypto.Enabled(),
		Files: a.fileLimits(),
	}))
}

func (a *App) UpdateForm(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	form, ok := a.formFor(w, r)
	if !ok {
		return
	}
	v, s, errMsg := a.readFormSettings(r, form.SiteDomains, form.NotificationLang)
	if errMsg != "" {
		w.WriteHeader(http.StatusBadRequest)
		a.renderFormSettings(w, r, form, v, errMsg, "")
		return
	}
	hooks, err := a.sealWebhooks(s)
	if err != nil {
		http.Error(w, tr(r, "common.err.internal"), http.StatusInternalServerError)
		return
	}
	if err := a.Q.UpdateForm(r.Context(), database.UpdateFormParams{
		ID: form.ID, Name: s.Name, Active: s.Active,
		NotifyEmail: s.NotifyEmail, Recipients: s.Recipients, EmailIncludeContent: s.IncludeContent,
		StoreSubmissions: s.Store, RetentionDays: s.RetentionDays, RedirectUrl: s.RedirectURL,
		SlackWebhookUrl: hooks.Slack, TeamsWebhookUrl: hooks.Teams, DiscordWebhookUrl: hooks.Discord,
		ChatIncludeContent: s.ChatIncludeContent,
		TelegramBotToken:   hooks.TelegramToken, TelegramChatID: nilIfEmpty(s.TelegramChatID),
		AcceptAttachments: s.Attachments, Captcha: s.Captcha, NotificationLang: s.NotificationLang,
	}); err != nil {
		a.renderFormSettings(w, r, form, v, tr(r, "common.err.update"), "")
		return
	}
	if meta := a.formAuditMeta(form, s); meta != nil {
		meta["ip"] = web.ClientIP(r)
		a.audit(r.Context(), auditEntry{
			ActorID:  refUUID(u.ID),
			Action:   auditFormUpdated,
			Entity:   auditEntityForm,
			EntityID: refUUID(form.ID),
			Meta:     meta,
		})
	}
	flash := "form.flash.updated"
	if s.Captcha && !form.Captcha {
		flash = "form.flash.captcha_on"
	}
	web.Flash(a.Sessions, r, tr(r, flash))
	http.Redirect(w, r, "/forms/"+form.ID.String()+"/settings", http.StatusSeeOther)
}

// channelChanges names the alert channels that an input adds, removes or replaces,
// for the audit. Only states are recorded, never an address, a token or a chat ID.
// An unreadable secret counts as absent, which it is for sending.
func (a *App) channelChanges(old database.GetFormScopedRow, s formSettings) map[string]string {
	telegram := channelChange(openSecret(a.BotTokenCrypto, old.TelegramBotToken, old.ID), s.TelegramToken)
	if telegram == "" && deref(old.TelegramChatID) != s.TelegramChatID {
		telegram = "replaced"
	}
	meta := map[string]string{}
	for name, change := range map[string]string{
		"slack":    channelChange(openSecret(a.WebhookCrypto, old.SlackWebhookUrl, old.ID), s.SlackURL),
		"teams":    channelChange(openSecret(a.WebhookCrypto, old.TeamsWebhookUrl, old.ID), s.TeamsURL),
		"discord":  channelChange(openSecret(a.WebhookCrypto, old.DiscordWebhookUrl, old.ID), s.DiscordURL),
		"telegram": telegram,
	} {
		if change != "" {
			meta[name] = change
		}
	}
	return meta
}

// formAuditMeta names the settings changed, without their values. nil if nothing changes.
func (a *App) formAuditMeta(old database.GetFormScopedRow, s formSettings) map[string]string {
	meta := a.channelChanges(old, s)
	var changed []string
	for _, c := range []struct {
		name    string
		differs bool
	}{
		{"name", old.Name != s.Name},
		{"active", old.Active != s.Active},
		{"notify_email", old.NotifyEmail != s.NotifyEmail},
		{"recipients", !slices.Equal(old.Recipients, s.Recipients)},
		{"email_content", old.EmailIncludeContent != s.IncludeContent},
		{"store", old.StoreSubmissions != s.Store},
		{"retention", old.RetentionDays != s.RetentionDays},
		{"attachments", old.AcceptAttachments != s.Attachments},
		{"captcha", old.Captcha != s.Captcha},
		{"redirect", deref(old.RedirectUrl) != deref(s.RedirectURL)},
		{"chat_content", old.ChatIncludeContent != s.ChatIncludeContent},
		{"notification_lang", old.NotificationLang != s.NotificationLang},
	} {
		if c.differs {
			changed = append(changed, c.name)
		}
	}
	if len(changed) > 0 {
		meta["changed"] = strings.Join(changed, ",")
	}
	if len(meta) == 0 {
		return nil
	}
	meta["name"] = s.Name
	meta["chat_content"] = strconv.FormatBool(s.ChatIncludeContent)
	return meta
}

// channelChange qualifies the change to an alert channel ("" if it does not change).
func channelChange(before, after string) string {
	switch {
	case before == after:
		return ""
	case before == "":
		return "added"
	case after == "":
		return "removed"
	}
	return "replaced"
}

var chatLabels = map[chat.Channel]string{
	chat.Slack: "Slack", chat.Teams: "Teams", chat.Discord: "Discord", chat.Telegram: "Telegram",
}

// TestWebhook sends a test message to the submitted channel, without saving anything.
func (a *App) TestWebhook(w http.ResponseWriter, r *http.Request) {
	form, ok := a.formFor(w, r)
	if !ok {
		return
	}
	v, _, _ := a.readFormSettings(r, form.SiteDomains, form.NotificationLang)
	msg := a.chatTestMessage(v.NotificationLang, form.Name, form.SiteName)
	ch := chat.Channel(r.FormValue("channel"))
	label := chatLabels[ch]
	// Telegram has no "webhook address": its messages have their own text.
	keyPrefix := "form.chat.test"
	var target, errMsg string
	switch ch {
	case chat.Slack:
		target = v.SlackWebhookURL
	case chat.Teams:
		target = v.TeamsWebhookURL
	case chat.Discord:
		target = v.DiscordWebhookURL
	case chat.Telegram:
		keyPrefix = "form.chat.telegram_test"
	default:
		http.Error(w, tr(r, "common.err.bad_id"), http.StatusBadRequest)
		return
	}
	send := func(ctx context.Context) error { return a.Chat.Send(ctx, ch, target, msg) }
	switch {
	case ch == chat.Telegram && (v.TelegramBotToken == "" || v.TelegramChatID == ""):
		errMsg = tr(r, "form.chat.telegram_test_empty")
	case ch == chat.Telegram:
		errMsg = telegramError(r, v.TelegramBotToken, v.TelegramChatID)
		send = func(ctx context.Context) error {
			return a.Chat.SendTelegram(ctx, v.TelegramBotToken, v.TelegramChatID, msg)
		}
	case target == "":
		errMsg = tr(r, "form.chat.test_empty", label)
	case a.Chat.Validate(ch, target) != nil:
		errMsg = tr(r, "form.err."+string(ch)+"_url")
	}
	fail := func(status int, text string) {
		w.WriteHeader(status)
		a.renderFormSettings(w, r, form, v, text, "")
	}
	if errMsg != "" {
		fail(http.StatusBadRequest, errMsg)
		return
	}
	// Without a limit, an account could get the service to block the instance's
	// address, and with it everyone's alerts.
	if a.WebhookTestLimiter != nil && !a.WebhookTestLimiter.Allow(web.UserFrom(r.Context()).ID.String()) {
		fail(http.StatusTooManyRequests, tr(r, "form.chat.test_rate"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), chatTimeout)
	defer cancel()
	if err := send(ctx); err != nil {
		// The error from the chat package contains neither a webhook address nor a token.
		log.Printf("webhook: test %s en échec formulaire=%s: %q", ch, form.ID, err.Error()) // #nosec G706 -- ch is a known channel, form.ID a UUID, the error is quoted
		fail(http.StatusBadGateway, tr(r, keyPrefix+"_failed", label, err.Error()))
		return
	}
	a.renderFormSettings(w, r, form, v, "", tr(r, keyPrefix+"_ok", label))
}

// RegenerateFormKey invalidates the old key at once, which matters if a third party has taken it.
func (a *App) RegenerateFormKey(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	form, ok := a.formFor(w, r)
	if !ok {
		return
	}
	key, err := auth.GenerateAccessKey()
	if err != nil {
		http.Error(w, tr(r, "common.err.internal"), http.StatusInternalServerError)
		return
	}
	if err := a.Q.SetFormAccessKey(r.Context(), database.SetFormAccessKeyParams{ID: form.ID, AccessKey: key}); err != nil {
		http.Error(w, tr(r, "common.err.update"), http.StatusInternalServerError)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditFormKeyRegenerated,
		Entity:   auditEntityForm,
		EntityID: refUUID(form.ID),
		Meta:     map[string]string{"name": form.Name, "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "form.flash.key_regenerated"))
	http.Redirect(w, r, "/forms/"+form.ID.String(), http.StatusSeeOther)
}

func (a *App) DeleteForm(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	form, ok := a.formFor(w, r)
	if !ok {
		return
	}
	if err := a.Q.DeleteForm(r.Context(), form.ID); err != nil {
		web.Flash(a.Sessions, r, tr(r, "form.flash.delete_failed"))
		http.Redirect(w, r, "/forms/"+form.ID.String()+"/settings", http.StatusSeeOther)
		return
	}
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditFormDeleted,
		Entity:   auditEntityForm,
		EntityID: refUUID(form.ID),
		Meta:     map[string]string{"name": form.Name, "site": form.SiteID.String(), "ip": web.ClientIP(r)},
	})
	web.Flash(a.Sessions, r, tr(r, "form.flash.deleted"))
	http.Redirect(w, r, "/sites/"+form.SiteID.String(), http.StatusSeeOther)
}

func (a *App) fileLimits() ui.FileLimits {
	limits := ui.FileLimits{MaxFiles: maxAttachments, MaxMB: a.Cfg.MaxAttachmentBytes >> 20, Scanned: a.Antivirus != nil}
	if a.MailAttachmentBytes > 0 && a.MailAttachmentBytes < a.Cfg.MaxAttachmentBytes {
		limits.EmailMB = a.MailAttachmentBytes >> 20
	}
	return limits
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func dedupeNonEmpty(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
