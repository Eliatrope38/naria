package handlers

import (
	"html"
	"strings"
	"unicode/utf8"

	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/email"
	"gitlab.com/detag_inno/naria/internal/i18n"
	"gitlab.com/detag_inno/naria/internal/submission"
)

// maxSubjectLen caps the subject supplied by the form (the "subject" field).
const maxSubjectLen = 150

// submissionEmail composes the notification. stored, nil if the submission is not
// kept, provides the link to the interface. The language is the form's,
// not the visitor's. Without content, the email carries no visitor data,
// not even its Reply-To. noteKey, if given, is placed below the introduction.
func (a *App) submissionEmail(form database.GetFormByAccessKeyRow, meta submission.Meta, data []submission.Field, files []submission.File, stored *database.Submission, noteKey string) email.Message {
	loc := i18n.Get(i18n.Locale(form.NotificationLang))
	msg := email.Message{To: form.Recipients}
	link := ""
	if stored != nil {
		link = strings.TrimRight(a.Cfg.BaseURL, "/") + "/submissions/" + stored.ID.String()
	}
	intro := loc.T("mail.submission.intro", form.Name, form.SiteName)
	footer := loc.T("mail.submission.footer", a.Cfg.Brand.Name)

	if !form.EmailIncludeContent {
		msg.Subject = loc.T("mail.submission.subject", form.SiteName, form.Name)
		msg.HTML = submissionEmailHTML(intro, loc.T("mail.submission.no_content"), nil, link, loc.T("mail.submission.button"), footer, a.Cfg.Brand.Color)
		return msg
	}

	msg.Subject = loc.T("mail.submission.subject", form.SiteName, form.Name)
	if s := oneLine(meta.Subject, maxSubjectLen); s != "" {
		msg.Subject = "[" + form.SiteName + "] " + s
	}
	msg.ReplyTo = submission.ReplyAddress(meta, data)
	note := ""
	if noteKey != "" {
		note = loc.T(noteKey)
	}
	msg.HTML = submissionEmailHTML(intro, note, data, link, loc.T("mail.submission.button"), footer, a.Cfg.Brand.Color)
	for _, f := range files {
		msg.Attachments = append(msg.Attachments, email.Attachment(f))
	}
	return msg
}

// oneLine reduces free text to a single bounded line (email subject).
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) { // do not cut in the middle of a character
		s = s[:len(s)-1]
	}
	return s + "…"
}

// submissionEmailHTML lays out the notification. All visitor content is escaped.
func submissionEmailHTML(intro, note string, fields []submission.Field, link, button, footer, color string) string {
	var b strings.Builder
	b.WriteString(`<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#15202b">`)
	b.WriteString("<p>" + html.EscapeString(intro) + "</p>")
	if note != "" {
		b.WriteString(`<p style="color:#555c63">` + html.EscapeString(note) + `</p>`)
	}
	if len(fields) > 0 {
		b.WriteString(`<table style="border-collapse:collapse;width:100%;max-width:640px">`)
		for _, f := range fields {
			value := strings.ReplaceAll(html.EscapeString(f.Value), "\n", "<br>")
			b.WriteString(`<tr><th style="text-align:left;vertical-align:top;padding:8px 12px 8px 0;border-bottom:1px solid #e8eaed;color:#6b7280;font-weight:normal;width:32%">` +
				html.EscapeString(f.Name) +
				`</th><td style="vertical-align:top;padding:8px 0;border-bottom:1px solid #e8eaed">` + value + `</td></tr>`)
		}
		b.WriteString(`</table>`)
	}
	if link != "" {
		b.WriteString(`<p style="margin-top:20px"><a href="` + html.EscapeString(link) + `" style="background:` + color + `;color:#fff;padding:9px 18px;border-radius:4px;text-decoration:none">` + html.EscapeString(button) + `</a></p>`)
	}
	b.WriteString(`<hr style="border:none;border-top:1px solid #e8eaed;margin:18px 0"><p style="color:#8b9298;font-size:12px">` + html.EscapeString(footer) + `</p>`)
	b.WriteString("</div>")
	return b.String()
}
