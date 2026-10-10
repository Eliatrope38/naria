package handlers

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"gitlab.com/detag_inno/naria/internal/chat"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/i18n"
	"gitlab.com/detag_inno/naria/internal/submission"
)

// Each channel has its own: a slow service must not make the others fail.
const chatTimeout = 15 * time.Second

// notifyChat posts the alert in the background. An alert is not a destination:
// a failing chat service neither fails nor delays any submission.
func (a *App) notifyChat(form database.GetFormByAccessKeyRow, data []submission.Field, stored *database.Submission) {
	if a.Chat == nil {
		return
	}
	sends := map[chat.Channel]func(context.Context, chat.Message) error{}
	for ch, sealed := range map[chat.Channel]*string{
		chat.Slack:   form.SlackWebhookUrl,
		chat.Teams:   form.TeamsWebhookUrl,
		chat.Discord: form.DiscordWebhookUrl,
	} {
		if target := openSecret(a.WebhookCrypto, sealed, form.ID); target != "" {
			sends[ch] = func(ctx context.Context, m chat.Message) error { return a.Chat.Send(ctx, ch, target, m) }
		}
	}
	if token := openSecret(a.BotTokenCrypto, form.TelegramBotToken, form.ID); token != "" {
		chatID := deref(form.TelegramChatID)
		sends[chat.Telegram] = func(ctx context.Context, m chat.Message) error {
			return a.Chat.SendTelegram(ctx, token, chatID, m)
		}
	}
	if len(sends) == 0 {
		return
	}
	msg := a.chatSubmissionMessage(form, data, stored)
	formID := form.ID
	go func() { // #nosec G118 -- the send must outlive the request, which is already answered
		for ch, send := range sends {
			ctx, cancel := context.WithTimeout(context.Background(), chatTimeout)
			err := send(ctx, msg)
			cancel()
			if err != nil {
				logChatFailure(ch, formID, err)
			}
		}
	}()
}

// The chat package error contains neither a webhook address nor a token.
func logChatFailure(ch chat.Channel, formID uuid.UUID, err error) {
	log.Printf("ERROR webhook: alerte %s formulaire=%s: %q", ch, formID, err.Error()) // #nosec G706 -- ch is a constant, formID a UUID, the error is quoted (%q escapes CR/LF)
}

// Without chat_include_content, no visitor data is posted: chat services
// are third parties, and a posted message escapes the retention period.
func (a *App) chatSubmissionMessage(form database.GetFormByAccessKeyRow, data []submission.Field, stored *database.Submission) chat.Message {
	loc := i18n.Get(i18n.Locale(form.NotificationLang))
	msg := chat.Message{
		Title:   loc.T("chat.submission.title", form.Name),
		Context: form.SiteName,
	}
	if stored != nil {
		msg.LinkURL = strings.TrimRight(a.Cfg.BaseURL, "/") + "/submissions/" + stored.ID.String()
		msg.LinkLabel = loc.T("chat.submission.link")
	}
	if form.ChatIncludeContent {
		msg.Fields = make([]chat.Field, 0, len(data))
		for _, f := range data {
			msg.Fields = append(msg.Fields, chat.Field{Name: f.Name, Value: f.Value})
		}
		msg.MoreNote = loc.T("chat.submission.more")
		return msg
	}
	switch {
	case stored != nil:
		msg.Note = loc.T("chat.submission.note_stored")
	case form.NotifyEmail:
		msg.Note = loc.T("chat.submission.note_email")
	}
	return msg
}

// chatTestMessage composes the message sent by the "Test" button.
func (a *App) chatTestMessage(lang, formName, siteName string) chat.Message {
	loc := i18n.Get(i18n.Locale(lang))
	return chat.Message{
		Title:   loc.T("chat.test.title", formName),
		Context: siteName,
		Note:    loc.T("chat.test.note"),
	}
}
