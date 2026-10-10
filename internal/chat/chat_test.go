package chat

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Validate keeps the server from reaching the instance's internal network.
func TestValidate(t *testing.T) {
	n := New([]string{"chat.interne.exemple", ".equipe.exemple"})
	cases := []struct {
		ch   Channel
		raw  string
		want error
	}{
		{Slack, "https://hooks.slack.com/services/T000/B000/XXXX", nil},
		{Slack, "  https://hooks.slack.com/services/T000/B000/XXXX  ", nil},
		{Slack, "https://HOOKS.slack.com:443/services/T/B/X", nil},
		{Teams, "https://abc123.de.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/w/triggers/manual/paths/invoke?api-version=1&sig=s", nil},
		{Slack, "https://chat.interne.exemple:8443/hooks/abc", nil},
		{Teams, "https://a.b.equipe.exemple/hooks/abc", nil},
		{Discord, "https://discord.com/api/webhooks/123456/TOKEN", nil},
		{Discord, "https://ptb.discord.com/api/webhooks/123456/TOKEN?wait=true", nil},
		{Discord, "https://discordapp.com/api/webhooks/123456/TOKEN", nil},
		{Discord, "https://discord.com/api/v10/webhooks/123456/TO-K_EN", nil},
		{Discord, "https://chat.interne.exemple/hooks/abc", nil}, // hôte de l'exploitant : chemin libre

		{Slack, "http://hooks.slack.com/services/T/B/X", ErrInvalidURL},
		{Slack, "", ErrInvalidURL},
		{Slack, "hooks.slack.com/services/T/B/X", ErrInvalidURL},
		{Slack, "https://user:pass@hooks.slack.com/services/T/B/X", ErrInvalidURL},
		{Slack, "https://hooks.slack.com@evil.tld/services/T/B/X", ErrInvalidURL},
		{Slack, "javascript:alert(1)", ErrInvalidURL},

		{Slack, "https://evil.tld/services/T/B/X", ErrHostNotAllowed},
		{Slack, "https://hooks.slack.com.evil.tld/services/T/B/X", ErrHostNotAllowed},
		{Slack, "https://evilhooks.slack.com/services/T/B/X", ErrHostNotAllowed},
		{Slack, "https://hooks.slack.com:8443/services/T/B/X", ErrHostNotAllowed},
		{Slack, "https://127.0.0.1/admin", ErrHostNotAllowed},
		{Slack, "https://localhost:5432/", ErrHostNotAllowed},
		{Slack, "https://169.254.169.254/latest/meta-data/", ErrHostNotAllowed},
		{Teams, "https://api.powerplatform.com/x", ErrHostNotAllowed}, // le suffixe exige un sous-domaine
		{Teams, "https://evilapi.powerplatform.com/x", ErrHostNotAllowed},
		{Teams, "https://hooks.slack.com/services/T/B/X", ErrHostNotAllowed},
		{Slack, "https://x.environment.api.powerplatform.com/y", ErrHostNotAllowed},
		{Slack, "https://equipe.exemple/hooks", ErrHostNotAllowed},
		{Discord, "https://evil.discord.com/api/webhooks/1/T", ErrHostNotAllowed}, // pas de joker sur discord.com
		{Discord, "https://discord.com.evil.tld/api/webhooks/1/T", ErrHostNotAllowed},
		{Discord, "https://hooks.slack.com/services/T/B/X", ErrHostNotAllowed},
		{Slack, "https://discord.com/api/webhooks/1/T", ErrHostNotAllowed},

		// discord.com serves the whole Discord API: only a webhook path gets through.
		{Discord, "https://discord.com/", ErrInvalidURL},
		{Discord, "https://discord.com/channels/1/2", ErrInvalidURL},
		{Discord, "https://discord.com/api/v10/auth/login", ErrInvalidURL},
		{Discord, "https://discord.com/api/webhooks/1/T/slack", ErrInvalidURL},
		{Discord, "https://discord.com/api/webhooks/1%2FT", ErrInvalidURL},
		{Discord, "https://discord.com/api/webhooks/../v10/auth/login", ErrInvalidURL},
	}
	for _, tc := range cases {
		if err := n.Validate(tc.ch, tc.raw); !errors.Is(err, tc.want) {
			t.Errorf("Validate(%s, %q) = %v, want %v", tc.ch, tc.raw, err, tc.want)
		}
	}
}

// server starts a fake chat service over HTTPS and a Notifier that trusts it.
func server(t *testing.T, h http.HandlerFunc) (*Notifier, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	n := New([]string{u.Hostname()})
	client := srv.Client()
	client.CheckRedirect = n.Client.CheckRedirect
	n.Client = client
	return n, srv.URL + "/hook/SECRET-TOKEN"
}

func TestSendPostsJSON(t *testing.T) {
	for _, ch := range []Channel{Slack, Teams, Discord} {
		var got map[string]any
		n, hook := server(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("%s: %s %s", ch, r.Method, r.Header.Get("Content-Type"))
			}
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &got); err != nil {
				t.Errorf("%s: corps JSON invalide: %v", ch, err)
			}
			w.WriteHeader(map[Channel]int{Slack: http.StatusOK, Teams: http.StatusAccepted, Discord: http.StatusNoContent}[ch])
		})
		if err := n.Send(context.Background(), ch, hook, Message{Title: "Titre", Fields: []Field{{"nom", "Ada"}}}); err != nil {
			t.Fatalf("%s: Send: %v", ch, err)
		}
		key := map[Channel]string{Slack: "blocks", Teams: "attachments", Discord: "allowed_mentions"}[ch]
		if _, ok := got[key]; !ok {
			t.Fatalf("%s: clé %q absente du message : %v", ch, key, got)
		}
	}
}

func TestSendErrorsDoNotLeakURL(t *testing.T) {
	n, hook := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	err := n.Send(context.Background(), Slack, hook, Message{Title: "x"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("statut 403 : got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatalf("l'erreur cite l'adresse du webhook : %v", err)
	}

	// Network failure: the HTTP client error contains the URL, which must be stripped.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	u, _ := url.Parse(srv.URL)
	down := New([]string{u.Hostname()})
	down.Client = srv.Client()
	srv.Close()
	err = down.Send(context.Background(), Teams, srv.URL+"/hook/SECRET-TOKEN", Message{Title: "x"})
	if err == nil {
		t.Fatal("serveur arrêté : une erreur était attendue")
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN") || strings.Contains(err.Error(), "/hook/") {
		t.Fatalf("l'erreur cite l'adresse du webhook : %v", err)
	}
}

func TestSendDoesNotFollowRedirects(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer target.Close()
	n, hook := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/interne", http.StatusTemporaryRedirect)
	})
	if err := n.Send(context.Background(), Slack, hook, Message{Title: "x"}); err == nil {
		t.Fatal("une redirection doit être traitée comme un échec")
	}
	if reached {
		t.Fatal("la redirection a été suivie")
	}
}

func TestSendRevalidatesURL(t *testing.T) {
	n := New(nil)
	if err := n.Send(context.Background(), Slack, "https://127.0.0.1:1/x", Message{Title: "x"}); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("got %v, want ErrHostNotAllowed", err)
	}
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSlackPayloadTreatsVisitorContentAsPlainText(t *testing.T) {
	p := slackPayload(Message{
		Title:   "Nouvelle soumission : <Contact>",
		Context: "Site & Cie",
		Fields: []Field{
			{"message", "<!channel> voyez <https://evil.tld|votre facture> *urgent*"},
			{"vide", ""},
		},
		LinkURL: "https://naria.test/submissions/1", LinkLabel: "Voir",
	})
	if p.Text != "[Site & Cie] Nouvelle soumission : <Contact>" {
		t.Errorf("repli = %q", p.Text)
	}
	if got := p.Blocks[0].Text; got.Type != "mrkdwn" || got.Text != "*Nouvelle soumission : &lt;Contact&gt;*\nSite &amp; Cie" {
		t.Errorf("en-tête = %+v", got)
	}
	msg := p.Blocks[1].Fields
	if len(msg) != 2 || msg[0].Type != "plain_text" || msg[1].Type != "plain_text" {
		t.Fatalf("champ du visiteur hors plain_text : %+v", msg)
	}
	if msg[1].Text != "<!channel> voyez <https://evil.tld|votre facture> *urgent*" {
		t.Errorf("valeur altérée : %q", msg[1].Text)
	}
	if empty := p.Blocks[2].Fields[1].Text; empty != "-" {
		t.Errorf("valeur vide = %q (Slack refuse un texte vide)", empty)
	}
	last := p.Blocks[len(p.Blocks)-1].Text
	if last.Text != "<https://naria.test/submissions/1|Voir>" {
		t.Errorf("lien = %q", last.Text)
	}
	// Only the header and the link (written by the application) are mrkdwn.
	for i, b := range p.Blocks[1 : len(p.Blocks)-1] {
		if b.Text != nil && b.Text.Type == "mrkdwn" {
			t.Errorf("bloc %d en mrkdwn", i+1)
		}
	}
}

func TestTeamsPayload(t *testing.T) {
	p := teamsPayload(Message{
		Title:   "Nouvelle soumission : Contact",
		Context: "Atelier",
		Fields:  []Field{{"message", "ligne 1\nligne 2 [votre facture](https://evil.tld)"}},
		LinkURL: "https://naria.test/submissions/1", LinkLabel: "Voir",
	})
	if p.Type != "message" || len(p.Attachments) != 1 || p.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("enveloppe inattendue : %s", marshal(t, p))
	}
	card := p.Attachments[0].Content
	if card.Type != "AdaptiveCard" || card.Version != "1.4" {
		t.Errorf("carte = %s %s", card.Type, card.Version)
	}
	value := card.Body[len(card.Body)-1].Text
	if strings.Contains(value, "](") {
		t.Errorf("lien Markdown d'un visiteur resté actif : %q", value)
	}
	if !strings.Contains(value, "ligne 1\n\nligne 2") {
		t.Errorf("saut de ligne non doublé : %q", value)
	}
	if len(card.Actions) != 1 || card.Actions[0].Type != "Action.OpenUrl" || card.Actions[0].URL != "https://naria.test/submissions/1" {
		t.Errorf("action = %+v", card.Actions)
	}
	// No link: no action (an action without a URL would get the card rejected).
	if got := teamsPayload(Message{Title: "x"}).Attachments[0].Content.Actions; got != nil {
		t.Errorf("actions sans lien = %+v", got)
	}
	if strings.Contains(marshal(t, teamsPayload(Message{Title: "x"})), `"actions"`) {
		t.Error("clé actions présente sans lien")
	}
}

func TestDiscordPayload(t *testing.T) {
	p := discordPayload(Message{
		Title:   "Nouvelle soumission : Contact",
		Context: "Atelier",
		Fields: []Field{
			{"message", "@everyone <@123> voyez [votre facture](https://evil.tld)"},
			{"vide", ""},
		},
		LinkURL: "https://naria.test/submissions/1", LinkLabel: "Voir",
	})
	raw := marshal(t, p)
	if !strings.Contains(raw, `"allowed_mentions":{"parse":[]}`) {
		t.Errorf("allowed_mentions doit interdire toute mention : %s", raw)
	}
	if p.Content != "**Nouvelle soumission : Contact**\nAtelier" {
		t.Errorf("content = %q", p.Content)
	}
	if len(p.Embeds) != 1 {
		t.Fatalf("embeds = %+v", p.Embeds)
	}
	desc := p.Embeds[0].Description
	if strings.Contains(desc, "](https://evil.tld") {
		t.Errorf("lien Markdown d'un visiteur resté actif : %q", desc)
	}
	if strings.Contains(desc, "<@") {
		t.Errorf("mention d'un visiteur restée active : %q", desc)
	}
	if !strings.Contains(desc, "**vide**\n-") {
		t.Errorf("valeur vide : %q", desc)
	}
	if !strings.HasSuffix(desc, "[Voir](https://naria.test/submissions/1)") || strings.Count(desc, "](") != 1 {
		t.Errorf("lien = %q", desc)
	}

	p = discordPayload(Message{
		Title: "Contact <@1>", Context: "[site](https://evil.tld)",
		Fields:   []Field{{"x](https://evil.tld) <@123>", "v"}},
		MoreNote: "Contenu tronqué.",
	})
	if all := p.Content + p.Embeds[0].Description; strings.Contains(all, "](") || strings.Contains(all, "<@") {
		t.Errorf("syntaxe active hors des valeurs : %q", all)
	}
	if strings.Contains(p.Embeds[0].Description, "Contenu tronqué.") {
		t.Errorf("mention « tronqué » sans troncature : %q", p.Embeds[0].Description)
	}
	p = discordPayload(Message{Title: "x", Fields: []Field{{strings.Repeat("n", fieldNameMax+1), "v"}}, MoreNote: "Contenu tronqué."})
	if !strings.HasSuffix(p.Embeds[0].Description, "Contenu tronqué.") {
		t.Errorf("nom de champ coupé sans le signaler : %q", p.Embeds[0].Description)
	}

	// Nothing to say beyond the title: no embed (Discord refuses an empty embed).
	if got := discordPayload(Message{Title: "x"}); got.Embeds != nil || strings.Contains(marshal(t, got), `"embeds"`) {
		t.Errorf("embed vide : %+v", got.Embeds)
	}

	// Maximum content, in emojis (two UTF-16 units each): the description stays under the limit,
	// without losing either the truncation notice or the link.
	big := make([]Field, maxFields)
	for i := range big {
		big[i] = Field{Name: strings.Repeat("n", 300), Value: strings.Repeat("😀", maxValueRunes)}
	}
	p = discordPayload(Message{
		Title: strings.Repeat("😀", 1500), Fields: big, MoreNote: "Contenu tronqué.",
		LinkURL: "https://naria.test/submissions/1", LinkLabel: "Voir",
	})
	if n := len16(p.Content); n > discordContentMax || !strings.HasSuffix(p.Content, "…**") {
		t.Errorf("content : %d unités UTF-16 (max %d), fin %q (le gras doit rester fermé)", n, discordContentMax, p.Content[len(p.Content)-8:])
	}
	desc = p.Embeds[0].Description
	if n := len16(desc); n > discordDescriptionMax || n < discordDescriptionMax-600 {
		t.Errorf("description : %d unités UTF-16 (max %d, et le budget doit être utilisé)", n, discordDescriptionMax)
	}
	if !strings.HasSuffix(desc, "Contenu tronqué.\n\n[Voir](https://naria.test/submissions/1)") {
		t.Errorf("fin de description = %q", desc[len(desc)-80:])
	}
}

func TestClip16(t *testing.T) {
	cases := []struct {
		in    string
		limit int
		want  string
		cut   bool
	}{
		{"abc", 3, "abc", false},
		{"abcd", 3, "ab…", true},
		{"😀😀", 4, "😀😀", false},
		{"😀😀", 3, "😀…", true}, // never half an emoji
		{"😀😀", 2, "…", true},
		{"abc", 0, "", true},
	}
	for _, tc := range cases {
		got, cut := clip16(tc.in, tc.limit)
		if got != tc.want || cut != tc.cut || len16(got) > tc.limit {
			t.Errorf("clip16(%q, %d) = %q, %v ; want %q, %v", tc.in, tc.limit, got, cut, tc.want, tc.cut)
		}
	}
}

func TestFit(t *testing.T) {
	long := strings.Repeat("é", maxValueRunes+50)
	out, truncated := fit([]Field{{"a", long}, {"b", "court"}})
	if !truncated || len([]rune(out[0].Value)) != maxValueRunes+1 || !strings.HasSuffix(out[0].Value, "…") || out[1].Value != "court" {
		t.Errorf("valeur longue : truncated=%v len=%d", truncated, len([]rune(out[0].Value)))
	}

	many := make([]Field, maxFields+5)
	for i := range many {
		many[i] = Field{Name: "f", Value: "v"}
	}
	if out, truncated := fit(many); len(out) != maxFields || !truncated {
		t.Errorf("trop de champs : %d gardés, truncated=%v", len(out), truncated)
	}

	big := make([]Field, maxFields)
	for i := range big {
		big[i] = Field{Name: "f", Value: strings.Repeat("x", maxValueRunes)}
	}
	out, truncated = fit(big)
	total := 0
	for _, f := range out {
		total += len([]rune(f.Value))
	}
	if !truncated || total > maxTotalRunes+len(out) {
		t.Errorf("budget dépassé : %d caractères, truncated=%v", total, truncated)
	}

	if out, truncated := fit([]Field{{"a", "b"}}); truncated || len(out) != 1 {
		t.Errorf("contenu court : truncated=%v", truncated)
	}
}

const testTelegramToken = "123456789:AAExampleExampleExampleExampleExample"

func TestValidateTelegram(t *testing.T) {
	cases := []struct {
		token, chat string
		want        error
	}{
		{testTelegramToken, "-1001234567890", nil},
		{testTelegramToken, "123456", nil},
		{testTelegramToken, "@canal_public", nil},
		{testTelegramToken, "@abcde", nil},                       // 5 characters: the shortest
		{testTelegramToken, "@a" + strings.Repeat("b", 31), nil}, // 32: the longest
		{"1:" + strings.Repeat("A", 20), "1", nil},
		{strings.Repeat("9", 20) + ":" + strings.Repeat("A", 100), strings.Repeat("9", 20), nil},

		{"", "-100", ErrTelegramToken},
		{"123456789", "-100", ErrTelegramToken},
		{"123456789:court", "-100", ErrTelegramToken},
		{"abc:" + strings.Repeat("A", 35), "-100", ErrTelegramToken},
		{testTelegramToken + "/../getMe", "-100", ErrTelegramToken},
		{testTelegramToken + "/sendMessage?x=", "-100", ErrTelegramToken},
		{testTelegramToken + "@evil.tld", "-100", ErrTelegramToken},
		{"x" + testTelegramToken, "-100", ErrTelegramToken},
		{"/" + testTelegramToken, "-100", ErrTelegramToken},
		{testTelegramToken + "\n", "-100", ErrTelegramToken},
		{"1:" + strings.Repeat("A", 19), "-100", ErrTelegramToken},
		{"1:" + strings.Repeat("A", 101), "-100", ErrTelegramToken},
		{strings.Repeat("9", 21) + ":" + strings.Repeat("A", 35), "-100", ErrTelegramToken},
		{"pas-un-jeton", "pas un identifiant", ErrTelegramToken}, // the token is checked first

		{testTelegramToken, "", ErrTelegramChat},
		{testTelegramToken, "mon groupe", ErrTelegramChat},
		{testTelegramToken, "@abcd", ErrTelegramChat},
		{testTelegramToken, "@a" + strings.Repeat("b", 32), ErrTelegramChat},
		{testTelegramToken, "@1abcd", ErrTelegramChat},
		{testTelegramToken, strings.Repeat("9", 21), ErrTelegramChat},
		{testTelegramToken, "-100\n", ErrTelegramChat},
		{testTelegramToken, "-100\n1", ErrTelegramChat},
	}
	for _, tc := range cases {
		if err := ValidateTelegram(tc.token, tc.chat); !errors.Is(err, tc.want) {
			t.Errorf("ValidateTelegram(%q, %q) = %v, want %v", tc.token, tc.chat, err, tc.want)
		}
	}
}

func TestTelegramPayload(t *testing.T) {
	p := telegramPayload("-100123", Message{
		Title:   "Nouvelle soumission : <Contact>",
		Context: "Site & Cie",
		Fields: []Field{
			{"message", `<a href="https://evil.tld">votre facture</a> & <b>urgent</b>`},
			{"<i>nom</i>", "@durov (@admin), répondre à ada@exemple.fr"},
			{"@nom_de_champ", "x"},
			{"vide", ""},
		},
		LinkURL: `https://naria.test/submissions/1?a=1&b="x"`, LinkLabel: "Voir",
	})
	raw := marshal(t, p)
	if p.ChatID != "-100123" || p.ParseMode != "HTML" || !strings.Contains(raw, `"link_preview_options":{"is_disabled":true}`) {
		t.Errorf("enveloppe inattendue : %s", raw)
	}
	if !strings.HasPrefix(p.Text, "<b>Nouvelle soumission : &lt;Contact&gt;</b>\nSite &amp; Cie\n\n") {
		t.Errorf("en-tête = %q", p.Text)
	}
	if !strings.Contains(p.Text, `&lt;a href="https://evil.tld"&gt;votre facture&lt;/a&gt; &amp; &lt;b&gt;urgent&lt;/b&gt;`) {
		t.Errorf("balises d'un visiteur non échappées : %q", p.Text)
	}
	if !strings.Contains(p.Text, "<b>&lt;i&gt;nom&lt;/i&gt;</b>\n") || !strings.Contains(p.Text, "<b>vide</b>\n-") {
		t.Errorf("noms de champ : %q", p.Text)
	}
	link := `<a href="https://naria.test/submissions/1?a=1&amp;b=&#34;x&#34;">Voir</a>`
	if !strings.HasSuffix(p.Text, "\n\n"+link) || strings.Count(p.Text, "<a ") != 1 {
		t.Errorf("lien = %q", p.Text)
	}
	if strings.Contains(p.Text, "@durov") || strings.Contains(p.Text, "@admin") || strings.Contains(p.Text, "@nom_de_champ") {
		t.Errorf("@mention d'un visiteur restée active : %q", p.Text)
	}
	if !strings.Contains(p.Text, "ada@exemple.fr") {
		t.Errorf("adresse email altérée : %q", p.Text)
	}

	// Maximum content made of characters that grow when escaped: the text stays under the limit,
	// without a split entity (Telegram would refuse the whole message).
	big := make([]Field, maxFields)
	for i := range big {
		big[i] = Field{Name: strings.Repeat("<", 300), Value: strings.Repeat("&😀", maxValueRunes/2)}
	}
	p = telegramPayload("1", Message{
		Title: strings.Repeat("&", 2000), Context: strings.Repeat("<", 2000), Fields: big, MoreNote: "Contenu tronqué.",
		LinkURL: "https://naria.test/submissions/1", LinkLabel: "Voir",
	})
	if n := len16(p.Text); n > telegramTextMax || n < telegramTextMax-600 {
		t.Errorf("texte : %d unités UTF-16 (max %d, et le budget doit être utilisé)", n, telegramTextMax)
	}
	entities := strings.Count(p.Text, "&amp;") + strings.Count(p.Text, "&lt;") + strings.Count(p.Text, "&gt;")
	if strings.Count(p.Text, "&") != entities {
		t.Errorf("entité HTML coupée")
	}
	if strings.Count(p.Text, "<b>") != strings.Count(p.Text, "</b>") {
		t.Errorf("balise <b> non fermée")
	}
	if !strings.HasSuffix(p.Text, "Contenu tronqué.\n\n<a href=\"https://naria.test/submissions/1\">Voir</a>") {
		t.Errorf("fin du texte = %q", p.Text[len(p.Text)-90:])
	}

	if got := telegramPayload("1", Message{Title: "x"}).Text; got != "<b>x</b>" {
		t.Errorf("titre seul = %q", got)
	}
}

func TestTelegramClean(t *testing.T) {
	const z = "​"
	cases := []struct{ in, want string }{
		{"", ""},
		{"sans arobase", "sans arobase"},
		{"ada@exemple.fr", "ada@exemple.fr"},
		{"5@a", "5@a"},
		{"@durov", "@" + z + "durov"},
		{"voir @durov", "voir @" + z + "durov"},
		{"(@durov)", "(@" + z + "durov)"},
		{"_@durov", "_@" + z + "durov"},
		{".@durov", ".@" + z + "durov"},
		{"@@durov", "@" + z + "@" + z + "durov"},
		{"fin @", "fin @" + z},
		// Non-ASCII letters and digits: nothing says Telegram treats them as the start of an address.
		{"é@durov", "é@" + z + "durov"},
		{"я@durov", "я@" + z + "durov"},
		{"中@durov", "中@" + z + "durov"},
		{"١@durov", "١@" + z + "durov"},
	}
	for _, tc := range cases {
		if got := telegramClean(tc.in); got != tc.want {
			t.Errorf("telegramClean(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestClipCost(t *testing.T) {
	cost := telegramMarkup.cost
	cases := []struct {
		in    string
		limit int
		want  string
		cut   bool
	}{
		{"a&", 6, "a&", false}, // 1 + 5
		{"a&&", 6, "a…", true},
		{"a&&", 11, "a&&", false},
		{"<>", 7, "<…", true},
		{"&", 4, "…", true},
	}
	for _, tc := range cases {
		got, cut := clipCost(tc.in, tc.limit, cost)
		if got != tc.want || cut != tc.cut {
			t.Errorf("clipCost(%q, %d) = %q, %v ; want %q, %v", tc.in, tc.limit, got, cut, tc.want, tc.cut)
		}
		if escaped := telegramMarkup.escape(got); len16(escaped) > tc.limit {
			t.Errorf("clipCost(%q, %d) : %q fait %d unités une fois échappé", tc.in, tc.limit, escaped, len16(escaped))
		}
	}
}

func TestSendTelegram(t *testing.T) {
	if got := New(nil).TelegramAPI; got != "https://api.telegram.org" {
		t.Errorf("adresse de l'API par défaut = %q", got)
	}
	var path string
	var got map[string]any
	status, answer := http.StatusOK, `{"ok":true}`
	n, hook := server(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	})
	n.TelegramAPI = strings.TrimSuffix(hook, "/hook/SECRET-TOKEN")

	if err := n.SendTelegram(context.Background(), testTelegramToken, "-100123", Message{Title: "Titre"}); err != nil {
		t.Fatalf("SendTelegram: %v", err)
	}
	if path != "/bot"+testTelegramToken+"/sendMessage" {
		t.Errorf("chemin appelé = %q", path)
	}
	if got["chat_id"] != "-100123" || got["parse_mode"] != "HTML" || got["text"] != "<b>Titre</b>" {
		t.Errorf("message = %v", got)
	}

	status, answer = http.StatusBadRequest, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`
	err := n.SendTelegram(context.Background(), testTelegramToken, "-100123", Message{Title: "x"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || !strings.Contains(err.Error(), "chat not found") {
		t.Errorf("refus : got %v", err)
	}
	status, answer = http.StatusUnauthorized, `{"ok":false,"description":"bad token `+testTelegramToken+`"}`
	err = n.SendTelegram(context.Background(), testTelegramToken, "-100123", Message{Title: "x"})
	if err == nil || strings.Contains(err.Error(), testTelegramToken) {
		t.Errorf("l'erreur cite le jeton : %v", err)
	}
	secret := testTelegramToken[strings.IndexByte(testTelegramToken, ':')+1:]
	status, answer = http.StatusUnauthorized, `{"ok":false,"description":"bad token 123456789%3A`+secret+`"}`
	err = n.SendTelegram(context.Background(), testTelegramToken, "-100123", Message{Title: "x"})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("l'erreur cite la moitié secrète du jeton : %v", err)
	}
	status, answer = http.StatusBadGateway, `<html>pas du JSON</html>`
	if err = n.SendTelegram(context.Background(), testTelegramToken, "-100123", Message{Title: "x"}); err == nil || err.Error() != "telegram: HTTP 502" {
		t.Errorf("réponse illisible : got %v", err)
	}

	path = ""
	if err := n.SendTelegram(context.Background(), testTelegramToken+"/../getMe", "-100123", Message{Title: "x"}); !errors.Is(err, ErrTelegramToken) {
		t.Errorf("jeton mal formé : got %v", err)
	}
	if err := n.SendTelegram(context.Background(), testTelegramToken, "x y", Message{Title: "x"}); !errors.Is(err, ErrTelegramChat) {
		t.Errorf("identifiant mal formé : got %v", err)
	}
	if path != "" {
		t.Errorf("un réglage refusé a tout de même été appelé : %s", path)
	}

	elsewhere := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere = true }))
	defer other.Close()
	redirecting, hook := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	redirecting.TelegramAPI = strings.TrimSuffix(hook, "/hook/SECRET-TOKEN")
	if err := redirecting.SendTelegram(context.Background(), testTelegramToken, "-100123", Message{Title: "x"}); err == nil || elsewhere {
		t.Errorf("redirection : err=%v, suivie=%v", err, elsewhere)
	}

	// Network failure: the HTTP client error contains the URL, and so the token.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	down := New(nil)
	down.Client, down.TelegramAPI = srv.Client(), srv.URL
	srv.Close()
	err = down.SendTelegram(context.Background(), testTelegramToken, "-100123", Message{Title: "x"})
	if err == nil || strings.Contains(err.Error(), testTelegramToken) || strings.Contains(err.Error(), "/bot") {
		t.Errorf("panne réseau : got %v", err)
	}
}
