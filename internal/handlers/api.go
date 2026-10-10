package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/i18n"
	"gitlab.com/detag_inno/naria/internal/web"
	"gitlab.com/detag_inno/naria/ui"
)

type apiTokenKey struct{}

// apiToken returns the token authenticated by APIAuth: its site and its creator.
func apiToken(r *http.Request) database.GetAPITokenByHashRow {
	tok, _ := r.Context().Value(apiTokenKey{}).(database.GetAPITokenByHashRow)
	return tok
}

// Beyond this limit the API stops creating forms on a site, so a runaway client
// cannot fill the database.
const maxAPIForms = 100

// APIAuth authenticates with a Bearer token. Without session or cookie, the API needs
// no CSRF token: a page from another origin can only set Authorization after a CORS
// preflight, which these routes refuse.
//
// The rate limit applies twice: per IP address before the token is read, then per token,
// for a caller that holds several addresses.
func (a *App) APIAuth(next http.Handler) http.Handler {
	limited := func(w http.ResponseWriter, r *http.Request, key string) bool {
		if a.APILimiter == nil || a.APILimiter.Allow(key) {
			return false
		}
		w.Header().Set("Retry-After", "60")
		writeAPIError(w, http.StatusTooManyRequests, tr(r, "api.err.rate"))
		return true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limited(w, r, web.RateLimitKey(r)) {
			return
		}
		plain, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !strings.HasPrefix(plain, auth.APITokenPrefix) {
			apiUnauthorized(w, r)
			return
		}
		tok, err := a.Q.GetAPITokenByHash(r.Context(), auth.HashToken(plain))
		if errors.Is(err, pgx.ErrNoRows) {
			apiUnauthorized(w, r)
			return
		}
		if err != nil {
			log.Printf("ERROR api: lecture du jeton: %v", err)
			writeAPIError(w, http.StatusInternalServerError, tr(r, "common.err.internal"))
			return
		}
		if limited(w, r, tok.ID.String()) {
			return
		}
		if err := a.Q.TouchAPIToken(r.Context(), tok.ID); err != nil {
			log.Printf("ERROR api: date de dernière utilisation du jeton %s: %v", tok.ID, err)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), apiTokenKey{}, tok)))
	})
}

// apiUnauthorized answers the same way for a missing, unknown or expired token, or one
// whose creator has lost access to the site.
func apiUnauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeAPIError(w, http.StatusUnauthorized, tr(r, "api.err.unauthorized"))
}

func writeAPIJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("ERROR api: écriture de la réponse: %v", err)
	}
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeAPIJSON(w, status, map[string]string{"error": message})
}

type apiSite struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

// apiForm omits recipients and alert channels: a token, even handed to a third party,
// must not reveal who receives submissions.
type apiForm struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Active              bool   `json:"active"`
	AccessKey           string `json:"access_key"`
	SubmitURL           string `json:"submit_url"`
	NotifyEmail         bool   `json:"notify_email"`
	EmailIncludeContent bool   `json:"email_include_content"`
	StoreSubmissions    bool   `json:"store_submissions"`
	RetentionDays       int32  `json:"retention_days"`
	AcceptAttachments   bool   `json:"accept_attachments"`
	Captcha             bool   `json:"captcha"`
	NotificationLang    string `json:"notification_lang"`
	RedirectURL         string `json:"redirect_url"`
}

func (a *App) submitURL() string {
	return strings.TrimRight(a.Cfg.BaseURL, "/") + "/submit"
}

func (a *App) apiForm(f database.Form) apiForm {
	return apiForm{
		ID: f.ID.String(), Name: f.Name, Active: f.Active,
		AccessKey: f.AccessKey, SubmitURL: a.submitURL(),
		NotifyEmail: f.NotifyEmail, EmailIncludeContent: f.EmailIncludeContent,
		StoreSubmissions: f.StoreSubmissions, RetentionDays: f.RetentionDays,
		AcceptAttachments: f.AcceptAttachments, Captcha: f.Captcha,
		NotificationLang: f.NotificationLang, RedirectURL: deref(f.RedirectUrl),
	}
}

// Its domains list where a form may be submitted from.
func (a *App) APISite(w http.ResponseWriter, r *http.Request) {
	tok := apiToken(r)
	writeAPIJSON(w, http.StatusOK, apiSite{ID: tok.SiteID.String(), Name: tok.SiteName, Domains: tok.SiteDomains})
}

func (a *App) APIListForms(w http.ResponseWriter, r *http.Request) {
	forms, err := a.Q.ListFormsOfSite(r.Context(), apiToken(r).SiteID)
	if err != nil {
		log.Printf("ERROR api: liste des formulaires: %v", err)
		writeAPIError(w, http.StatusInternalServerError, tr(r, "common.err.load"))
		return
	}
	out := make([]apiForm, 0, len(forms))
	for _, f := range forms {
		out = append(out, a.apiForm(f))
	}
	writeAPIJSON(w, http.StatusOK, map[string][]apiForm{"forms": out})
}

// apiFormInput accepts neither recipients nor alert channels: a token does not choose
// where submissions go, otherwise it could be used to write to anyone through the mail
// server. Notifications go to the token's creator.
type apiFormInput struct {
	Name                string `json:"name"`
	NotifyEmail         bool   `json:"notify_email"`
	EmailIncludeContent bool   `json:"email_include_content"`
	StoreSubmissions    bool   `json:"store_submissions"`
	RetentionDays       int    `json:"retention_days"`
	AcceptAttachments   bool   `json:"accept_attachments"`
	Captcha             bool   `json:"captcha"`
	NotificationLang    string `json:"notification_lang"`
	RedirectURL         string `json:"redirect_url"`
}

type apiCreatedForm struct {
	apiForm
	HTML string `json:"html"`
}

// decodeError maps a JSON decoder error to a status and message. The decoder's text is
// not returned: it names the server's internal types.
func decodeError(r *http.Request, err error) (int, string) {
	var tooLarge *http.MaxBytesError
	var badType *json.UnmarshalTypeError
	switch {
	case errors.As(err, &tooLarge):
		return http.StatusRequestEntityTooLarge, tr(r, "api.err.too_large")
	case errors.As(err, &badType) && badType.Field != "":
		return http.StatusBadRequest, tr(r, "api.err.json_type", badType.Field)
	}
	// encoding/json has no error type for an unknown field.
	if field, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
		return http.StatusBadRequest, tr(r, "api.err.json_field", field)
	}
	return http.StatusBadRequest, tr(r, "api.err.json")
}

// APICreateForm creates a form. A missing field takes the value used by the creation
// page, except the notification language, which is set in the body and defaults to French.
func (a *App) APICreateForm(w http.ResponseWriter, r *http.Request) {
	tok := apiToken(r)
	in := apiFormInput{
		NotifyEmail: a.Mailer != nil, EmailIncludeContent: true,
		StoreSubmissions: true, RetentionDays: defaultRetentionDays,
		NotificationLang: string(i18n.DefaultLocale),
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(&in)
	if err == nil {
		// Only one object is accepted: anything after it would be ignored without the caller knowing.
		if _, extra := dec.Token(); extra != io.EOF {
			err = errors.New("données après l'objet JSON")
		}
	}
	if err != nil {
		status, msg := decodeError(r, err)
		writeAPIError(w, status, msg)
		return
	}
	s, errMsg := a.validateFormSettings(r, ui.FormValues{
		Name: strings.TrimSpace(in.Name), Active: true,
		NotifyEmail: in.NotifyEmail, Recipients: tok.UserEmail,
		IncludeContent: in.EmailIncludeContent, Store: in.StoreSubmissions,
		RetentionDays: strconv.Itoa(in.RetentionDays), Attachments: in.AcceptAttachments, Captcha: in.Captcha,
		RedirectURL: strings.TrimSpace(in.RedirectURL), NotificationLang: in.NotificationLang,
	}, tok.SiteDomains)
	if errMsg != "" {
		writeAPIError(w, http.StatusBadRequest, errMsg)
		return
	}
	n, err := a.Q.CountFormsBySite(r.Context(), tok.SiteID)
	if err != nil {
		log.Printf("ERROR api: comptage des formulaires: %v", err)
		writeAPIError(w, http.StatusInternalServerError, tr(r, "form.err.create_failed"))
		return
	}
	if n >= maxAPIForms {
		writeAPIError(w, http.StatusConflict, tr(r, "api.err.too_many_forms", maxAPIForms))
		return
	}
	form, err := a.createForm(r, tok.UserID, tok.SiteID, s, tok.ID)
	if err != nil {
		log.Printf("ERROR api: création du formulaire: %v", err)
		writeAPIError(w, http.StatusInternalServerError, tr(r, "form.err.create_failed"))
		return
	}
	writeAPIJSON(w, http.StatusCreated, apiCreatedForm{
		apiForm: a.apiForm(form),
		HTML:    ui.HTMLSnippet(r.Context(), a.submitURL(), form.AccessKey, form.AcceptAttachments, form.Captcha),
	})
}
