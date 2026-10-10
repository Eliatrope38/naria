package handlers

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"gitlab.com/detag_inno/naria/internal/database"
	"gitlab.com/detag_inno/naria/internal/web"
)

const (
	// Each export holds a file in memory until its reader has received it, hence a cap on
	// their number across all accounts.
	maxExports = 2
	// A reader that barely reads does not hold its slot forever.
	exportTimeout = 30 * time.Minute
	// With the number prefixed, a 255-byte name would exceed the file system limit.
	maxZipName = 200
)

type exportLine struct {
	id     uuid.UUID
	at     time.Time
	values map[string]string
}

// exportLines decrypts the submissions. The columns are the union of the fields, in
// order of first appearance. An unreadable submission is dropped.
func (a *App) exportLines(list []database.Submission) (columns []string, lines []exportLine) {
	columns = []string{}
	seen := map[string]bool{}
	lines = make([]exportLine, 0, len(list))
	for _, sub := range list {
		fields, readable := a.decodeSubmission(sub)
		if !readable {
			continue
		}
		l := exportLine{id: sub.ID, at: sub.CreatedAt, values: make(map[string]string, len(fields))}
		for _, f := range fields {
			if !seen[f.Name] {
				seen[f.Name] = true
				columns = append(columns, f.Name)
			}
			l.values[f.Name] = f.Value
		}
		lines = append(lines, l)
	}
	return columns, lines
}

// writeCSV writes the submissions. If folders is not nil, a folder column follows
// the date, at a fixed position: a visitor field cannot take it.
func writeCSV(w io.Writer, r *http.Request, columns []string, lines []exportLine, folders map[uuid.UUID]string) error {
	if _, err := w.Write([]byte("\xEF\xBB\xBF")); err != nil { // BOM: Excel then reads the UTF-8 correctly
		return err
	}
	cw := csv.NewWriter(w)
	header := make([]string, 0, len(columns)+2)
	header = append(header, tr(r, "submission.col.received"))
	if folders != nil {
		header = append(header, tr(r, "export.folder_col"))
	}
	for _, c := range columns {
		header = append(header, csvCell(c))
	}
	_ = cw.Write(header)
	for _, l := range lines {
		rec := make([]string, 0, len(columns)+2)
		rec = append(rec, l.at.UTC().Format(time.RFC3339))
		if folders != nil {
			rec = append(rec, folders[l.id])
		}
		for _, c := range columns {
			rec = append(rec, csvCell(l.values[c]))
		}
		_ = cw.Write(rec)
	}
	cw.Flush()
	return cw.Error()
}

// csvCell neutralizes formula injection: the content comes from anonymous visitors,
// and a spreadsheet would run a cell starting with =, +, - or @.
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// zipEntryName names an attached file. The name comes from a visitor: without path
// separators, nothing is written outside the folder on extraction. Characters refused
// by Windows, trailing dots or spaces and overly long names are fixed, otherwise
// extraction fails. The number prefix tells apart two files with the same name.
func zipEntryName(position int16, name string) string {
	name = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '<', '>', '"', '|', '?', '*':
			return '_'
		}
		return r
	}, name)
	name = strconv.Itoa(int(position)+1) + "-" + strings.TrimRight(name, ". ")
	if len(name) <= maxZipName {
		return name
	}
	// The extension is kept, unless it makes up the whole name.
	ext := path.Ext(name)
	if len(ext) > 16 {
		ext = ""
	}
	cut := maxZipName - len(ext)
	for !utf8.RuneStart(name[cut]) {
		cut--
	}
	return strings.TrimRight(name[:cut], ". ") + ext
}

func (a *App) ExportCSV(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	form, ok := a.formFor(w, r)
	if !ok {
		return
	}
	list, err := a.Q.ListAllSubmissionsByForm(r.Context(), form.ID)
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	columns, lines := a.exportLines(list)
	// Data leaving the instance is audited (without its content).
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditSubmissionsExported,
		Entity:   auditEntityForm,
		EntityID: refUUID(form.ID),
		Meta:     map[string]string{"name": form.Name, "ip": web.ClientIP(r)},
	})

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="naria-`+form.ID.String()+`.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	if err := writeCSV(w, r, columns, lines, nil); err != nil {
		log.Printf("ERROR export CSV formulaire=%s: %v", form.ID, err)
	}
}

// attachmentData reads and decrypts an attachment within the requester's scope.
// ok is false if it is missing: deleted, out of scope, or undecryptable.
// An error means the database did not respond.
func (a *App) attachmentData(ctx context.Context, id uuid.UUID, isAdmin bool, viewer uuid.UUID) (data []byte, ok bool, err error) {
	row, err := a.Q.GetAttachmentScoped(ctx, database.GetAttachmentScopedParams{ID: id, IsAdmin: isAdmin, ViewerID: viewer})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	data, err = a.AttachmentCrypto.DecryptBytes(row.Content)
	if err != nil {
		log.Printf("ERROR export ZIP: pièce jointe illisible id=%s: %v", id, err)
		return nil, false, nil
	}
	return data, true, nil
}

// ExportZIP exports the CSV and one folder per submission carrying files. Files are
// streamed one at a time; submissions are fully decrypted before the first write,
// since the CSV needs all its columns.
func (a *App) ExportZIP(w http.ResponseWriter, r *http.Request) {
	u := web.UserFrom(r.Context())
	form, ok := a.formFor(w, r)
	if !ok {
		return
	}
	if a.exports.Add(1) > maxExports {
		a.exports.Add(-1)
		w.Header().Set("Retry-After", "60")
		http.Error(w, tr(r, "export.err.busy"), http.StatusServiceUnavailable)
		return
	}
	defer a.exports.Add(-1)
	list, err := a.Q.ListAllSubmissionsByForm(r.Context(), form.ID)
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	attachments, err := a.Q.ListAttachmentsByForm(r.Context(), form.ID)
	if err != nil {
		http.Error(w, tr(r, "common.err.load"), http.StatusInternalServerError)
		return
	}
	columns, lines := a.exportLines(list)
	// A submission's folder carries its row number in the CSV. The files
	// of an unreadable submission, absent from the CSV, are not exported.
	rank := make(map[uuid.UUID]int, len(lines))
	for i, l := range lines {
		rank[l.id] = i + 1
	}
	folders := map[uuid.UUID]string{}
	exported := 0
	for _, att := range attachments {
		if n, ok := rank[att.SubmissionID]; ok {
			folders[att.SubmissionID] = fmt.Sprintf("%s/%04d", tr(r, "export.folder"), n)
			exported++
		}
	}
	// The audit entry precedes the send: it counts the files the export is about to
	// output, even if it is interrupted afterwards.
	a.audit(r.Context(), auditEntry{
		ActorID:  refUUID(u.ID),
		Action:   auditSubmissionsExported,
		Entity:   auditEntityForm,
		EntityID: refUUID(form.ID),
		Meta:     map[string]string{"name": form.Name, "ip": web.ClientIP(r), "attachments": strconv.Itoa(exported)},
	})

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="naria-`+form.ID.String()+`.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	rc := http.NewResponseController(w)
	zw := zip.NewWriter(w)
	limit := time.Now().Add(exportTimeout)
	// The server timeout, set for a page, would cut off a large export.
	entry := func(name string, method uint16, modified time.Time) (io.Writer, error) {
		deadline := time.Now().Add(transferTimeout)
		if deadline.After(limit) {
			deadline = limit
		}
		if err := rc.SetWriteDeadline(deadline); err != nil {
			log.Printf("ERROR export ZIP: délai d'écriture non prolongé: %v", err)
		}
		return zw.CreateHeader(&zip.FileHeader{Name: name, Method: method, Modified: modified})
	}
	// abort closes the connection: returning would let the browser save
	// a truncated archive as a successful download.
	abort := func(err error) {
		if r.Context().Err() == nil {
			log.Printf("ERROR export ZIP formulaire=%s: %q", form.ID, err.Error()) // #nosec G706 -- form.ID is a UUID; the error is quoted (%q escapes CR/LF)
		}
		panic(http.ErrAbortHandler)
	}

	f, err := entry(tr(r, "export.csv_name"), zip.Deflate, time.Now())
	if err == nil {
		err = writeCSV(f, r, columns, lines, folders)
	}
	if err != nil {
		abort(err)
	}
	isAdmin, viewer := scope(u)
	var missing []string
	for _, att := range attachments {
		folder, ok := folders[att.SubmissionID]
		if !ok {
			continue
		}
		// A missing file is reported in the archive rather than aborting it.
		name, err := a.AttachmentCrypto.Decrypt(att.Filename)
		if err != nil {
			log.Printf("ERROR export ZIP: nom de pièce jointe illisible id=%s: %v", att.ID, err)
			missing = append(missing, folder+"/"+zipEntryName(att.Position, tr(r, "submission.unreadable")))
			continue
		}
		entryName := folder + "/" + zipEntryName(att.Position, name)
		data, ok, err := a.attachmentData(r.Context(), att.ID, isAdmin, viewer)
		if err != nil {
			abort(err)
		}
		if !ok {
			missing = append(missing, entryName)
			continue
		}
		// No compression: uploaded files (images, PDFs, documents) are
		// mostly already compressed.
		f, err := entry(entryName, zip.Store, lines[rank[att.SubmissionID]-1].at)
		if err == nil {
			_, err = f.Write(data)
		}
		if err != nil {
			abort(err)
		}
	}
	if len(missing) > 0 {
		f, err := entry(tr(r, "export.missing_name"), zip.Deflate, time.Now())
		if err == nil {
			_, err = io.WriteString(f, tr(r, "export.missing_intro")+"\n\n"+strings.Join(missing, "\n")+"\n")
		}
		if err != nil {
			abort(err)
		}
	}
	if err := zw.Close(); err != nil {
		abort(err)
	}
}
