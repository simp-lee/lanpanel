package ui

import (
	"lanpanel/internal/domain"
	"lanpanel/internal/uistate"
	"net/http"
	"net/url"
	"strings"
)

func secretRevealHTML(server *Server, r *http.Request) string {
	handle := strings.TrimSpace(r.URL.Query().Get("secret"))
	if handle == "" {
		return ""
	}
	sessionFingerprint, ok := server.sessionFingerprintFromRequest(r)
	if !ok {
		return panel("One-Time Secret", `<p class="error">Secret is no longer available.</p>`)
	}
	server.mu.Lock()
	secret, ok := server.secrets[handle]
	if ok && !secret.RevealExpiresAt.IsZero() && server.options.Now().After(secret.RevealExpiresAt) {
		delete(server.secrets, handle)
		ok = false
	}
	if ok && secret.SessionIDFingerprint != sessionFingerprint {
		server.mu.Unlock()
		return panel("One-Time Secret", `<p class="error">Secret is no longer available.</p>`)
	}
	if ok {
		delete(server.secrets, handle)
	}
	server.mu.Unlock()
	if !ok {
		return panel("One-Time Secret", `<p class="error">Secret is no longer available.</p>`)
	}
	body := `<p>` + esc(secret.Label) + ` fingerprint ` + esc(secret.Fingerprint) + `</p>`
	if !secret.ExpiresAt.IsZero() {
		body += `<p>Expires at ` + esc(secret.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")) + `</p>`
	}
	body += `<div class="secret">` + esc(secret.Value) + `</div>`
	return panel("One-Time Secret", body)
}

func jobsHistoryHTML(server *Server, r *http.Request, records []domain.JobRecord) string {
	if len(records) == 0 {
		return panel("History", `<p>No jobs recorded yet.</p>`)
	}
	body := ``
	for _, record := range records {
		summary := record.ResultSummary
		if summary == "" {
			summary = record.ErrorSummary
		}
		detail := kvTableHTML([]kv{
			{"ID", record.ID},
			{"Kind", string(record.Kind)},
			{"Status", string(record.Status)},
			{"Summary", summary},
			{"Checkpoint", string(record.CheckpointRef.Kind) + " " + record.CheckpointRef.Path},
			{"Modified paths", strings.Join(record.ModifiedPaths, ", ")},
			{"Retry command", record.RetryCommand},
			{"Config snapshot", record.ConfigSnapshotRef},
		})
		events, err := server.state.ListEvents(record.ID)
		if err != nil {
			detail += errorBlock(err)
		} else {
			detail += eventsHTML(events)
		}
		if handle, ok := server.secretHandleForJob(r, record.ID); ok {
			detail += `<p><a href="/jobs?secret=` + esc(url.QueryEscape(handle)) + `">Reveal one-time handoff</a></p>`
		}
		body += miniPanel(string(record.Kind)+" "+record.ID, detail)
	}
	return panel("History", body)
}

func (server *Server) secretHandleForJob(r *http.Request, jobID string) (string, bool) {
	sessionFingerprint, ok := server.sessionFingerprintFromRequest(r)
	if !ok {
		return "", false
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	for handle, secret := range server.secrets {
		if !secret.RevealExpiresAt.IsZero() && server.options.Now().After(secret.RevealExpiresAt) {
			delete(server.secrets, handle)
			continue
		}
		if secret.JobID == jobID && secret.SessionIDFingerprint == sessionFingerprint {
			return handle, true
		}
	}
	return "", false
}

func eventsHTML(events []uistate.Event) string {
	if len(events) == 0 {
		return `<p>No events recorded.</p>`
	}
	body := `<table class="data-table events-table"><thead><tr><th class="event-col-at">At</th><th class="event-col-status">Status</th><th>Message</th></tr></thead><tbody>`
	for _, event := range events {
		body += `<tr>` + nowrapCell(event.At.Format("2006-01-02T15:04:05Z07:00")) + `<td class="cell-nowrap">` + statusBadge(string(event.Status)) + `</td>` + summaryCell(event.Message) + `</tr>`
	}
	return tableWrap(body + `</tbody></table>`)
}
