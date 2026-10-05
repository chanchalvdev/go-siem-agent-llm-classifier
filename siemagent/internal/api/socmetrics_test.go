package api

import (
	"net/http"
	"testing"

	"github.com/chverma/siemagent/internal/socmetrics"
)

func TestSOCMetricsEndpoint(t *testing.T) {
	ts, _ := incidentServer(t)
	for _, port := range []string{"1", "2"} {
		classifyLine(t, ts, "sshd[1]: Failed password for root from 203.0.113.7 port "+port+" ssh2")
	}
	classifyLine(t, ts, "sshd[1]: Failed password for admin from 198.51.100.1 port 22 ssh2")

	var r socmetrics.Report
	if code := doJSON(t, http.MethodGet, ts.URL+"/api/soc/metrics?days=7", "", &r); code != http.StatusOK {
		t.Fatalf("metrics: %d", code)
	}
	if r.Days != 7 || len(r.Daily) != 7 || r.IncidentsOpened != 2 || r.OpenNow != 2 || r.UnassignedOpen != 2 {
		t.Fatalf("report: %+v", r)
	}
	if r.EventTotals.Events != 3 || r.EventTotals.Alerts != 3 || r.Daily[6].IncidentsOpened != 2 {
		t.Fatalf("volume: %+v / %+v", r.EventTotals, r.Daily[6])
	}
	if r.TopAttackTypes[0].Name != "Brute Force" || r.TopAttackTypes[0].Count != 2 {
		t.Fatalf("top attack types: %+v", r.TopAttackTypes)
	}

	for _, bad := range []string{"0", "366", "x"} {
		if code := doJSON(t, http.MethodGet, ts.URL+"/api/soc/metrics?days="+bad, "", nil); code != http.StatusBadRequest {
			t.Errorf("days=%s: %d", bad, code)
		}
	}
}
