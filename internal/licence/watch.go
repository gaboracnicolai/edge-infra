package licence

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	validDesc = prometheus.NewDesc(
		"edge_licence_valid",
		"1 while the installed Talyvor Edge licence is signed by a trusted key and "+
			"unexpired, otherwise 0. Advisory: no traffic depends on it.",
		nil, nil,
	)
	expiryDesc = prometheus.NewDesc(
		"edge_licence_expiry_timestamp_seconds",
		"Unix time the installed Talyvor Edge licence expires; 0 when no trusted "+
			"licence can be read.",
		nil, nil,
	)
)

// Watcher checks the licence installed at a path. It is a Prometheus collector
// (each scrape re-reads the file, so a renewed licence shows at once) and Run
// logs every change of state. It never touches anything that serves traffic.
type Watcher struct {
	path string
	keys []ed25519.PublicKey
	log  *slog.Logger
	now  func() time.Time
	last State // Run's goroutine only
}

func NewWatcher(path string, keys []ed25519.PublicKey, log *slog.Logger) *Watcher {
	return &Watcher{path: path, keys: keys, log: log, now: time.Now}
}

// Status checks the installed licence now.
func (w *Watcher) Status() Status { return CheckFile(w.path, w.keys, w.now()) }

// Run checks at once and then every interval until ctx ends, logging the state
// each time it changes — so a licence that expires while Edge runs is warned
// about within one interval.
func (w *Watcher) Run(ctx context.Context, every time.Duration) {
	w.observe()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.observe()
		}
	}
}

func (w *Watcher) observe() {
	s := w.Status()
	if s.State == w.last {
		return
	}
	w.last = s.State
	switch s.State {
	case Valid:
		w.log.Info("Talyvor Edge licence valid",
			"licensee", s.Licence.Licensee, "plan", s.Licence.Plan, "id", s.Licence.ID,
			"expires_at", s.Licence.ExpiresAt)
	case Expired:
		w.log.Warn("Talyvor Edge licence EXPIRED — traffic is not affected; ask Talyvor to renew it",
			"licensee", s.Licence.Licensee, "plan", s.Licence.Plan, "id", s.Licence.ID,
			"expired_at", s.Licence.ExpiresAt)
	case Missing:
		w.log.Warn("no Talyvor Edge licence installed — traffic is not affected", "path", w.path)
	default:
		w.log.Warn("Talyvor Edge licence not valid — traffic is not affected", "path", w.path, "err", s.Err)
	}
}

func (w *Watcher) Describe(ch chan<- *prometheus.Desc) {
	ch <- validDesc
	ch <- expiryDesc
}

func (w *Watcher) Collect(ch chan<- prometheus.Metric) {
	s := w.Status()
	valid, expiry := 0.0, 0.0
	if s.State == Valid {
		valid = 1
	}
	if s.Licence != nil {
		expiry = float64(s.Licence.ExpiresAt.Unix())
	}
	ch <- prometheus.MustNewConstMetric(validDesc, prometheus.GaugeValue, valid)
	ch <- prometheus.MustNewConstMetric(expiryDesc, prometheus.GaugeValue, expiry)
}
