package search

import (
	"time"

	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

type RawResult struct {
	SourceKey        string
	SourceTable      string
	SourceKind       string
	SourceMAC        string
	LocationID       string
	SensorID         string
	ObservedAt       *time.Time
	BSSID            string
	SSID             string
	FrameSubtype     string
	CosineSimilarity float32
	KeywordRank      float32
	Score            float32
	ThreatBoost      float32
	SequenceLogProb  float64
	BoostReasons     []string
	Tags             []string
	DetailJSON       string
}

type Options struct {
	TopK          int
	MinSimilarity float32
	Kinds         []string
	Filters       *searchv1.SearchFilters
}

const rrfK = 60.0
