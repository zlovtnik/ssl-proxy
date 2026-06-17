package search

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/embed"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/metrics"
	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

type Service struct {
	searchv1.UnimplementedSearchServiceServer

	Pool                  *pgxpool.Pool
	Embedder              embed.Client
	Config                config.Config
	Metrics               *metrics.Metrics
	Logger                zerolog.Logger
	SuggCache             SuggestCache
	suggMu                sync.Mutex
	graphCache            sync.Map
	graphCacheJanitorOnce sync.Once
}

func NewService(pool *pgxpool.Pool, embedder embed.Client, cfg config.Config, m *metrics.Metrics, logger zerolog.Logger) *Service {
	s := &Service{Pool: pool, Embedder: embedder, Config: cfg, Metrics: m, Logger: logger}
	s.startGraphCacheJanitor()
	return s
}

func (s *Service) Search(ctx context.Context, req *searchv1.SearchRequest) (*searchv1.SearchResponse, error) {
	started := time.Now()
	if req == nil {
		return nil, errors.New("request is required")
	}
	wildcardAll := isWildcardAllSearch(req.Query)
	if !wildcardAll && !hasMeaningfulSearchTerms(req.Query) {
		return nil, errors.New("search query is required and must contain meaningful terms")
	}
	query := req.Query
	topK := config.ClampTopK(req.TopK)
	mode := normalizeMode(req.Mode)
	if wildcardAll {
		mode = searchv1.SearchMode_SEARCH_MODE_SPARSE
	}
	kinds, err := requestKinds(req.Kind)
	if err != nil {
		return nil, err
	}
	searchCtx, cancel := context.WithTimeout(ctx, s.Config.SearchTimeout)
	defer cancel()

	opts := Options{TopK: topK, MinSimilarity: req.MinSimilarity, Kinds: kinds, Filters: req.Filters}
	var denseResults, sparseResults []RawResult
	var qvec []float32
	var modeUsed = mode
	var fallbackReason string

	if mode == searchv1.SearchMode_SEARCH_MODE_DENSE || mode == searchv1.SearchMode_SEARCH_MODE_HYBRID {
		kindForQuery := embed.Kind(kinds[0])
		text := BuildQueryText(query, kinds[0])
		vectors, err := s.Embedder.Embed(searchCtx, []string{text}, kindForQuery)
		if err != nil {
			if mode == searchv1.SearchMode_SEARCH_MODE_DENSE {
				return nil, err
			}
			modeUsed = searchv1.SearchMode_SEARCH_MODE_SPARSE
			fallbackReason = err.Error()
		} else if len(vectors) > 0 {
			qvec = vectors[0]
			denseResults, err = Dense(searchCtx, s.Pool, qvec, s.Config.EmbeddingModel, opts)
			if err != nil {
				if mode == searchv1.SearchMode_SEARCH_MODE_DENSE {
					return nil, err
				}
				modeUsed = searchv1.SearchMode_SEARCH_MODE_SPARSE
				fallbackReason = err.Error()
			}
		}
	}
	if mode == searchv1.SearchMode_SEARCH_MODE_SPARSE || mode == searchv1.SearchMode_SEARCH_MODE_HYBRID || modeUsed == searchv1.SearchMode_SEARCH_MODE_SPARSE {
		sparseResults, err = Sparse(searchCtx, s.Pool, query, opts)
		if err != nil {
			return nil, err
		}
	}

	var fused []RawResult
	switch modeUsed {
	case searchv1.SearchMode_SEARCH_MODE_DENSE:
		fused = denseResults
	case searchv1.SearchMode_SEARCH_MODE_SPARSE:
		fused = sparseResults
	default:
		fused = Fuse(denseResults, sparseResults, rerankCandidateLimit(topK), s.Config.HybridAlpha)
	}
	fused, err = ApplyThreatBoosts(searchCtx, s.Pool, fused)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(fused, func(i, j int) bool {
		if fused[i].Score == fused[j].Score {
			return fused[i].SourceKey < fused[j].SourceKey
		}
		return fused[i].Score > fused[j].Score
	})
	if len(fused) > topK {
		fused = fused[:topK]
	}

	if tokens := ExtractSequenceTokens(query); len(tokens) > 1 {
		sequenceScore, err := ScoreSequence(searchCtx, s.Pool, tokens)
		if err == nil {
			for i := range fused {
				fused[i].SequenceLogProb = sequenceScore
			}
		}
	}

	resultKeys := make([]string, 0, len(fused))
	for _, result := range fused {
		resultKeys = append(resultKeys, result.SourceKey)
	}
	queryID, logErr := LogQuery(searchCtx, s.Pool, query, responseKind(req.Kind), qvec, topK, resultKeys, req.SessionId, time.Since(started).Milliseconds())
	if logErr != nil {
		s.Logger.Warn().Err(logErr).Msg("search query logging failed")
	}

	resp := &searchv1.SearchResponse{
		QueryId:           queryID,
		ModeUsed:          modeUsed,
		FallbackReason:    fallbackReason,
		DenseResultCount:  int32(len(denseResults)),
		SparseResultCount: int32(len(sparseResults)),
		FusedResultCount:  int32(len(fused)),
		Results:           make([]*searchv1.SearchResult, 0, len(fused)),
	}
	for _, result := range fused {
		resp.Results = append(resp.Results, toProtoResult(result))
	}
	if s.Metrics != nil {
		s.Metrics.ObserveSearch(responseKind(req.Kind), modeName(modeUsed), "ok", started, len(resp.Results))
	}
	return resp, nil
}

func (s *Service) SearchStream(req *searchv1.SearchRequest, stream searchv1.SearchService_SearchStreamServer) error {
	resp, err := s.Search(stream.Context(), req)
	if err != nil {
		return err
	}
	for _, result := range resp.Results {
		if err := stream.Send(result); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Explain(ctx context.Context, req *searchv1.ExplainRequest) (*searchv1.ExplainResponse, error) {
	if req == nil || req.SourceKey == "" {
		return nil, errors.New("source_key is required")
	}
	searchReq := &searchv1.SearchRequest{
		Query: req.Query,
		Kind:  req.Kind,
		Mode:  searchv1.SearchMode_SEARCH_MODE_HYBRID,
		TopK:  50,
	}
	resp, err := s.Search(ctx, searchReq)
	if err != nil {
		return nil, err
	}
	for _, result := range resp.Results {
		if result.SourceKey == req.SourceKey {
			return &searchv1.ExplainResponse{
				SourceKey:       result.SourceKey,
				DenseScore:      result.CosineSimilarity,
				SparseScore:     result.KeywordRank,
				FusedScore:      result.Score - result.ThreatBoost,
				ThreatBoost:     result.ThreatBoost,
				BoostReasons:    result.BoostReasons,
				SequenceLogProb: result.SequenceLogProb,
			}, nil
		}
	}
	return &searchv1.ExplainResponse{SourceKey: req.SourceKey}, nil
}

func (s *Service) SuggestFilters(ctx context.Context, req *searchv1.SuggestFiltersRequest) (*searchv1.SuggestFiltersResponse, error) {
	prefix := ""
	if req != nil {
		prefix = req.Prefix
	}
	s.suggMu.Lock()
	if time.Now().Before(s.SuggCache.ExpiresAt) && s.SuggCache.Response != nil && prefix == "" {
		resp := s.SuggCache.Response
		s.suggMu.Unlock()
		return resp, nil
	}
	s.suggMu.Unlock()
	resp, err := SuggestFilters(ctx, s.Pool, prefix)
	if err != nil {
		return nil, err
	}
	if prefix == "" {
		s.suggMu.Lock()
		s.SuggCache = SuggestCache{ExpiresAt: time.Now().Add(30 * time.Second), Response: resp}
		s.suggMu.Unlock()
	}
	return resp, nil
}

func (s *Service) startGraphCacheJanitor() {
	if graphCacheTTL <= 0 {
		return
	}
	s.graphCacheJanitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(graphCacheTTL)
			defer ticker.Stop()
			for range ticker.C {
				s.pruneExpiredGraphCache(time.Now())
			}
		}()
	})
}

func (s *Service) pruneExpiredGraphCache(now time.Time) {
	s.graphCache.Range(func(key, value any) bool {
		entry, ok := value.(graphCacheEntry)
		if !ok {
			s.graphCache.Delete(key)
			return true
		}
		if !now.Before(entry.expiresAt) {
			s.graphCache.Delete(key)
		}
		return true
	})
}

func requestKinds(kind searchv1.SearchKind) ([]string, error) {
	switch kind {
	case searchv1.SearchKind_SEARCH_KIND_UNSPECIFIED, searchv1.SearchKind_SEARCH_KIND_EVENT:
		return []string{"event"}, nil
	case searchv1.SearchKind_SEARCH_KIND_BEHAVIOUR:
		return []string{"behaviour_window"}, nil
	case searchv1.SearchKind_SEARCH_KIND_SEQUENCE:
		return []string{"frame_sequence"}, nil
	case searchv1.SearchKind_SEARCH_KIND_DEVICE:
		return []string{"device"}, nil
	case searchv1.SearchKind_SEARCH_KIND_CROSS:
		return config.SupportedDBKinds(), nil
	default:
		return nil, errors.New("unsupported search kind")
	}
}

func normalizeMode(mode searchv1.SearchMode) searchv1.SearchMode {
	if mode == searchv1.SearchMode_SEARCH_MODE_UNSPECIFIED {
		return searchv1.SearchMode_SEARCH_MODE_HYBRID
	}
	return mode
}

func hasMeaningfulSearchTerms(query string) bool {
	return strings.Trim(query, " \t\n\r*%") != ""
}

func isWildcardAllSearch(query string) bool {
	trimmed := strings.TrimSpace(query)
	return trimmed != "" && strings.Trim(trimmed, "*% \t\n\r") == ""
}

func responseKind(kind searchv1.SearchKind) string {
	switch kind {
	case searchv1.SearchKind_SEARCH_KIND_BEHAVIOUR:
		return "behaviour_window"
	case searchv1.SearchKind_SEARCH_KIND_SEQUENCE:
		return "frame_sequence"
	case searchv1.SearchKind_SEARCH_KIND_DEVICE:
		return "device"
	case searchv1.SearchKind_SEARCH_KIND_CROSS:
		return "cross"
	default:
		return "event"
	}
}

func modeName(mode searchv1.SearchMode) string {
	switch mode {
	case searchv1.SearchMode_SEARCH_MODE_DENSE:
		return "dense"
	case searchv1.SearchMode_SEARCH_MODE_SPARSE:
		return "sparse"
	case searchv1.SearchMode_SEARCH_MODE_HYBRID:
		return "hybrid"
	default:
		return "unspecified"
	}
}

func toProtoResult(result RawResult) *searchv1.SearchResult {
	out := &searchv1.SearchResult{
		SourceKey:        result.SourceKey,
		SourceTable:      result.SourceTable,
		SourceMac:        result.SourceMAC,
		LocationId:       result.LocationID,
		SensorId:         result.SensorID,
		Score:            result.Score,
		CosineSimilarity: result.CosineSimilarity,
		KeywordRank:      result.KeywordRank,
		ThreatBoost:      result.ThreatBoost,
		Tags:             result.Tags,
		SourceKind:       result.SourceKind,
		Bssid:            result.BSSID,
		Ssid:             result.SSID,
		FrameSubtype:     result.FrameSubtype,
		SequenceLogProb:  result.SequenceLogProb,
		BoostReasons:     result.BoostReasons,
		DetailJson:       result.DetailJSON,
		Highlights:       map[string]string{},
	}
	if result.ObservedAt != nil {
		out.ObservedAt = timestamppb.New(*result.ObservedAt)
	}
	return out
}
