package qdrant

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"

	qd "github.com/qdrant/go-client/qdrant"
)

// Store wraps the Qdrant client for a single collection.
type Store struct {
	client     *qd.Client
	collection string
}

// SearchResult is a single nearest-neighbour hit.
type SearchResult struct {
	ID      string
	Score   float32
	Payload map[string]any
}

// New dials the Qdrant gRPC endpoint (host:port) and returns a Store.
func New(addr, collection string) (*Store, error) {
	host, port, err := splitAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("qdrant addr: %w", err)
	}

	client, err := qd.NewClient(&qd.Config{
		Host: host,
		Port: port,
	})
	if err != nil {
		return nil, fmt.Errorf("qdrant NewClient: %w", err)
	}
	return &Store{client: client, collection: collection}, nil
}

// EnsureCollection creates the collection if it does not already exist.
// dims must match the embedding model output (768 for nomic-embed-text).
func (s *Store) EnsureCollection(ctx context.Context, dims uint64) error {
	err := s.client.CreateCollection(ctx, &qd.CreateCollection{
		CollectionName: s.collection,
		VectorsConfig: qd.NewVectorsConfig(&qd.VectorParams{
			Size:     dims,
			Distance: qd.Distance_Cosine,
		}),
	})
	if err != nil {
		// Swallow "already exists" so this is idempotent on restarts.
		if strings.Contains(err.Error(), "already exists") {
			return nil
		}
		return fmt.Errorf("EnsureCollection: %w", err)
	}

	// Keyword indexes for hybrid filtering (errors here are non-fatal).
	for _, field := range []string{"severity", "attack_type"} {
		_, _ = s.client.CreateFieldIndex(ctx, &qd.CreateFieldIndexCollection{
			CollectionName: s.collection,
			FieldName:      field,
			FieldType:      qd.FieldType_FieldTypeKeyword.Enum(),
		})
	}
	return nil
}

// Upsert stores a vector + payload under a deterministic ID derived from the string id.
func (s *Store) Upsert(ctx context.Context, id string, vector []float32, payload map[string]any) error {
	h := fnv.New64a()
	h.Write([]byte(id))
	pointID := qd.NewIDNum(h.Sum64())

	qPayload, err := qd.TryValueMap(payload)
	if err != nil {
		return fmt.Errorf("Upsert build payload: %w", err)
	}

	// Wait for the write to be applied: without it the point is indexed
	// asynchronously and an immediate search can miss it.
	_, err = s.client.Upsert(ctx, &qd.UpsertPoints{
		CollectionName: s.collection,
		Wait:           qd.PtrOf(true),
		Points: []*qd.PointStruct{{
			Id:      pointID,
			Vectors: qd.NewVectors(vector...),
			Payload: qPayload,
		}},
	})
	if err != nil {
		return fmt.Errorf("Upsert: %w", err)
	}
	return nil
}

// Search finds the topK nearest neighbours of queryVector.
// An optional Qdrant filter can restrict results by payload fields.
func (s *Store) Search(ctx context.Context, queryVector []float32, topK uint64, filter *qd.Filter) ([]SearchResult, error) {
	req := &qd.QueryPoints{
		CollectionName: s.collection,
		Query:          qd.NewQuery(queryVector...),
		Limit:          &topK,
		WithPayload:    qd.NewWithPayload(true),
	}
	if filter != nil {
		req.Filter = filter
	}

	resp, err := s.client.Query(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("Search: %w", err)
	}

	results := make([]SearchResult, 0, len(resp))
	for _, pt := range resp {
		payload := make(map[string]any, len(pt.Payload))
		for k, v := range pt.Payload {
			payload[k] = extractValue(v)
		}
		results = append(results, SearchResult{
			ID:      fmt.Sprintf("%v", pt.Id),
			Score:   pt.Score,
			Payload: payload,
		})
	}
	return results, nil
}

// extractValue converts a Qdrant Value to a plain Go value for JSON encoding.
func extractValue(v *qd.Value) any {
	if v == nil {
		return nil
	}
	switch k := v.Kind.(type) {
	case *qd.Value_StringValue:
		return k.StringValue
	case *qd.Value_IntegerValue:
		return k.IntegerValue
	case *qd.Value_DoubleValue:
		return k.DoubleValue
	case *qd.Value_BoolValue:
		return k.BoolValue
	default:
		return nil
	}
}

func splitAddr(addr string) (string, int, error) {
	var host string
	var port int
	if _, err := fmt.Sscanf(addr, "%s", &addr); err != nil {
		return "", 0, err
	}
	// Split host:port
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, 6334, nil
	}
	host = addr[:idx]
	if _, err := fmt.Sscanf(addr[idx+1:], "%d", &port); err != nil {
		return "", 0, fmt.Errorf("invalid port in %q: %w", addr, err)
	}
	return host, port, nil
}
