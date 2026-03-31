package main

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"flag"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	tlog "github.com/transparency-dev/formats/log"

	"github.com/transparency-dev/tesseract/internal/client"
	"github.com/transparency-dev/tesseract/internal/types/staticct"
)

var (
	port      = flag.String("port", "8080", "Port to run the API on")
	bucket    = flag.String("bucket", "", "Name of S3 bucket")
	tableName = flag.String("table", "CertIndex", "DynamoDB table name")
	logOrigin = flag.String("log_origin", "", "Origin ID of the CT log")
)

type API struct {
	dyClient       *dynamodb.Client
	fetcher        *client.S3Fetcher
	mu             sync.RWMutex
	logSize        uint64
	tileCache      map[uint64]staticct.EntryBundle
	tileCacheOrder []uint64
	cacheLimit     int
}

type SearchResult struct {
	Domain string `json:"domain_name" dynamodbav:"domain_name"`
	Index  uint64 `json:"cert_index" dynamodbav:"cert_index"`
	Root   string `json:"root_name" dynamodbav:"root_name"`
}

// parseCTCert parses certificates
func parseCTCert(entry staticct.Entry) (*x509.Certificate, error) {
	
	cert, err := x509.ParseCertificate(entry.Certificate)
	if err == nil {
		return cert, nil
	}

	if !entry.IsPrecert {
		return nil, err
	}

	// If entry is a precertificate, it finds the signing algorithm
	var tbsSeq []asn1.RawValue
	if _, err := asn1.Unmarshal(entry.Certificate, &tbsSeq); err != nil {
		return nil, err
	}

	sigAlgIdx := 2
	if len(tbsSeq) > 0 && tbsSeq[0].Tag != 0 {
		sigAlgIdx = 1
	}

	// Create fake wrapper using right algorithm
	fake := struct {
		TBS            asn1.RawValue
		SigAlg         asn1.RawValue
		SignatureValue asn1.BitString
	}{
		TBS:            asn1.RawValue{FullBytes: entry.Certificate},
		SigAlg:         tbsSeq[sigAlgIdx], 
		SignatureValue: asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
	}

	fakeDER, err := asn1.Marshal(fake)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(fakeDER)
}

func (a *API) RefreshLogSize(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	for {
		select {
		case <-ticker.C:
			checkpoint, err := a.fetcher.ReadCheckpoint(ctx)
			if err == nil {
				var cp tlog.Checkpoint
				if _, err := cp.Unmarshal(checkpoint); err == nil {
					a.mu.Lock()
					a.logSize = cp.Size
					a.mu.Unlock()
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func main() {
	flag.Parse()
	if *bucket == "" || *logOrigin == "" {
		log.Fatal("--bucket and --log_origin are required")
	}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("AWS config error: %v", err)
	}

	dyClient := dynamodb.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)
	fetcher := client.NewS3Fetcher(s3Client, *bucket, false)

	checkpoint, _ := fetcher.ReadCheckpoint(ctx)
	var cp tlog.Checkpoint
	cp.Unmarshal(checkpoint)

	api := &API{
		dyClient:       dyClient,
		fetcher:        fetcher,
		logSize:        cp.Size,
		tileCache:      make(map[uint64]staticct.EntryBundle),
		tileCacheOrder: make([]uint64, 0),
		cacheLimit:     200,
	}

	go api.RefreshLogSize(context.Background())

	r := gin.Default()
	r.GET("/v1/search", api.handleSearch)
	r.GET("/v1/certificate/:index", api.handleGetCertificate)

	log.Printf("API listening on port %s...", *port)
	r.Run(":" + *port)
}

func (a *API) handleSearch(c *gin.Context) {
	query := strings.ToLower(strings.TrimSpace(c.Query("q")))
	if len(query) < 3 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Query too short"})
		return
	}

	var results []SearchResult
	var input *dynamodb.QueryInput

	if strings.Contains(query, ".") {
		input = &dynamodb.QueryInput{
			TableName:              aws.String(*tableName),
			KeyConditionExpression: aws.String("domain_name = :d"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":d": &types.AttributeValueMemberS{Value: query},
			},
		}
	} else {
		input = &dynamodb.QueryInput{
			TableName:              aws.String(*tableName),
			IndexName:              aws.String("RootIndex"),
			KeyConditionExpression: aws.String("root_name = :r"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":r": &types.AttributeValueMemberS{Value: query},
			},
		}
	}

	output, err := a.dyClient.Query(c.Request.Context(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	attributevalue.UnmarshalListOfMaps(output.Items, &results)
	if len(results) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "Nothing found"})
		return
	}

	c.JSON(http.StatusOK, results)
}

func (a *API) handleGetCertificate(c *gin.Context) {
	idx, err := strconv.ParseUint(c.Param("index"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Index not valid"})
		return
	}

	tileID := idx / 256
	localIdx := idx % 256

	a.mu.RLock()
	bundle, exists := a.tileCache[tileID]
	logSize := a.logSize
	a.mu.RUnlock()

	if !exists {
		bundle, err = client.GetEntryBundle(c.Request.Context(), a.fetcher.ReadEntryBundle, tileID, logSize)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tile not found"})
			return
		}
		a.mu.Lock()
		if len(a.tileCache) >= a.cacheLimit {
			delete(a.tileCache, a.tileCacheOrder[0])
			a.tileCacheOrder = a.tileCacheOrder[1:]
		}
		a.tileCache[tileID] = bundle
		a.tileCacheOrder = append(a.tileCacheOrder, tileID)
		a.mu.Unlock()
	}

	if localIdx >= uint64(len(bundle.Entries)) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Index out of range"})
		return
	}

	var entry staticct.Entry
	entry.UnmarshalText(bundle.Entries[localIdx])

	cert, err := parseCTCert(entry)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Parse error: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"index":       idx,
		"common_name": cert.Subject.CommonName,
		"issuer":      cert.Issuer.CommonName,
		"not_before":  cert.NotBefore,
		"not_after":   cert.NotAfter,
		"sans":        cert.DNSNames,
		"is_precert":  entry.IsPrecert,
	})
}