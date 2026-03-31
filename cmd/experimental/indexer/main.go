package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	tlog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tesseract/internal/client"
	"github.com/transparency-dev/tesseract/internal/types/staticct"
	"golang.org/x/net/publicsuffix"
)

var (
	bucket    = flag.String("bucket", "", "S3 bucket name")
	tableName = flag.String("table", "CertIndex", "DynamoDB table name")
	batchSize = flag.Int("batch_size", 10, "Number of tiles to process")
	interval  = flag.Duration("interval", 1*time.Hour, "Scan interval")
)

// Helper to extract domains from certificates
func getDomains(entry staticct.Entry) []string {
	var rawCert = entry.Certificate
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil && entry.IsPrecert {
		fake := struct {
			TBSCert asn1.RawValue
			Alg     pkix.AlgorithmIdentifier
			Sig     asn1.BitString
		}{
			TBSCert: asn1.RawValue{FullBytes: rawCert},
			Alg:     pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}},
		}
		fakeDER, _ := asn1.Marshal(fake)
		cert, _ = x509.ParseCertificate(fakeDER)
	}
	if cert == nil { return nil }

	unique := make(map[string]struct{})
	if cert.Subject.CommonName != "" { unique[strings.ToLower(cert.Subject.CommonName)] = struct{}{} }
	for _, dns := range cert.DNSNames { unique[strings.ToLower(dns)] = struct{}{} }
	
	var res []string
	for d := range unique { res = append(res, d) }
	return res
}

func getLastIndex(ctx context.Context, dyClient *dynamodb.Client, table string) uint64 {
	out, err := dyClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			"domain_name": &types.AttributeValueMemberS{Value: "__INTERNAL_STATE__"},
			"cert_index":  &types.AttributeValueMemberN{Value: "0"},
		},
	})
	if err != nil || out.Item == nil { return 0 }
	var state struct { LastIndex uint64 `dynamodbav:"last_index"` }
	attributevalue.UnmarshalMap(out.Item, &state)
	return state.LastIndex
}

func saveLastIndex(ctx context.Context, dyClient *dynamodb.Client, table string, idx uint64) {
	dyClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(table),
		Item: map[string]types.AttributeValue{
			"domain_name": &types.AttributeValueMemberS{Value: "__INTERNAL_STATE__"},
			"cert_index":  &types.AttributeValueMemberN{Value: "0"},
			"last_index":   &types.AttributeValueMemberN{Value: strconv.FormatUint(idx, 10)},
		},
	})
}

func main() {
	flag.Parse()
	ctx := context.Background()
	cfg, _ := config.LoadDefaultConfig(ctx)
	s3Client := s3.NewFromConfig(cfg)
	dyClient := dynamodb.NewFromConfig(cfg)
	fetcher := client.NewS3Fetcher(s3Client, *bucket, false)

	for {
		checkpointRaw, _ := fetcher.ReadCheckpoint(ctx)
		var cp tlog.Checkpoint
		cp.Unmarshal(checkpointRaw)

		lastIdx := getLastIndex(ctx, dyClient, *tableName)
		domainMap := make(map[string][]uint64)
		tilesCount := 0

		log.Printf("Start indexing from: %d", lastIdx)

		for i := lastIdx / 256; i <= (cp.Size-1)/256; i++ {
			bundle, err := client.GetEntryBundle(ctx, fetcher.ReadEntryBundle, i, cp.Size)
			if err != nil { continue }

			for j, raw := range bundle.Entries {
				var entry staticct.Entry
				entry.UnmarshalText(raw)
				globalIdx := (i * 256) + uint64(j)
				
				domains := getDomains(entry)
				unique := make(map[string]struct{})
				for _, d := range domains {
					d = strings.TrimPrefix(d, "*.")
					if d == "" { continue }
					unique[d] = struct{}{}
					root, _ := publicsuffix.EffectiveTLDPlusOne(d)
					if root != "" { unique[root] = struct{}{} }
				}
				for d := range unique { domainMap[d] = append(domainMap[d], globalIdx) }
				lastIdx = globalIdx
			}

			tilesCount++
			if tilesCount >= *batchSize {
				flush(ctx, dyClient, *tableName, domainMap, lastIdx)
				log.Printf("Indexed up to tile %d", i)
				domainMap = make(map[string][]uint64)
				tilesCount = 0
			}
		}
		time.Sleep(*interval)
	}
}

func flush(ctx context.Context, dyClient *dynamodb.Client, table string, data map[string][]uint64, lastIdx uint64) {
	var reqs []types.WriteRequest
	for domain, indices := range data {
		tld, _ := publicsuffix.PublicSuffix(domain)
		root := strings.TrimSuffix(domain, "."+tld)
		if root == "" { root = domain }

		for _, idx := range indices {
			reqs = append(reqs, types.WriteRequest{
				PutRequest: &types.PutRequest{
					Item: map[string]types.AttributeValue{
						"domain_name": &types.AttributeValueMemberS{Value: domain},
						"cert_index":  &types.AttributeValueMemberN{Value: strconv.FormatUint(idx, 10)},
						"root_name":   &types.AttributeValueMemberS{Value: root},
					},
				},
			})
			if len(reqs) == 25 {
				dyClient.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{RequestItems: map[string][]types.WriteRequest{table: reqs}})
				reqs = []types.WriteRequest{}
			}
		}
	}
	if len(reqs) > 0 {
		dyClient.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{RequestItems: map[string][]types.WriteRequest{table: reqs}})
	}
	saveLastIndex(ctx, dyClient, table, lastIdx)
}