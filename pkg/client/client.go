package client

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tesseract/internal/client"
	"github.com/transparency-dev/tesseract/internal/staticct"
)

// Alias
type S3Fetcher = client.S3Fetcher
type Monitor = client.Monitor
type EntryBundleFetcherFunc = client.EntryBundleFetcherFunc

func NewS3Fetcher(s3Client *s3.Client, bucket string, decompress bool) *client.S3Fetcher {
	return client.NewS3Fetcher(s3Client, bucket, decompress)
}

func GetEntryBundle(ctx context.Context, f client.EntryBundleFetcherFunc, i, logSize uint64) (staticct.EntryBundle, error) {
	return client.GetEntryBundle(ctx, f, i, logSize)
}

func ProcessBundle(
	ctx context.Context, 
	f *client.S3Fetcher, 
	mon *client.Monitor, 
	bIdx uint64, 
	cp *log.Checkpoint, 
	target string, 
	startIdx, 
	endIdx uint64,
) error {
	// Passiamo tutto all'internal senza cambiare nulla
	return client.ProcessBundle(ctx, f, mon, bIdx, cp, target, startIdx, endIdx)
}

func ExtractDomains(certBytes []byte) []string {
	return client.ExtractDomains(certBytes)
}