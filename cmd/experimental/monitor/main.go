package main

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"bytes"
	"compress/gzip"

	tlog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tesseract/internal/types/staticct"
	"github.com/transparency-dev/tesseract/internal/client"
	"github.com/transparency-dev/tessera/api/layout"
	tdnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/crypto/cryptobyte"

	"crypto/x509"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

var hasher = rfc6962.DefaultHasher

// CLI flags
var (
	bucket        = flag.String("bucket", "", "Name of the S3 bucket")
	logOrigin     = flag.String("log_origin", "", "Identity of the log (eg. test-static-ct)")
	pubkeySecret  = flag.String("pubkey_secret", "", "AWS Secrets Manager secret ID containing the log public key (base64 DER)")
	leafIndex     = flag.Uint64("leaf_index", 0, "Optional leaf index to verify inclusion for")
	searchDomain  = flag.String("search_domain", "", "Optional domain string to search for in ingested entries")
	startIndex    = flag.Uint64("start_index", 0, "Start index (inclusive) when doing a search")
	endIndex      = flag.Uint64("end_index", 0, "End index (inclusive) when doing a search")
)

// --------------------- Core types -----------------------------

// S3Fetcher implements file fetching from an AWS S3 bucket.
type S3Fetcher struct {
	client *s3.Client
	bucket string
	decompressBundles bool
}

// Monitor monitors a TesseraCT log and can verify proofs
type Monitor struct {
	fetcher *S3Fetcher
	logStateTracker *client.LogStateTracker
	verifier note.Verifier
}

// --------------------- Constructors -----------------------------

// S3 Fetcher constructor
func NewS3Fetcher(s3Client *s3.Client, bucket string, decompress bool) *S3Fetcher {
	return &S3Fetcher{
		client:				s3Client,
		bucket:				bucket,
		decompressBundles:	decompress,
	}
}

// NewMonitor creates a new Monitor for the given log URL
func NewMonitor(ctx context.Context, f *S3Fetcher, verifier note.Verifier, origin string) (*Monitor, error) {
	
	// Create log state tracker
	tracker, err := client.NewLogStateTracker(
		ctx,
		f.ReadCheckpoint,
		f.ReadTile,
		[]byte{},
		verifier,
		origin,
		client.UnilateralConsensus(f.ReadCheckpoint),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create log state tracker: %w", err)
	}

	return &Monitor{
		fetcher:			f,
		logStateTracker: 	&tracker,
		verifier: 			verifier,
	}, nil
}

// --------------------- Monitor Methods -----------------------------

// UpdateCheckpoint fetches the latest checkpoint from the log and verifies consistency.
// Returns the old checkpoint, consistency proof, and new checkpoint.
func (m *Monitor) UpdateCheckpoint(ctx context.Context) ([]byte, [][]byte, []byte, error) {
	oldCP, proof, newCP, err := m.logStateTracker.Update(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to update checkpoint: %w", err)
	}
	return oldCP, proof, newCP, nil
}

// InclusionProof builds an inclusion proof for a leaf at the given index.
// The proof is relative to the current tracked checkpoint.
func (m *Monitor) InclusionProof(ctx context.Context, leafIndex uint64) ([][]byte, error) {
	if m.logStateTracker.ProofBuilder == nil {
		return nil, fmt.Errorf("proof builder not initialized")
	}

	proofNodes, err := m.logStateTracker.ProofBuilder.InclusionProof(ctx, leafIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to build inclusion proof: %w", err)
	}
	return proofNodes, nil
}

// ConsistencyProof builds a consistency proof between two tree sizes.
// If smallerSize is 0, the larger size is used as the target size.
func (m *Monitor) ConsistencyProof(ctx context.Context, smallerSize, largerSize uint64) ([][]byte, error) {
	if m.logStateTracker.ProofBuilder == nil {
		return nil, fmt.Errorf("proof builder not initialized")
	}

	proofNodes, err := m.logStateTracker.ProofBuilder.ConsistencyProof(ctx, smallerSize, largerSize)
	if err != nil {
		return nil, fmt.Errorf("failed to build consistency proof: %w", err)
	}
	return proofNodes, nil
}

// VerifyConsistencyProof verifies a consistency proof between two checkpoints.
func (m *Monitor) VerifyConsistencyProof(
	smallerCP, largerCP *tlog.Checkpoint,
	proofNodes [][]byte,
) error {
	if err := proof.VerifyConsistency(
		hasher,
		smallerCP.Size,
		largerCP.Size,
		proofNodes,
		smallerCP.Hash,
		largerCP.Hash,
	); err != nil {
		return fmt.Errorf("consistency proof verification failed: %w", err)
	}
	return nil
}

// VerifyInclusionProof verifies an inclusion proof for a leaf at the given index.
func (m *Monitor) VerifyInclusionProof(
	leafHash []byte,
	leafIndex uint64,
	cp *tlog.Checkpoint,
	proofNodes [][]byte,
) error {
	if err := proof.VerifyInclusion(
		hasher,
		leafIndex,
		cp.Size,
		leafHash,
		proofNodes,
		cp.Hash,
	); err != nil {
		return fmt.Errorf("inclusion proof verification failed: %w", err)
	}
	return nil
}

// VerifyCheckpointSignature verifies that the checkpoint is properly signed by the log.
// Returns true if signature verification succeeds, false otherwise.
func (m *Monitor) VerifyCheckpointSignature(cp *tlog.Checkpoint, checkpointRaw []byte) (bool, error) {
	cpNote, err := note.Open(checkpointRaw, note.VerifierList(m.verifier))
	if err != nil {
		return false, fmt.Errorf("failed to open signed checkpoint: %w", err)
	}

	// Verify the checkpoint was parsed correctly
	parsedCP, _, _, err := tlog.ParseCheckpoint(checkpointRaw, *logOrigin, m.verifier)
	if err != nil {
		return false, fmt.Errorf("failed to parse checkpoint: %w", err)
	}

	if cpNote == nil || parsedCP == nil {
		return false, fmt.Errorf("checkpoint verification produced nil result")
	}

	return true, nil
}

// GetLatestCheckpoint returns the current tracked checkpoint.
func (m *Monitor) GetLatestCheckpoint() *tlog.Checkpoint {
	return &m.logStateTracker.LatestConsistent
}

// --------------------- Fetcher Methods -----------------------------

// ctEntriesPath builds the path of the log entries
func ctEntriesPath(n uint64, p uint8) string {
	return fmt.Sprintf("tile/data/%s", layout.NWithSuffix(0, n, p))
}

// ReadEntryBundle retrieves a bundle of entries and decompresses it if needed
func (f *S3Fetcher) ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error) {
	path := ctEntriesPath(i, p)
	data, err := f.fetch(ctx, path)
	if err != nil {
		return nil, err
	}

	if f.decompressBundles {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer reader.Close()
		return io.ReadAll(reader)
	}

	return data, nil
}

// Fetch retrieves a file (checkpoint or tile) from S3 using AWS credentials
func (f *S3Fetcher) fetch(ctx context.Context, key string) ([]byte, error) {
	output, err := f.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &f.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from S3 (%s): %w", key, err)
	}
	defer output.Body.Close()
	return io.ReadAll(output.Body)
}

// ReadCheckpoint retrieves the checkpoint from S3
func (f *S3Fetcher) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	return f.fetch(ctx, layout.CheckpointPath)
}

// ReadTile retrieves a tile from S3
func (f *S3Fetcher) ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error) {
	return f.fetch(ctx, layout.TilePath(l, i, p))
}

// --------------------- Business logic -----------------------------

// ToRFC6962Leaf converts a TesseraCT entry to the standard RFC 6962 leaf
func ToRFC6962Leaf(e staticct.Entry) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(0) // Version V1
	b.AddUint8(0) // LeafType: timestamped_entry
	b.AddUint64(e.Timestamp)
	
	if e.IsPrecert {
		b.AddUint16(1) // PrecertLogEntryType
		b.AddBytes(e.IssuerKeyHash)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	} else {
		b.AddUint16(0) // X509LogEntryType
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	}
	// Extensions
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(e.RawExtensions))
	})
	
	return b.BytesOrPanic()
}

// ProcessBundle downloads an entire bundle and looks for the domain
func ProcessBundle(ctx context.Context, f *S3Fetcher, mon *Monitor, bIdx uint64, cp *tlog.Checkpoint, target string, startIdx, endIdx uint64) error {
    // 1. Retrieve the bundles using the GetEntryBundle function provided by client.go
	fmt.Printf("  -> Scanning bundle %d...\n", bIdx)
    bundle, err := client.GetEntryBundle(ctx, f.ReadEntryBundle, bIdx, cp.Size)
    if err != nil {
        return err
    }

	if len(bundle.Entries) == 0 {
        fmt.Printf("  Bundle %d is empty\n", bIdx)
    }

    // 2. Iterate the entries splitted by UnmarshalText provided by staticct.go
    for i, rawEntry := range bundle.Entries {
        globalIdx := (bIdx * 256) + uint64(i)

        // Filter index out of range
        if globalIdx < startIdx || globalIdx > endIdx {
            continue
        }

        // 3. Parsing of entry
        var entry staticct.Entry
        if err := entry.UnmarshalText(rawEntry); err != nil {
            continue 
        }

        // 4. Call of SearchDomainInCert to search the domain in the entry
        if match, matchedName, cert := SearchDomainInCert(entry, target); match {
            fmt.Printf("\n[MATCH] Index %d | CN=%s\n", globalIdx, matchedName)
			if cert != nil {
				fmt.Printf("Subject: %s\n", cert.Subject)
			}

			leafData := ToRFC6962Leaf(entry)
            // 5. Inclusion Proof verify
            nodes, err := mon.InclusionProof(ctx, globalIdx)
            if err != nil {
                fmt.Printf("  Proof error: %v\n", err)
                continue
            }

            // Compute leaf hash
            leafHash := hasher.HashLeaf(leafData)
            
            if err := mon.VerifyInclusionProof(leafHash, globalIdx, cp, nodes); err != nil {
                fmt.Printf("  Inclusion proof FAILED: %v\n", err)
            } else {
                fmt.Printf("  Inclusion proof OK\n")
            }
        }
    }
    return nil
}

// SearchDomainInCert parses the X.509 certificate and search the domain in the CN and in the SANs
func SearchDomainInCert(entry staticct.Entry, target string) (bool, string, *x509.Certificate) {
	target = strings.ToLower(target)
	cert, err := x509.ParseCertificate(entry.Certificate)
	if err != nil {
		if strings.Contains(strings.ToLower(string(entry.Certificate)), target) {
			fmt.Printf("This is a precertificate\n")
			return true, "Pre-cert", nil
		}
		return false, "", nil
	}
	
	// Checks the Common Name
	if strings.Contains(strings.ToLower(cert.Subject.CommonName), target) {
		return true, cert.Subject.CommonName, cert
	}
	// Checks the SANs (Subject Alternative Names)
	for _, dns := range cert.DNSNames {
		if strings.Contains(strings.ToLower(dns), target) {
			return true, dns, cert
		}
	}
	return false, "", nil
}

// --------------------- AWS helpers -----------------------------

// initAWSConfig sets up the default AWS SDK configuration using the
// environment/EC2 instance profile.
func initAWSConfig(ctx context.Context) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx)
}

// getPublicKey fetches the secret value from Secrets Manager and returns
// either the string contents or the binary blob.
func getPublicKey(ctx context.Context, secretID string) ([]byte, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	sm := secretsmanager.NewFromConfig(cfg)
	out, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &secretID})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secret %s: %w", secretID, err)
	}
	if out.SecretString != nil {
		return []byte(*out.SecretString), nil
	}
	return out.SecretBinary, nil
}

// logSigVerifier builds a note.Verifier from an origin string and a public
// key encoded (usually base64 DER) in keyRaw.  This is the same helper used
// in other parts of the codebase.
func logSigVerifier(origin, keyRaw string) (note.Verifier, error) {
	if origin == "" {
		return nil, fmt.Errorf("origin cannot be empty")
	}
	if keyRaw == "" {
		return nil, fmt.Errorf("public key material cannot be empty")
	}

	// The public key material may arrive in several formats:
	//  * raw DER blob
	//  * PEM encoded (text with headers)
	//  * base64-encoded DER
	// First try to handle PEM; if that succeeds we just use the contained
	// bytes. Otherwise fall back to base64 decoding (silently ignoring the
	// error), and finally use the raw input.
	derBytes := []byte(keyRaw)
	if block, _ := pem.Decode(derBytes); block != nil {
		// strip PEM headers
		derBytes = block.Bytes
	} else if decoded, err := base64.StdEncoding.DecodeString(keyRaw); err == nil {
		// successfully base64 decoded, use that instead
		derBytes = decoded
	}
	pub, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	verifierKey, err := tdnote.RFC6962VerifierString(origin, pub)
	if err != nil {
		return nil, fmt.Errorf("error creating verifier string: %w", err)
	}
	return tdnote.NewVerifier(verifierKey)
}

// --------------------- Main function -----------------------------

func main() {
    flag.Parse()
    ctx := context.Background()

    // required flags
    if *bucket == "" || *logOrigin == "" || *pubkeySecret == "" {
        fmt.Fprintln(os.Stderr, "--bucket, --log_origin and --pubkey_secret are required")
        flag.Usage()
        os.Exit(1)
    }

    // initialize AWS config
    cfg, err := initAWSConfig(ctx)
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to init AWS config: %v\n", err)
        os.Exit(1)
    }

    // fetch public key from Secrets Manager
    pubBytes, err := getPublicKey(ctx, *pubkeySecret)
    if err != nil {
        fmt.Fprintf(os.Stderr, "error retrieving public key: %v\n", err)
        os.Exit(1)
    }
    verifier, err := logSigVerifier(*logOrigin, string(pubBytes))
    if err != nil {
        fmt.Fprintf(os.Stderr, "error creating verifier: %v\n", err)
        os.Exit(1)
    }

    // create S3 monitor
    s3Client := s3.NewFromConfig(cfg)
    s3Fetcher := NewS3Fetcher(s3Client, *bucket, false)
    mon, err := NewMonitor(ctx, s3Fetcher, verifier, *logOrigin)
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to create monitor: %v\n", err)
        os.Exit(1)
    }

    // phase 2 sync
	oldCPraw, proof, _, err := mon.UpdateCheckpoint(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update failed: %v\n", err)
		os.Exit(1)
	}
	// parse the new checkpoint so we can inspect fields and pass a typed
	// value to the verification helpers.
	newCP := mon.GetLatestCheckpoint()

	fmt.Printf("new checkpoint size: %d\n", newCP.Size)
	if oldCPraw != nil {
		oldCP, _, _, err := tlog.ParseCheckpoint(oldCPraw, *logOrigin, mon.verifier)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse old checkpoint: %v\n", err)
		} else {
			if err := mon.VerifyConsistencyProof(oldCP, newCP, proof); err != nil {
				fmt.Fprintf(os.Stderr, "consistency proof failed: %v\n", err)
			} else {
				fmt.Println("consistency proof verified")
			}
		}
	}

    if *searchDomain != "" {
        if *endIndex < *startIndex {
            fmt.Fprintln(os.Stderr, "end_index must be >= start_index")
            os.Exit(1)
        } else if *endIndex == 0 {
			*endIndex = newCP.Size - 1
		}
        fmt.Printf("searching domain %q from %d..%d\n", *searchDomain, *startIndex, *endIndex)

        // Compute the range of bundles to check
        // Each bundle has 256 entries
        startBundle := *startIndex / 256
        endBundle := *endIndex / 256

        for bIdx := startBundle; bIdx <= endBundle; bIdx++ {
            err := ProcessBundle(ctx, s3Fetcher, mon, bIdx, newCP, *searchDomain, *startIndex, *endIndex)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Error processing bundle %d: %v\n", bIdx, err)
                continue
            }
        }
		
    }
}
