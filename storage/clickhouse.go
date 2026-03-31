package storage

import (
	"context"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// SaveBatch uploads a batch of indexes and domains in ClickHouse
func SaveBatch(ctx context.Context, conn driver.Conn, data map[string][]uint64) error {
	batch, err := conn.PrepareBatch(ctx, "INSERT INTO domain_index (domain_name, cert_indices)")
	if err != nil {
		return err
	}

	for domain, indices := range data {
		if err := batch.Append(domain, indices); err != nil {
			return err
		}
	}

	return batch.Send()
}