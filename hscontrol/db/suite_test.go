package db

import (
	"log"
	"os"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
)

func newSQLiteTestDB() (*HSDatabase, error) {
	tmpDir, err := os.MkdirTemp("", "headscale-db-test-*")
	if err != nil {
		return nil, err
	}

	log.Printf("database path: %s", tmpDir+"/headscale_test.db")
	zerolog.SetGlobalLevel(zerolog.Disabled)

	db, err := NewHeadscaleDatabase(
		&types.Config{
			Database: types.DatabaseConfig{
				Type: types.DatabaseSqlite,
				Sqlite: types.SqliteConfig{
					Path: tmpDir + "/headscale_test.db",
				},
			},
			Policy: types.PolicyConfig{
				Mode: types.PolicyModeDB,
			},
		},
		emptyCache(),
	)
	if err != nil {
		return nil, err
	}

	return db, nil
}
