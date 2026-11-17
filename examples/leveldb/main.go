// Command leveldb summarizes a LevelDB store directory: CURRENT, its
// manifest, the sorted tables and the write-ahead logs.
//
//	go run ./examples/leveldb -dir "C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb"
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	forensic "github.com/laenix/ewfgo"
)

func main() {
	dir := flag.String("dir", "", "LevelDB store directory (contains CURRENT)")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: leveldb -dir <store-directory>")
		os.Exit(2)
	}
	if err := run(context.Background(), *dir); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dir string) error {
	store, err := forensic.OpenLevelDB(dir, forensic.Options{})
	if err != nil {
		return err
	}
	defer store.Close()

	info := store.Info()
	fmt.Printf("store      %s\n", info.Path)
	fmt.Printf("current    %s (%d manifest files)\n", info.CurrentManifest, info.ManifestFiles)
	fmt.Printf("manifest   %d records, %d edits, complete=%t, live tables=%d\n",
		info.ManifestRecords, info.ManifestEdits, info.ManifestComplete, info.LiveTables)
	fmt.Printf("tables     %d (%d key+value bytes scanned)\n", info.Tables, info.TableBytes)
	fmt.Printf("logs       %d (%d entries, %d deletions)\n",
		info.Logs, info.LogEntries, info.LogDeletions)

	tables, err := store.Tables(ctx)
	if err != nil {
		return err
	}
	for _, table := range tables {
		fmt.Printf("  table %06d %-24s live=%-5t entries=%-6d deleted=%-4d complete=%t\n",
			table.Number, table.Name, table.Live, table.Entries, table.Deleted, table.ScanComplete)
		if table.FirstKey != "" {
			fmt.Printf("        keys %q .. %q\n", table.FirstKey, table.LastKey)
		}
	}
	logs, err := store.Logs(ctx)
	if err != nil {
		return err
	}
	for _, log := range logs {
		fmt.Printf("  log   %06d %-24s records=%-5d batches=%-5d entries=%-6d deletions=%d\n",
			log.Number, log.Name, log.Records, log.Batches, log.Entries, log.Deletions)
	}
	warnings, err := store.Warnings(ctx)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		fmt.Println("warning:", warning)
	}
	return nil
}
