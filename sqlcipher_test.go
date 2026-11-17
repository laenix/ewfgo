package forensic_test

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/containers/sqlcipher"
	"github.com/laenix/ewfgo/internal/data/source"
)

func encryptedSQLite(t *testing.T) []byte {
	t.Helper()
	params := sqlcipher.ParamsV4()
	plain := make([]byte, int(params.PageSize)*2)
	copy(plain, sqlcipher.SQLiteMagic)
	binary.BigEndian.PutUint16(plain[16:], uint16(params.PageSize))
	plain[20] = byte(params.ReserveBytes())
	for i := int(params.PageSize); i < len(plain); i++ {
		plain[i] = byte(i)
	}
	var salt [sqlcipher.SaltBytes]byte
	for i := range salt {
		salt[i] = byte(0x20 + i)
	}
	encrypted, err := sqlcipher.EncryptDatabase(plain, salt, []byte("correct horse"), params)
	if err != nil {
		t.Fatalf("EncryptDatabase: %v", err)
	}
	return encrypted
}

func TestOpenSQLCipher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "browser.db")
	if err := os.WriteFile(path, encryptedSQLite(t), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := forensic.OpenSQLCipher(ctx, path, "correct horse", forensic.Options{})
	if err != nil {
		t.Fatalf("OpenSQLCipher: %v", err)
	}
	defer db.Close()

	info := db.Info()
	if info.Version != "SQLCipher 4" || info.PageSize != 4096 || info.PageCount != 2 {
		t.Fatalf("info = %+v", info)
	}
	if info.Salt == "" || info.HMAC == "" {
		t.Fatalf("info = %+v", info)
	}
	header := make([]byte, 16)
	if _, err := db.Source().ReadAt(0, header); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(header) != string(sqlcipher.SQLiteMagic) {
		t.Fatalf("decrypted header = %q", header)
	}

	if _, err := forensic.OpenSQLCipher(ctx, path, "wrong", forensic.Options{}); !errors.Is(err, forensic.ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase = %v, want ErrWrongPassphrase", err)
	}
}

func TestOpenSQLCipherSource(t *testing.T) {
	db, err := forensic.OpenSQLCipherSource(context.Background(),
		source.NewMemorySource(1, encryptedSQLite(t)), "correct horse", forensic.Options{})
	if err != nil {
		t.Fatalf("OpenSQLCipherSource: %v", err)
	}
	header := make([]byte, 16)
	if _, err := db.Source().ReadAt(0, header); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(header) != string(sqlcipher.SQLiteMagic) {
		t.Fatalf("decrypted header = %q", header)
	}
}

func TestOpenSQLCipherRejectsPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.db")
	plain := make([]byte, 4096)
	copy(plain, sqlcipher.SQLiteMagic)
	binary.BigEndian.PutUint16(plain[16:], 4096)
	if err := os.WriteFile(path, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := forensic.OpenSQLCipher(context.Background(), path, "pass", forensic.Options{}); !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("plaintext SQLite = %v, want ErrUnsupported", err)
	}
}
