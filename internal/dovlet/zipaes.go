package dovlet

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// WinZip AES (AE-1/AE-2) as produced and consumed by zip.js in the web app.
// Spec: https://www.winzip.com/en/support/aes-encryption/
const (
	entryName     = "message.txt"
	methodAES     = 99
	extraAESID    = 0x9901
	pbkdf2Iter    = 1000
	pwvLen        = 2
	macLen        = 10
	writeStrength = 3 // AES-256
)

var (
	// ErrBadPassword is returned for a wrong password or a damaged archive.
	// The two cases are deliberately reported the same way, as in the web app.
	ErrBadPassword    = errors.New("wrong password or corrupted data")
	errInvalidArchive = errors.New("invalid Dovlet archive")
)

func aesSizes(strength byte) (saltLen, keyLen int, ok bool) {
	switch strength {
	case 1:
		return 8, 16, true
	case 2:
		return 12, 24, true
	case 3:
		return 16, 32, true
	}
	return 0, 0, false
}

func deriveKeys(password string, salt []byte, keyLen int) (encKey, macKey, pwv []byte, err error) {
	dk, err := pbkdf2.Key(sha1.New, password, salt, pbkdf2Iter, 2*keyLen+pwvLen)
	if err != nil {
		return nil, nil, nil, err
	}
	return dk[:keyLen], dk[keyLen : 2*keyLen], dk[2*keyLen:], nil
}

// ctrXOR applies AES-CTR with WinZip's little-endian counter starting at 1.
// Go's cipher.NewCTR uses a big-endian counter, so it cannot be used here.
func ctrXOR(key, data []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	var ctr, ks [aes.BlockSize]byte
	for off := 0; off < len(data); off += aes.BlockSize {
		for i := range ctr {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
		block.Encrypt(ks[:], ctr[:])
		end := min(off+aes.BlockSize, len(data))
		subtle.XORBytes(data[off:end], data[off:end], ks[:end-off])
	}
	return nil
}

func mac(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)[:macLen]
}

func dosDateTime(t time.Time) (date, tm uint16) {
	if t.Year() < 1980 {
		return 1<<5 | 1, 0
	}
	date = uint16((t.Year()-1980)<<9 | int(t.Month())<<5 | t.Day())
	tm = uint16(t.Hour()<<11 | t.Minute()<<5 | t.Second()/2)
	return
}

// SafeZipName returns the base name of a ZIP file path, rejecting names
// that could escape the current directory or collide with message.txt.
func SafeZipName(name string) (string, error) {
	base := name
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSpace(base)
	switch {
	case base == "", base == ".", base == "..", strings.ContainsAny(base, `/\`):
		return "", fmt.Errorf("invalid ZIP filename %q", name)
	case strings.IndexFunc(base, unicode.IsControl) >= 0:
		return "", fmt.Errorf("ZIP filename %q contains control characters", name)
	case len(base) > 200:
		return "", fmt.Errorf("ZIP filename %q is too long", name)
	case !strings.HasSuffix(strings.ToLower(base), ".zip"):
		return "", fmt.Errorf("ZIP file %q must end in .zip", name)
	}
	return base, nil
}

// ValidateZipFile applies the web app's file rules: a .zip name, at most
// MaxZipBytes, non-empty, starting with the PK signature.
func ValidateZipFile(name string, data []byte) error {
	if _, err := SafeZipName(name); err != nil {
		return err
	}
	switch {
	case len(data) == 0:
		return errors.New("ZIP file is empty")
	case len(data) > MaxZipBytes:
		return fmt.Errorf("ZIP file is %d bytes; the limit is %d bytes", len(data), MaxZipBytes)
	case len(data) < 2 || data[0] != 'P' || data[1] != 'K':
		return errors.New("not a ZIP file (missing PK signature)")
	}
	return nil
}

// sealEntry encrypts data as a single-entry WinZip AE-2 AES-256 ZIP.
// method is the actual compression method (zip.Deflate or zip.Store);
// data is the uncompressed content, compressed here when method is Deflate.
func sealEntry(name string, data []byte, password string, method uint16) ([]byte, error) {
	stored := data
	if method == zip.Deflate {
		var comp bytes.Buffer
		fw, err := flate.NewWriter(&comp, 6)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(data); err != nil {
			return nil, err
		}
		if err := fw.Close(); err != nil {
			return nil, err
		}
		stored = comp.Bytes()
	}

	saltLen, keyLen, _ := aesSizes(writeStrength)
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	encKey, macKey, pwv, err := deriveKeys(password, salt, keyLen)
	if err != nil {
		return nil, err
	}
	enc := bytes.Clone(stored)
	if err := ctrXOR(encKey, enc); err != nil {
		return nil, err
	}
	payload := make([]byte, 0, saltLen+pwvLen+len(enc)+macLen)
	payload = append(payload, salt...)
	payload = append(payload, pwv...)
	payload = append(payload, enc...)
	payload = append(payload, mac(macKey, enc)...)

	// Extra field 0x9901: vendor version 2 (AE-2, CRC omitted), "AE",
	// strength, actual compression method.
	extra := make([]byte, 11)
	binary.LittleEndian.PutUint16(extra[0:], extraAESID)
	binary.LittleEndian.PutUint16(extra[2:], 7)
	binary.LittleEndian.PutUint16(extra[4:], 2)
	copy(extra[6:], "AE")
	extra[8] = writeStrength
	binary.LittleEndian.PutUint16(extra[9:], method)

	date, tm := dosDateTime(time.Now())
	fh := &zip.FileHeader{
		Name:               name,
		Method:             methodAES,
		Flags:              0x1, // encrypted
		CreatorVersion:     3<<8 | 51,
		ReaderVersion:      51,
		ModifiedDate:       date,
		ModifiedTime:       tm,
		CRC32:              0,
		CompressedSize64:   uint64(len(payload)),
		UncompressedSize64: uint64(len(data)),
		Extra:              extra,
		ExternalAttrs:      0o644 << 16,
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	w, err := zw.CreateRaw(fh)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(payload); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// SealZip compresses text with DEFLATE and encrypts it into a single-entry
// "message.txt" ZIP using WinZip AE-2, AES-256.
func SealZip(text []byte, password string) ([]byte, error) {
	return sealEntry(entryName, text, password, zip.Deflate)
}

// SealZipFile encrypts a ZIP file as a single entry kept under its original
// filename. The file is stored uncompressed: it is already compressed.
func SealZipFile(filename string, data []byte, password string) ([]byte, error) {
	name, err := SafeZipName(filename)
	if err != nil {
		return nil, err
	}
	if err := ValidateZipFile(name, data); err != nil {
		return nil, err
	}
	return sealEntry(name, data, password, zip.Store)
}

type aesExtra struct {
	version  uint16
	strength byte
	method   uint16
}

func findAESExtra(extra []byte) (aesExtra, bool) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra)
		size := int(binary.LittleEndian.Uint16(extra[2:]))
		extra = extra[4:]
		if size > len(extra) {
			return aesExtra{}, false
		}
		if id == extraAESID && size >= 7 && string(extra[2:4]) == "AE" {
			return aesExtra{
				version:  binary.LittleEndian.Uint16(extra),
				strength: extra[4],
				method:   binary.LittleEndian.Uint16(extra[5:]),
			}, true
		}
		extra = extra[size:]
	}
	return aesExtra{}, false
}

// Entry is one decrypted Dovlet payload: either the text message
// ("message.txt") or a ZIP file kept under its original filename.
type Entry struct {
	Filename string
	Data     []byte
}

// IsText reports whether the entry is the text message.
func (e *Entry) IsText() bool { return e != nil && e.Filename == entryName }

// OpenZip authenticates, decrypts and decompresses a Dovlet ZIP, enforcing
// the same structural and size limits as the web app. It accepts the text
// entry ("message.txt", at most MaxTextBytes) and ZIP-file entries (at most
// MaxZipBytes); anything else is rejected.
func OpenZip(b []byte, password string) (*Entry, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, errInvalidArchive
	}
	if len(zr.File) != 1 {
		return nil, errInvalidArchive
	}
	f := zr.File[0]
	isText := f.Name == entryName
	// An archive entry must already be a plain base name: unlike a file
	// path given by the user, "../photos.zip" inside an archive is not
	// sanitised, it is rejected.
	base, baseErr := SafeZipName(f.Name)
	isFile := !isText && baseErr == nil && base == f.Name
	if !isText && !isFile {
		return nil, errInvalidArchive
	}
	limit := MaxTextBytes
	if isFile {
		limit = MaxZipBytes
	}
	if f.Flags&0x1 == 0 || f.UncompressedSize64 > uint64(limit) {
		return nil, errInvalidArchive
	}
	// Only WinZip AES is accepted; legacy ZipCrypto is never produced by Dovlet.
	ae, ok := findAESExtra(f.Extra)
	if f.Method != methodAES || !ok || (ae.version != 1 && ae.version != 2) {
		return nil, errInvalidArchive
	}
	saltLen, keyLen, ok := aesSizes(ae.strength)
	if !ok || (ae.method != zip.Deflate && ae.method != zip.Store) {
		return nil, errInvalidArchive
	}

	raw, err := f.OpenRaw()
	if err != nil {
		return nil, errInvalidArchive
	}
	payload, err := io.ReadAll(raw)
	if err != nil || len(payload) < saltLen+pwvLen+macLen {
		return nil, errInvalidArchive
	}
	salt := payload[:saltLen]
	pwvGot := payload[saltLen : saltLen+pwvLen]
	data := bytes.Clone(payload[saltLen+pwvLen : len(payload)-macLen])
	tag := payload[len(payload)-macLen:]

	encKey, macKey, pwv, err := deriveKeys(password, salt, keyLen)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(pwv, pwvGot) != 1 ||
		subtle.ConstantTimeCompare(mac(macKey, data), tag) != 1 {
		return nil, ErrBadPassword
	}
	if err := ctrXOR(encKey, data); err != nil {
		return nil, err
	}

	var r io.Reader = bytes.NewReader(data)
	if ae.method == zip.Deflate {
		fr := flate.NewReader(r)
		defer fr.Close()
		r = fr
	}
	// Bounded sink: never inflate more than the limit, whatever the header says.
	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil || len(out) > limit || uint64(len(out)) != f.UncompressedSize64 {
		return nil, ErrBadPassword
	}
	if ae.version == 1 && crc32.ChecksumIEEE(out) != f.CRC32 {
		return nil, ErrBadPassword
	}
	if isText && !utf8.Valid(out) {
		return nil, ErrBadPassword
	}
	return &Entry{Filename: f.Name, Data: out}, nil
}
