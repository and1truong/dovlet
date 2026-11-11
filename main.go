// Command dovlet hides password-encrypted text inside PNG images.
// It is byte-compatible with the Dovlet web app.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/and1truong/dovlet/internal/dovlet"
)

var version = "dev"

const usage = `dovlet - private messages, carried inside pictures

Usage:
  dovlet encode [flags]            encrypt a message and hide it in a PNG
  dovlet decode [flags] IMAGE.png  recover the message from a PNG
  dovlet version

The password is read from --password-file, then $DOVLET_PASSWORD, and
otherwise prompted for on the terminal. It is never accepted as an argument.

Run "dovlet encode -h" or "dovlet decode -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "encode", "enc", "e":
		err = runEncode(os.Args[2:])
	case "decode", "dec", "d":
		err = runDecode(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("dovlet", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "dovlet: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		var ue usageError
		fmt.Fprintln(os.Stderr, "dovlet:", err)
		if errors.As(err, &ue) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

type usageError struct{ error }

// parse lets flags appear before and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageError{err}
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func strFlag(fs *flag.FlagSet, p *string, short, long, help string) {
	fs.StringVar(p, short, "", help)
	fs.StringVar(p, long, "", "same as -"+short)
}

func runEncode(args []string) error {
	var message, input, cover, output, pwFile string
	var force bool
	fs := flag.NewFlagSet("encode", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dovlet encode [-m TEXT | -i FILE] [-c COVER] [-o OUT.png] [flags]

Encrypts the message (AES-256 ZIP) and hides it in a PNG. With neither -m nor
-i the message is read from stdin. The PNG is decoded again before it is
written to make sure the message can be recovered.

Flags:
`)
		fs.PrintDefaults()
	}
	strFlag(fs, &message, "m", "message", "message `text` (visible to other local users via the process list; prefer -i or stdin for secrets)")
	strFlag(fs, &input, "i", "input", "read the message from `file` (- for stdin)")
	strFlag(fs, &cover, "c", "cover", "cover `image` (PNG, JPEG or WebP); default is the built-in apple")
	strFlag(fs, &output, "o", "output", "output PNG `file`, - for stdout (default dovlet-message.png)")
	fs.StringVar(&pwFile, "password-file", "", "read the password from the first line of `file`")
	fs.BoolVar(&force, "f", false, "overwrite the output file if it exists")
	fs.BoolVar(&force, "force", false, "same as -f")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usageError{fmt.Errorf("unexpected argument %q (use -m or -i for the message)", pos[0])}
	}
	if message != "" && input != "" {
		return usageError{errors.New("use only one of -m and -i")}
	}
	if output == "" {
		output = "dovlet-message.png"
	}
	if output != "-" && !force {
		if _, err := os.Stat(output); err == nil {
			return fmt.Errorf("%s already exists (use -f to overwrite)", output)
		}
	}

	var text []byte
	switch {
	case message != "":
		text = []byte(message)
	case input != "" && input != "-":
		if text, err = readLimited(input, dovlet.MaxTextBytes); err != nil {
			return err
		}
	default:
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintln(os.Stderr, "Type the message, then press Ctrl-D on an empty line:")
		}
		if text, err = io.ReadAll(io.LimitReader(os.Stdin, dovlet.MaxTextBytes+1)); err != nil {
			return err
		}
	}
	var coverData []byte
	if cover != "" {
		if coverData, err = readLimited(cover, dovlet.MaxImageBytes); err != nil {
			return err
		}
	}
	// Validate the message before asking for a password.
	if err := dovlet.ValidateMessage(text, strings.Repeat("x", dovlet.MinPasswordRunes)); err != nil {
		return err
	}
	password, err := readPassword(pwFile, true)
	if err != nil {
		return err
	}

	res, err := dovlet.Encode(text, password, coverData)
	if err != nil {
		return err
	}
	if err := writeOutput(output, res.PNG, 0o644, force); err != nil {
		return err
	}
	dest := output
	if output == "-" {
		dest = "stdout"
	}
	fmt.Fprintf(os.Stderr, "Wrote %s (%d×%d, %d of %d bytes used); decryption verified.\n"+
		"Send it as an original file/document attachment and share the password separately.\n",
		dest, res.Width, res.Height, res.ZipBytes, res.Capacity)
	return nil
}

func runDecode(args []string) error {
	var output, zipOut, pwFile string
	var force bool
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dovlet decode [-o FILE] [--zip FILE] [flags] IMAGE.png

Recovers the message from a Dovlet PNG (- reads the image from stdin).
The message is written to stdout unless -o is given.

Flags:
`)
		fs.PrintDefaults()
	}
	strFlag(fs, &output, "o", "output", "write the message to `file` instead of stdout")
	fs.StringVar(&zipOut, "zip", "", "also save the encrypted ZIP to `file`")
	fs.StringVar(&pwFile, "password-file", "", "read the password from the first line of `file`")
	fs.BoolVar(&force, "f", false, "overwrite output files if they exist")
	fs.BoolVar(&force, "force", false, "same as -f")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{errors.New("decode needs exactly one IMAGE argument")}
	}
	for _, p := range []string{output, zipOut} {
		if p != "" && p != "-" && !force {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("%s already exists (use -f to overwrite)", p)
			}
		}
	}
	if zipOut == "-" && (output == "" || output == "-") {
		return usageError{errors.New("the message and the ZIP cannot both go to stdout")}
	}

	var img []byte
	if pos[0] == "-" {
		img, err = io.ReadAll(io.LimitReader(os.Stdin, dovlet.MaxImageBytes+1))
	} else {
		img, err = readLimited(pos[0], dovlet.MaxImageBytes)
	}
	if err != nil {
		return err
	}
	password, err := readPassword(pwFile, false)
	if err != nil {
		return err
	}
	text, archive, err := dovlet.Decode(img, password)
	if err != nil {
		return err
	}
	if zipOut != "" {
		if err := writeOutput(zipOut, archive, 0o644, force); err != nil {
			return err
		}
	}
	if output == "" {
		output = "-"
	}
	return writeOutput(output, text, 0o600, force)
}

func readLimited(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%s is larger than the %d byte limit", path, limit)
	}
	return b, nil
}

// readPassword takes the password from a file, $DOVLET_PASSWORD or the
// terminal, in that order. Terminal entry is confirmed when encoding because
// a mistyped password cannot be recovered.
func readPassword(file string, confirm bool) (string, error) {
	if file != "" {
		b, err := readLimited(file, 4096)
		if err != nil {
			return "", err
		}
		line, _, _ := bytes.Cut(b, []byte("\n"))
		return strings.TrimSuffix(string(line), "\r"), nil
	}
	if v, ok := os.LookupEnv("DOVLET_PASSWORD"); ok {
		return v, nil
	}
	tty, err := openTTY()
	if err != nil {
		return "", errors.New("no terminal for the password prompt; use --password-file or DOVLET_PASSWORD")
	}
	defer tty.Close()
	prompt := func(label string) (string, error) {
		fmt.Fprint(tty, label)
		b, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		return string(b), err
	}
	label := "Password: "
	if confirm {
		label = fmt.Sprintf("Password (at least %d characters): ", dovlet.MinPasswordRunes)
	}
	pw, err := prompt(label)
	if err != nil || !confirm {
		return pw, err
	}
	again, err := prompt("Repeat password: ")
	if err != nil {
		return "", err
	}
	if again != pw {
		return "", errors.New("passwords do not match")
	}
	return pw, nil
}

func openTTY() (*os.File, error) {
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		return f, nil
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDWR, 0); err == nil && term.IsTerminal(int(f.Fd())) {
		return f, nil
	}
	return nil, errors.New("no terminal")
}

// writeOutput writes to stdout for "-", otherwise atomically via a temporary
// file in the same directory so a failure never leaves a partial file.
func writeOutput(path string, data []byte, perm os.FileMode, force bool) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dovlet-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if force {
		return os.Rename(tmp.Name(), path)
	}
	// Link fails if the target appeared meanwhile, so nothing is clobbered.
	if err := os.Link(tmp.Name(), path); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists (use -f to overwrite)", path)
		}
		return err
	}
	return nil
}
