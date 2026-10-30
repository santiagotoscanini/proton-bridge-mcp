// A Bridge-shaped gluon for proton-mcp's end-to-end tests. It replaces
// gluon's demo/demo.go (rev 7e800978ab4a) in the test build (gluon-demo.nix)
// and differs from it in three ways only:
//
//   - one user, with Bridge's mailbox layout: the system mailboxes carry the
//     special-use attributes Bridge gives them
//     (proton-bridge v3.27.1 internal/services/imapservice/imap_updates.go),
//     and "Folders"/"Labels" are \Noselect prefixes, so CREATE outside them
//     fails as it does on Bridge;
//   - implicit TLS with the certificate the test hands it (Bridge's IMAP
//     listener is implicit TLS once SSL is on);
//   - SIGUSR1 bumps UIDVALIDITY, as a Bridge resync does.
//
// It prints "listening on <addr>" on stdout so a test can bind port 0.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ProtonMail/gluon"
	"github.com/ProtonMail/gluon/connector"
	"github.com/ProtonMail/gluon/imap"
	"github.com/sirupsen/logrus"
)

func main() {
	ctx := context.Background()

	if level, err := logrus.ParseLevel(os.Getenv("GLUON_LOG_LEVEL")); err == nil {
		logrus.SetLevel(level)
	} else {
		logrus.SetLevel(logrus.WarnLevel)
	}

	dir := os.Getenv("GLUON_DIR")

	server, err := gluon.New(
		gluon.WithDataDir(dir),
		gluon.WithDatabaseDir(dir),
	)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create server")
	}

	defer server.Close(ctx)

	flags := imap.NewFlagSet(imap.FlagAnswered, imap.FlagSeen, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft)

	conn := connector.NewDummy(
		[]string{"user1@example.com", "alias1@example.com"},
		[]byte("pass"),
		100*time.Millisecond,
		flags,
		flags,
		imap.NewFlagSet(),
	)

	if _, err := server.AddUser(ctx, conn, []byte("pass")); err != nil {
		logrus.WithError(err).Fatal("Failed to add user")
	}

	if err := conn.Sync(ctx); err != nil {
		logrus.WithError(err).Fatal("Failed to sync")
	}

	system := []struct {
		id, name, attr string
	}{
		{"drafts", "Drafts", imap.AttrDrafts},
		{"sent", "Sent", imap.AttrSent},
		{"starred", "Starred", imap.AttrFlagged},
		{"archive", "Archive", imap.AttrArchive},
		{"spam", "Spam", imap.AttrJunk},
		{"trash", "Trash", imap.AttrTrash},
		{"allmail", "All Mail", imap.AttrAll},
	}

	for _, m := range system {
		if err := conn.MailboxCreated(imap.Mailbox{
			ID:             imap.MailboxID(m.id),
			Name:           []string{m.name},
			Flags:          flags,
			PermanentFlags: flags,
			Attributes:     imap.NewFlagSet(imap.AttrNoInferiors, m.attr),
		}); err != nil {
			logrus.WithError(err).Fatal("Failed to create system mailbox")
		}
	}

	// After the system mailboxes: with both prefixes set the dummy refuses
	// any other top-level name, as Bridge does.
	conn.SetFolderPrefix("Folders")
	conn.SetLabelsPrefix("Labels")
	conn.Flush()

	cert, err := tls.LoadX509KeyPair(os.Getenv("GLUON_TLS_CERT"), os.Getenv("GLUON_TLS_KEY"))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load the TLS key pair")
	}

	host := "127.0.0.1:0"
	if envHost := os.Getenv("GLUON_HOST"); envHost != "" {
		host = envHost
	}

	plain, err := net.Listen("tcp", host)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to listen")
	}

	listener := tls.NewListener(plain, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	bump := make(chan os.Signal, 1)
	signal.Notify(bump, syscall.SIGUSR1)

	go func() {
		for range bump {
			conn.UIDValidityBumped()
			conn.Flush()
			fmt.Println("uidvalidity bumped")
		}
	}()

	fmt.Printf("listening on %v\n", plain.Addr())

	if err := server.Serve(ctx, listener); err != nil {
		logrus.WithError(err).Fatal("Failed to serve")
	}

	for err := range server.GetErrorCh() {
		logrus.WithError(err).Error("Error while serving")
	}
}
