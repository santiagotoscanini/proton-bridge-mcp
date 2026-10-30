# Proton's gluon IMAP server (the engine inside Bridge) at the revision
# Bridge v3.27.1 vendors, with its demo replaced by tests/gluon/demo.go:
# a Bridge-shaped mailbox layout behind implicit TLS. A check input of
# package.nix only — the end-to-end tests run the tools against it.
{
  buildGoModule,
  fetchFromGitHub,
}:

buildGoModule {
  pname = "gluon-demo";
  version = "0-unstable-2026-09-01";

  src = fetchFromGitHub {
    owner = "ProtonMail";
    repo = "gluon";
    rev = "7e800978ab4a9942829eb6116e33ea0278c03e91";
    hash = "sha256-435DO8RyUswGef6ZtTYi4a+R6p1Y9TBPQbAH3onAOrY=";
  };

  vendorHash = "sha256-CbAgJXCHUCtY1iCB2lfjy82OTQPmFUCmHNYR9W1YzXw=";

  postPatch = ''
    cp ${./tests/gluon/demo.go} demo/demo.go
  '';

  subPackages = [ "demo" ];
  env.GOTOOLCHAIN = "local";
  doCheck = false;

  meta.mainProgram = "demo";
}
