# proton-bridge-mcp: the server, with its whole test suite in checkPhase —
# unit, MIME corpus, the scripted fake Bridge, the MCP layer, and the
# end-to-end tests against a real gluon (Bridge's IMAP engine).
{
  lib,
  python3Packages,
  callPackage,
  openssl,
  gluonDemo ? callPackage ./gluon-demo.nix { },
}:

python3Packages.buildPythonApplication {
  pname = "proton-bridge-mcp";
  version = "0.1.0";
  pyproject = true;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./pyproject.toml
      ./README.md
      ./src
      ./tests
    ];
  };

  build-system = [ python3Packages.setuptools ];

  dependencies = with python3Packages; [
    icalendar
    imapclient
    mcp
    starlette
    uvicorn
  ];

  nativeCheckInputs = [
    python3Packages.pytestCheckHook
    python3Packages.hypothesis
    python3Packages.httpx
    openssl # test certificates shaped like Bridge's
    gluonDemo
  ];

  preCheck = ''
    export PROTON_MCP_GLUON=${lib.getExe gluonDemo}
    export PROTON_MCP_REQUIRE_GLUON=1
  '';

  pytestFlags = [
    "-p"
    "no:cacheprovider"
  ];

  pythonImportsCheck = [ "proton_mcp" ];

  meta = {
    description = "MCP server for Proton Mail through Proton Mail Bridge: read, organize, draft; sends only calendar replies";
    homepage = "https://github.com/santiagotoscanini/proton-bridge-mcp";
    license = lib.licenses.mit;
    mainProgram = "proton-mcp";
    platforms = lib.platforms.linux;
  };
}
