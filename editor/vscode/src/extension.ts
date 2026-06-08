// routels VS Code extension — thin LSP client wrapping `routels lsp`.

import { workspace, ExtensionContext, window } from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

const NETLINT_LANGUAGES = [
  "frr", "eos", "vyos", "routeros", "bird", "nftables",
  "debinterfaces", "wireguard", "haproxy", "sysctl",
];

export function activate(_context: ExtensionContext) {
  const cfg = workspace.getConfiguration("routels");
  const binary = cfg.get<string>("path", "routels");

  const serverOptions: ServerOptions = {
    command: binary,
    args: ["lsp"],
    transport: TransportKind.stdio,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: NETLINT_LANGUAGES.map((language) => ({ scheme: "file", language })),
    synchronize: {
      configurationSection: "routels",
    },
  };

  client = new LanguageClient(
    "routels",
    "routels",
    serverOptions,
    clientOptions,
  );

  client.start().catch((err: unknown) => {
    window.showErrorMessage(
      `routels: failed to start LSP — is \`${binary}\` on PATH? (${err})`,
    );
  });
}

export function deactivate(): Thenable<void> | undefined {
  return client?.stop();
}
