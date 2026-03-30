{
  description = "xforce: run commands in an isolated netns and force traffic through tun2socks";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }@inputs:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
    ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages."${system}";
        lib = pkgs.lib;
        pname = "xforce";
        version = "0.1.0";

        xforce = pkgs.buildGoModule {
          inherit pname version;
          src = ./.;

          subPackages = [ "." ];
          vendorHash = "sha256-F6qAL7xwIG0o6I2ODgstHps5zD6GjXjNWSWUtUDrU7g=";

          ldflags = [
            "-s"
            "-w"
          ];

          nativeBuildInputs = [ pkgs.makeWrapper ];

          postInstall = ''
            if [ -f "$out/bin/main" ]; then
              mv "$out/bin/main" "$out/bin/${pname}"
            fi
            wrapProgram "$out/bin/${pname}" \
              --prefix PATH : ${lib.makeBinPath [ pkgs.slirp4netns ]}
          '';

          meta = with lib; {
            description = "Run commands in an isolated rootless netns via tun2socks";
            license = licenses.mit;
            platforms = platforms.linux;
            mainProgram = pname;
          };
        };
      in
      {
        formatter = pkgs.nixfmt;

        packages = {
          default = xforce;
          xforce = xforce;
        };

        apps.default = {
          type = "app";
          program = "${xforce}/bin/${pname}";
          meta = {
            description = "xforce app entrypoint";
          };
        };

        checks = {
          build = xforce;
        };

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go
            pkgs.gopls
            pkgs.slirp4netns
          ];
        };
      }
    );
}
