{
  description = "List ports and their processes on Linux, macOS, and Windows.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = rec {
          portview = pkgs.rustPlatform.buildRustPackage {
            pname = "portview";
            version = "2.1.0";

            src = self;

            cargoLock.lockFile = ./Cargo.lock;

            meta = with pkgs.lib; {
              description = "List ports and their processes on Linux, macOS, and Windows.";
              homepage = "https://github.com/Mapika/portview";
              license = licenses.mit;
              mainProgram = "portview";
            };
          };
          default = portview;
        };
      }
    );
}
