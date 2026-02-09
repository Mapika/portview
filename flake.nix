{
  description = "A diagnostic-first port viewer. See what's on your ports, then act on it.";

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
            version = "0.6.0";

            src = self;

            cargoLock.lockFile = ./Cargo.lock;

            meta = with pkgs.lib; {
              description = "A diagnostic-first port viewer. See what's on your ports, then act on it.";
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
