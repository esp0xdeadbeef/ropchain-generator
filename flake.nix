{
  description = "ROP chain generator - a Python helper package for generating ROP chains from gadget collections";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python3;
        pythonEnv = python.withPackages (ps: with ps; [
          keystone-engine
          pwntools
        ]);
        ropchain-generator = python.pkgs.buildPythonPackage {
          pname = "ropchain_generator";
          version = "0.1.0";
          pyproject = true;
          build-system = [ python.pkgs.setuptools ];
          src = ./.;
          propagatedBuildInputs = with python.pkgs; [
            keystone-engine
            pwntools
          ];
          doCheck = false; # no tests defined
          meta = with pkgs.lib; {
            description = "A Python helper package for generating ROP chains from gadget collections";
            license = licenses.mit;
            maintainers = [ ];
          };
        };
      in
      {
        packages = {
          default = ropchain-generator;
          ropchain-generator = ropchain-generator;
        };

        devShells.default = pkgs.mkShell {
          name = "ropchain-generator-dev";
          buildInputs = [
            pythonEnv
          ];
          shellHook = ''
            export PYTHONPATH="$(pwd):$PYTHONPATH"
            echo "ropchain-generator dev shell"
            echo "Python: $(python --version)"
            echo "Use: python -c 'from ropchain_generator import RopChainGenerator' to test"
          '';
        };
      }
    );
}
