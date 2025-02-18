{
  description = "Wazuh stack packaged with docker compose in NixOS";

  inputs = { nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; };

  outputs = { self, nixpkgs, ... }: {
    nixosModules.wazuh = import ./wazuh.nix;
  };
}
