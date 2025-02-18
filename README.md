# Wazuh-nix

This repository contains the necessary files to build a Wazuh stack (Indexer, server & dashboard) for NixOS.
It use the [wazuh-docker](https://github.com/wazuh/wazuh-docker.git) repository to build the docker images **which is pretty gross but it works**.

**Wazuh version**: 4.10.1


## Installation

Here is a quick guide to get you started:

### With flake

1. Add this repository to your NixOS flake.nix file

```nix
{
  inputs = {
    # ...
    wazuh.url = "github:anotherhadi/wazuh-nix";
  };

  outputs = inputs@{ nixpkgs, ... }: {
    nixosConfigurations = {
      your-config = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          inputs.wazuh.nixosModules.wazuh
          ./configuration.nix
        ];
      };
    };
  };
}
```

2. Enable the module in your configuration.nix

```nix
{
  programs.wazuh.enable = true;
}
```

## Configuration

Here are the default options:

```nix
{
  programs.wazuh = {
    enable = false;
    username = "admin";
    password = "HMthisismys3cr3tP5ssword34a;";
    hashedPassword = "..."; # ${pkgs.spring-boot-cli}/bin/spring encodepassword my_secret_password | cut -c 9-
  };
```

> [!Important]
> Obviously, you should change the default password.
