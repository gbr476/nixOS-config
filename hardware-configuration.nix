# Do not modify this file!  It was generated by ‘nixos-generate-config’
# and may be overwritten by future invocations.  Please make changes
# to /etc/nixos/configuration.nix instead.
{ config, lib, pkgs, modulesPath, ... }:

{
  imports =
    [ (modulesPath + "/installer/scan/not-detected.nix")
    ];

  boot.initrd.availableKernelModules = [ "xhci_pci" "ehci_pci" "ahci" "usb_storage" "usbhid" "sd_mod" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ "kvm-intel" ];
  boot.extraModulePackages = [ ];

  fileSystems."/" =
    { device = "/dev/disk/by-uuid/35682bf3-5d6f-48b9-90ca-7d9b9a69c7b8";
      fsType = "btrfs";
    };

  boot.initrd.luks.devices."nix-store".device = "/dev/disk/by-uuid/696d5031-f2da-4040-acd1-ad1d47bdd488";

  fileSystems."/boot" =
    { device = "/dev/disk/by-uuid/7DFB-C96D";
      fsType = "vfat";
    };

  fileSystems."/root" =
    { device = "/dev/disk/by-uuid/35682bf3-5d6f-48b9-90ca-7d9b9a69c7b8";
      fsType = "btrfs";
      options = [ "subvol=root" "noatime" ];
    };

  fileSystems."/nix" =
    { device = "/dev/disk/by-uuid/35682bf3-5d6f-48b9-90ca-7d9b9a69c7b8";
      fsType = "btrfs";
      options = [ "subvol=nix" "noatime" ];
    };

  fileSystems."/etc" =
    { device = "/dev/disk/by-uuid/35682bf3-5d6f-48b9-90ca-7d9b9a69c7b8";
      fsType = "btrfs";
      options = [ "subvol=etc" "noatime" ];
    };

  fileSystems."/var/log" =
    { device = "/dev/disk/by-uuid/35682bf3-5d6f-48b9-90ca-7d9b9a69c7b8";
      fsType = "btrfs";
      options = [ "subvol=log" "noatime" ];
      neededForBoot = true;
    };

  fileSystems."/home" =
    { device = "/dev/disk/by-uuid/35682bf3-5d6f-48b9-90ca-7d9b9a69c7b8";
      fsType = "btrfs";
      options = [ "subvol=home" ];
    };

  # Setup keyfile
  boot.initrd.secrets = {
    "/crypto_keyfile.bin" = null;
  };

  # Enable swap on luks
  boot.initrd.luks.devices."luks-129dfb52-4fa5-4dae-bbfa-a32bb4faad8e".device = "/dev/disk/by-uuid/129dfb52-4fa5-4dae-bbfa-a32bb4faad8e";
  boot.initrd.luks.devices."luks-129dfb52-4fa5-4dae-bbfa-a32bb4faad8e".keyFile = "/crypto_keyfile.bin";

  swapDevices = [ { device = "/dev/disk/by-uuid/b4d85801-af4d-40bd-8f81-a0ca72e31f43"; } ];
  
  #services.fstrim.enable = true;

  # Enables DHCP on each ethernet and wireless interface. In case of scripted networking
  # (the default) this is the recommended approach. When using systemd-networkd it's
  # still possible to use this option, but it's recommended to use it in conjunction
  # with explicit per-interface declarations with `networking.interfaces.<interface>.useDHCP`.
  #networking.useDHCP = lib.mkDefault true;
  # networking.interfaces.enp0s25.useDHCP = lib.mkDefault true;
  # networking.interfaces.enp5s0.useDHCP = lib.mkDefault true;
  # networking.interfaces.wlp9s1.useDHCP = lib.mkDefault true;

  nixpkgs.hostPlatform = lib.mkDefault "x86_64-linux";
  hardware.cpu.intel.updateMicrocode = lib.mkDefault config.hardware.enableRedistributableFirmware;
}
