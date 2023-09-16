# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running `nixos-help`).

{ config, lib, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

  # Use the systemd-boot EFI boot loader.
  #boot.loader.systemd-boot.enable = true;
  #boot.loader.efi.canTouchEfiVariables = true;
  boot = {
    supportedFilesystems = [ "btrfs" ];
    loader = {
      efi.canTouchEfiVariables = true;
      efi.efiSysMountPoint = "/boot";
      grub = {
        enable = true;
        device = "nodev";
        enableCryptodisk = true;
        copyKernels = false;
        efiInstallAsRemovable = false;
        efiSupport = true;
        useOSProber = true;
        splashImage = null;
        extraEntries = ''
          menuentry "Reboot" {
            reboot
          }
          menuentry "Poweroff" {
            halt
          }
        '';
      };
    };
  };

  virtualisation.libvirtd.enable = true;

  #networking.hostName = "nixos"; # Define your hostname.
  # Pick only one of the below networking options.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.
  #networking.networkmanager.enable = true;  # Easiest to use and most distros use this by default.
  networking = {
    hostName = "nix";
    #nameservers = [ "127.0.0.1" "::" ];
    networkmanager = {
    #  dns = "none";
      enable = true;
    };

    nftables = {
      enable = false;
      ruleset = ''
        table inet filter {
          # https://www.cloudflare.com/ips-v4
          set cloudflare_ipv4 {
            type ipv4_addr
            flags interval
            elements = {
              173.245.48.0/20,
              103.21.244.0/22,
              103.22.200.0/22,
              103.31.4.0/22,
              141.101.64.0/18,
              108.162.192.0/18,
              190.93.240.0/20,
              188.114.96.0/20,
              197.234.240.0/22,
              198.41.128.0/17,
              162.158.0.0/15,
              104.16.0.0/13,
              104.24.0.0/14,
              172.64.0.0/13,
              131.0.72.0/22
            }
          }

          # https://www.cloudflare.com/ips-v6
          set cloudflare_ipv6 {
            type ipv6_addr
            flags interval
            elements = {
              2400:cb00::/32,
              2606:4700::/32,
              2803:f800::/32,
              2405:b500::/32,
              2405:8100::/32,
              2a06:98c0::/29,
              2c0f:f248::/32
            }
          }

          chain output {
            type filter hook output priority 0
            policy accept

            ip daddr @cloudflare_ipv4 counter reject
            ip6 daddr @cloudflare_ipv6 counter reject
          }

          chain input {
            type filter hook output priority 0
            policy accept

            ip saddr @cloudflare_ipv4 counter reject
            ip6 saddr @cloudflare_ipv6 counter reject
          }
        }
      '';
    };

    #useDHCP = {
      
    interfaces = {
      enp5s0.useDHCP = true;
      enp0s25.useDHCP = true;
      #wlp2s0.useDHCP = true;
    };

    # Configure network proxy if necessary
    # proxy.default = "http://user:password@proxy:port/";
    # proxy.noProxy = "127.0.0.1,localhost,internal.domain";

    # Open ports in the firewall.
    firewall.allowedTCPPorts = [ 59879 ];
    firewall.allowedUDPPorts = [ 4001 ];
  };

  # Set your time zone.
  time.timeZone = "America/Chicago";

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";


  # Select internationalisation properties.
  i18n.defaultLocale = "en_US.UTF-8";

  i18n.extraLocaleSettings = {
    LC_ADDRESS = "en_US.UTF-8";
    LC_IDENTIFICATION = "en_US.UTF-8";
    LC_MEASUREMENT = "en_US.UTF-8";
    LC_MONETARY = "en_US.UTF-8";
    LC_NAME = "en_US.UTF-8";
    LC_NUMERIC = "en_US.UTF-8";
    LC_PAPER = "en_US.UTF-8";
    LC_TELEPHONE = "en_US.UTF-8";
    LC_TIME = "en_US.UTF-8";
  };
  # Select internationalisation properties.
  # i18n.defaultLocale = "en_US.UTF-8";
  # console = {
  #   font = "Lat2-Terminus16";
  #   keyMap = "us";
  #   useXkbConfig = true; # use xkbOptions in tty.
  # };

  # Enable the X11 windowing system.
  #services.xserver.enable = true;


  # Enable the Plasma 5 Desktop Environment.
  #services.xserver.displayManager.sddm.enable = true;
  #services.xserver.desktopManager.plasma5.enable = true;
  

  # Configure keymap in X11
  # services.xserver.layout = "us";
  # services.xserver.xkbOptions = "eurosign:e,caps:escape";

  # Enable CUPS to print documents.
  # services.printing.enable = true;

  # Enable sound.
  # sound.enable = true;
  # hardware.pulseaudio.enable = true;

  # Enable touchpad support (enabled default in most desktopManager).
  # services.xserver.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.geoff-admin = {
     isNormalUser = true;
     description = "geoff-admin";
     createHome = true;
     extraGroups = [ "wheel" "networkmanager" ]; # Enable ‘sudo’ for the user.
     packages = with pkgs; [
       firefox
       kate
       tree
       efibootmgr
     ];
  };

  # Allow unfree packages
  nixpkgs.config.allowUnfree = true;

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
  #   vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
     wget
     gparted
     krusader
  ];
#  environment = {
#    etc."resolv.conf".text = ''
#      nameserver 127.0.0.1
#      nameserver ::
#      options edns0
#    '';
#    localBinInPath = true;
#    systemPackages = with pkgs; [
#      atool compsize cryptsetup htop-vim inotify-tools killall rsync unzip zip
#      oathToolkit isync stow tor w3m wget yt-dlp
#      imv mpv pavucontrol sent yacreader
#      ffmpeg mkvtoolnix mediainfo simplescreenrecorder sox
#      darktable gimp imagemagick pdftk
#    ];
#    wordlist.enable = true;
#  };

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  #services.openssh.enable = true;
  services = {
	# Enable the X11 windowing system.
        # Configure keymap in X11
        xserver = {
          enable = true;
          layout = "us";
          xkbVariant = "";
        };	
        #openiscsi = {
	#	enable = true;
	#	name = "10.0.1.52";
	#};
	
	# Enable the GNOME 3 Desktop Environment.
	xserver.displayManager.sddm.enable = true;
	xserver.desktopManager.plasma5.enable = true;
	
		# List services that you want to enable:
	
	# Enable the OpenSSH daemon.
	openssh.enable = true;
	#openssh.settings.passwordAuthentication = true;
	#openssh.settings.permitRootLogin = "yes";
	#openssh.kbdInteractiveAuthentication = false;
	#openssh.extraConfig = ''
	#	PubkeyAcceptedAlgorithms +ssh-rsa
	#	HostkeyAlgorithms +ssh-rsa
	#'';
	
	#services.dbus.packages = with pkgs; [ gnome3.dconf ];
		
	
	# Configure keymap in X11
	# services.xserver.layout = "us";
	# services.xserver.xkbOptions = "eurosign:e";
	
	# Enable CUPS to print documents.
	printing.enable = true;
	
	#pipewire = {
	#	enable = true;
	#	alsa.enable = true;
	#	alsa.support32Bit = true;
	#	pulse.enable = true;
		# If you want to use JACK applications, uncomment this
		#jack.enable = true;
	
		# use the example session manager (no others are packaged yet so this is enabled by default,
		# no need to redefine it in your config for now)
		#media-session.enable = true;
	#};
	
	#pcscd.enable = true;
	#udev.packages = with pkgs; [ pkgs.yubikey-personalization pkgs.libu2f-host ];
  };


  # Enable sound with pipewire.
  sound.enable = true;
  hardware.pulseaudio.enable = false;
  security.rtkit.enable = true;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
    # If you want to use JACK applications, uncomment this
    #jack.enable = true;

    # use the example session manager (no others are packaged yet so this is enabled by default,
    # no need to redefine it in your config for now)
    #media-session.enable = true;
  };

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;

  # Copy the NixOS configuration file and link it from the resulting system
  # (/run/current-system/configuration.nix). This is useful in case you
  # accidentally delete configuration.nix.
  # system.copySystemConfiguration = true;

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It's perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "23.05"; # Did you read the comment?

}

