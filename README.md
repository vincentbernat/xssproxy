# xssproxy

Forward freedesktop.org Idle Inhibition Service calls to Xss

## Description

xssproxy implements the *org.freedesktop.ScreenSaver* D-Bus interface described
in the [Idle Inhibition Service Draft][idle-inhibition] by the freedesktop.org
developers.
The inhibition of the screensaver is then controlled using the
`XScreenSaverSuspend` function from the
[Xss (X11 Screen Saver extension) library][xss].

## Usage

To use run in your *~/.xinitrc* file.
The program doesn't return so you need to run it in the background.

    xssproxy &

To ignore some applications, like Firefox, use `-i firefox`.

## Installation

### Debian

    sudo apt-get install xssproxy

### NixOS

    nix-env -i xssproxy

### Compiling

    make
    make install

[idle-inhibition]: https://people.freedesktop.org/~hadess/idle-inhibition-spec/index.html
[xss]: https://www.x.org/releases/X11R7.6/doc/man/man3/Xss.3.xhtml
