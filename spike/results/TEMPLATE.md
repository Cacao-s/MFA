# Spike result — <platform>

- Date:
- Stack / version tried:
- Device / OS version:

## 1. Secure storage

- [ ] 32-byte key written and read back after a force-quit and relaunch
- [ ] Key not readable from another app or from app files on the device
- How: <API, plugin or crate used>
- Evidence: <recording or screenshot>
- Notes:

## 2. Biometrics

- [ ] Prompt appears
- [ ] Success returns success
- [ ] Cancel is distinguishable from failure
- How:
- Evidence:
- Notes:

## 3. QR input

- [ ] Mobile: camera reads an `otpauth://` code from a screen
- [ ] Desktop: PNG or screen grab read from a file
- How:
- Evidence:
- Notes:

## 4. Background blanking

- [ ] The code is not visible in the app switcher thumbnail
- How:
- Evidence:
- Notes:

## 5. Clipboard clearing

- [ ] A copied code is cleared after 30 seconds
- [ ] or: this platform cannot do it, and the UI must not promise it
- How:
- Notes:

## Conclusion

Workable on this platform: yes / no / with caveats

What would have to change:
