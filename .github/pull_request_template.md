**What this changes, and why**

**How it was verified**

- [ ] `make check` passes (fmt, clippy, tests)
- [ ] New or changed behaviour has a test that fails without the change
- [ ] Touched a parser? It has a property test, and ideally a fuzz target
- [ ] Platforms built and run by hand, if the change touches `apple/`,
      `android/` or `windows/` — CI can compile those, but only a device can
      tell you whether biometrics, the camera or the secure store behaved

**Anything that was not verified**

Say so plainly. A change that compiles but was never run on a device is
normal here; one that is described as working when it was not is not.
