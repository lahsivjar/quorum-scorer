# quorum-scorer

Shared scoreboard for a group of three or more. A score is the fold of a signed hash chain. It commits when a strict majority of the current members sign the same bytes. Game labels are inside those bytes, so the grand total and the per-game breakdown are the same fold.

This repository starts with the Kotlin Multiplatform protocol module. `commonMain` has no Android or iOS imports. The JVM target runs the tests. Android and iOS clients come next, once those toolchains are available; they will call this module and keep their keys in the Android Keystore and the Secure Enclave.

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
./gradlew :protocol:jvmTest
```

Phone screens for the board, the signature review, and the game breakdown are in `ux/index.html`.
