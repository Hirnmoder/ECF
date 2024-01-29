# ECF

**Encrypted Container File: Design and Implementation of a Hybrid-Encrypted Multi-Recipient File Structure**

Tobias J. Bauer and Andreas Aßmuth

Links: [Conference Paper](https://www.thinkmind.org/index.php?view=article&articleid=cloud_computing_2023_1_10_28001), [Implementation](https://github.com/Hirnmoder/ECF)


---

This repository contains the Proof-of-Concept (PoC) implementation and is structured as follows:

Folder | Content
---|---
`perf` | Code and data for performance analysis
`src` | Complete source code
`src/EncryptedContainerFile` | ECF PoC source code
`src/EncryptedContainerFile/ECF.CLI` | Command Line Interface (CLI) tool to interact with ECF files
`src/EncryptedContainerFile/ECF.Core` | Implementation of all ECF operations including private key management
`src/EncryptedContainerFile/ECF.Test` | Unit and performance tests for *ECF.Core*
`src/EncryptedContainerFile/ECF.Test.Profiling` | Performance test evaluation code; generates data for performance analysis
`src/nsec` | Submodule *nsec* with minor change to allow key conversion from **Ed25519** to **X25519**
`src/yae` | Submodule *yae* with minor change to allow in-memory text manipulation
