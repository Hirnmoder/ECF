# ECF

**Encrypted Container File: Design and Implementation of a Hybrid-Encrypted Multi-Recipient File Structure**

Tobias Bauer and Andreas Aßmuth


---

This repository contains the Proof-of-Concept (PoC) implementation and is structured as follows:

Folder | Content
---|---
`src` | Complete source code
`src/EncryptedContainerFile` | ECF PoC source code
`src/EncryptedContainerFile/ECF.ClI` | Command Line Interface (CLI) tool to interact with ECF files
`src/EncryptedContainerFile/ECF.Core` | Implementation of all ECF operations including private key management
`src/EncryptedContainerFile/ECF.Test` | Simple unit tests for *ECF.Core*
`src/nsec` | Submodule *nsec* with minor change to allow key conversion from **Ed25519** to **X25519**
`src/yae` | Submodule *yae* with minor change to allow in-memory text manipulation

