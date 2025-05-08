<!--
 * @Author: ashokkasthuri ashokk@smu.edu.sg
 * @Date: 2025-04-21 16:28:28
 * @LastEditors: ashokkasthuri ashokk@smu.edu.sg
 * @LastEditTime: 2025-04-29 10:30:11
 * @FilePath: /ERC-analysis-master/salt_singnature_attack.md
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
-->
```mermaid
%%{init: {'theme': 'default', 'themeVariables': {
  'primaryColor': '#f2f2f2',
  'primaryTextColor': '#000',
  'actorBackground': '#e6f7ff',
  'actorBorder': '#007acc',
  'lineColor': '#007acc',
  'sequenceNumberColor': '#000',
  'background': '#ffffff'
}}}%%
sequenceDiagram
    participant User
    participant Python
    participant VC as VulnerableContract
    participant SC as SecureContract
    participant Blockchain

    Note over User,Blockchain: === REPLAY ATTACK (NO SALT) ===
    User->>Python: Start test
    Python->>Python: Generate EIP-712 data\n(domain = name+version+chainId+verifyingContract)
    Python->>Python: Create signature SIG_VULN
    Python->>VC: verifyMessage("Transfer 100 ETH", SIG_VULN)
    VC->>Blockchain: Hash domain separator\n(no salt included)
    Blockchain-->>VC: Valid signature
    VC-->>Python: ✅ Recovered: Signer
    Python->>VC: Replay same SIG_VULN\non new instance
    VC->>Blockchain: Same domain hash\n(no salt variation)
    Blockchain-->>VC: Accepts replayed signature
    VC-->>Python: ✅ Recovered: Signer\n(REPLAY SUCCESS)

    Note over User,Blockchain: === SECURE IMPLEMENTATION (WITH SALT) ===
    Python->>Python: Generate EIP-712 data\n(domain += unique salt)
    Python->>Python: Create signature SIG_SECURE
    Python->>SC: verifyMessage("Transfer 100 ETH", SIG_SECURE)
    SC->>Blockchain: Hash domain separator\n(with unique salt)
    Blockchain-->>SC: Valid signature
    SC-->>Python: ✅ Recovered: Signer
    Python->>SC: Attempt replay\nwith SIG_VULN
    SC->>Blockchain: Hash domain\n(salt mismatch)
    Blockchain-->>SC: ❌ Invalid signature
    SC-->>Python: ❌ Revert("Invalid signer")\n(REPLAY FAILED)

```


