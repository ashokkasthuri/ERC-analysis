<!--
 * @Author: ashokkasthuri ashokk@smu.edu.sg
 * @Date: 2025-04-22 13:01:41
 * @LastEditors: ashokkasthuri ashokk@smu.edu.sg
 * @LastEditTime: 2025-04-22 13:01:45
 * @FilePath: /ERC-analysis-master/domain_separator_overview.md
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
-->


```mermaid

%%{init: {'theme': 'neutral'}}%%
flowchart TD
    A[Message] --> B(DOMAIN_SEPARATOR)
    B --> C{Unique Cryptographic Binding}
    C --> D[Prevent Cross-Contract Replays]
    C --> E[Chain-Specific Signatures]
    C --> F[Version Control]
    C --> G[Contract Instance Isolation]
```





```mermaid
%%{init: {'theme': 'neutral'}}%%
flowchart LR
    DOMAIN[DOMAIN_SEPARATOR] -->|Inputs| HASH[keccak256]
    HASH -->|Components| NAME[Contract Name]
    HASH --> VERSION[Contract Version]
    HASH --> CHAIN[Chain ID]
    HASH --> ADDR[Contract Address]
    HASH --> SALT[Unique Salt]

```



```mermaid
%%{init: {'theme': 'neutral'}}%%
flowchart TD
    NoSalt[Without Salt] -->|Same Domain| Replay(Replay Possible)
    WithSalt[With Salt] -->|Unique Per Contract| NoReplay(Replay Prevented)

```



```mermaid

sequenceDiagram
    Attacker->>ContractA: Get signature σ for action X
    Attacker->>ContractB: Deploy identical contract
    Attacker->>ContractB: Submit (X, σ)
    ContractB->>EVM: Verify(σ)
    EVM-->>ContractB: ✅ Valid (Same DOMAIN_SEPARATOR)
```



```mermaid
graph LR
    ChainA[Ethereum Mainnet] -->|Same DOMAIN_SEPARATOR| ChainB[Polygon]
    ChainC[Optimism] -->|Different chainId| ChainD[Arbitrum]

```