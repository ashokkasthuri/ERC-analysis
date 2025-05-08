<!--
 * @Author: ashokkasthuri ashokk@smu.edu.sg
 * @Date: 2025-04-29 10:29:49
 * @LastEditors: ashokkasthuri ashokk@smu.edu.sg
 * @LastEditTime: 2025-04-29 10:48:53
 * @FilePath: /ERC-analysis-master/signature_replay.md
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
-->
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
    actor User
    participant ContractA
    participant ContractB
    participant Signature
    
    Note over User: Secure Implementation (Your Current Code)
    User->>ContractA: testReplayAttack(messageHash, v, r, s)
    ContractA->>ContractA: getDigest() with DOMAIN_SEPARATOR_A
    ContractA->>Signature: Verify with ContractA's domain
    Signature-->>ContractA: Recovered: 0xeBB...70aC
    ContractA->>User: Success (Address matches signer)
    
    User->>ContractB: Same testReplayAttack(messageHash, v, r, s)
    ContractB->>ContractB: getDigest() with DOMAIN_SEPARATOR_B
    ContractB->>Signature: Verify with ContractB's domain
    Signature-->>ContractB: Recovered: 0x677...D9eA
    Note right of ContractB: Different address!<br/>Attack failed
    
    Note over User: Vulnerable Implementation (For Comparison)
    User->>ContractA: testReplayAttack(messageHash, v, r, s)
    ContractA->>ContractA: getDigest() WITHOUT domain separation
    ContractA->>Signature: Verify raw message
    Signature-->>ContractA: Recovered: 0xeBB...70aC
    ContractA->>User: Success
    
    User->>ContractB: Same testReplayAttack(messageHash, v, r, s)
    ContractB->>ContractB: getDigest() WITHOUT domain separation
    ContractB->>Signature: Verify same raw message
    Signature-->>ContractB: Recovered: 0xeBB...70aC
    Note right of ContractB: Same address!<br/>Attack succeeded