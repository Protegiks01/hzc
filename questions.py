import json

BASE_URL = "https://deepwiki.com/codertjay/zigi"


def get_questions():
    try:
        with open("all_questions.json", "r") as f:
            return json.load(f)

    except:
        return []


questions = get_questions()

questions_generator  = [
    "api/zigchain/dex/genesis.pulsar.go",
    "api/zigchain/dex/module/module.pulsar.go",
    "api/zigchain/dex/packet.pulsar.go",
    "api/zigchain/dex/params.pulsar.go",
    "api/zigchain/dex/pool_uids.pulsar.go",
    "api/zigchain/dex/pool.pulsar.go",
    "api/zigchain/dex/pools_meta.pulsar.go",
    "api/zigchain/dex/query_grpc.pb.go",
    "api/zigchain/dex/query.pulsar.go",
    "api/zigchain/dex/tx_grpc.pb.go",
    "api/zigchain/dex/tx.pulsar.go",
    "api/zigchain/factory/denom_auth.pulsar.go",
    "api/zigchain/factory/denom.pulsar.go",
    "api/zigchain/factory/genesis.pulsar.go",
    "api/zigchain/factory/module/module.pulsar.go",
    "api/zigchain/factory/params.pulsar.go",
    "api/zigchain/factory/query_grpc.pb.go",
    "api/zigchain/factory/query.pulsar.go",
    "api/zigchain/factory/tx_grpc.pb.go",
    "api/zigchain/factory/tx.pulsar.go",
    "api/zigchain/tokenwrapper/genesis.pulsar.go",
    "api/zigchain/tokenwrapper/module/module.pulsar.go",
    "api/zigchain/tokenwrapper/params.pulsar.go",
    "api/zigchain/tokenwrapper/query_grpc.pb.go",
    "api/zigchain/tokenwrapper/query.pulsar.go",
    "api/zigchain/tokenwrapper/tx_grpc.pb.go",
    "api/zigchain/tokenwrapper/tx.pulsar.go",
    "app/ante.go",
    "app/app.go",
    "app/config.go",
    "app/export.go",
    "app/genesis_account.go",
    "app/genesis.go",
    "app/ibc.go",
    "app/keepers/keepers_config.go",
    "app/keepers/keepers.go",
    "app/setup_handlers.go",
    "app/test_setup.go",
    "app/upgrades/types.go",
    "app/upgrades/v1/constants.go",
    "app/upgrades/v1/upgrades.go",
    "app/upgrades/v2/constants.go",
    "app/upgrades/v2/upgrades.go",
    "app/wasm.go",
    "cmd/zigchaind/cmd/commands.go",
    "cmd/zigchaind/cmd/config.go",
    "cmd/zigchaind/cmd/root.go",
    "cmd/zigchaind/cmd/testnet_multi_node.go",
    "cmd/zigchaind/cmd/testnet.go",
    "cmd/zigchaind/main.go",
    "docs/docs.go",
    "store/mock/cosmos_cosmos_db_DB.go",
    "testutil/data/address_errors.go",
    "testutil/data/demon_errors.go",
    "testutil/data/ibc_errors.go",
    "testutil/data/pool_errors.go",
    "testutil/helpers/types.go",
    "testutil/keeper/dex.go",
    "testutil/keeper/factory.go",
    "testutil/keeper/tokenwrapper.go",
    "testutil/mock/grpc_server.go",
    "testutil/mock/logger.go",
    "testutil/network/network.go",
    "testutil/nullify/nullify.go",
    "testutil/sample/sample.go",
    "tools/tools.go",
    "wasmbinding/bindings/msg.go",
    "wasmbinding/bindings/query.go",
    "wasmbinding/message_plugin.go",
    "wasmbinding/queries.go",
    "wasmbinding/query_plugin.go",
    "wasmbinding/stargate_whitelist.go",
    "wasmbinding/wasm.go",
    "x/dex/client/cli/tx.go",
    "x/dex/events/emit.go",
    "x/dex/keeper/k_get_set_params.go",
    "x/dex/keeper/keeper.go",
    "x/dex/keeper/msg_server_add_liquidity.go",
    "x/dex/keeper/msg_server_create_pool.go",
    "x/dex/keeper/msg_server_remove_liquidity.go",
    "x/dex/keeper/msg_server_swap_exact_in.go",
    "x/dex/keeper/msg_server_swap_exact_out.go",
    "x/dex/keeper/msg_server.go",
    "x/dex/keeper/msg_update_params.go",
    "x/dex/keeper/pool_uids.go",
    "x/dex/keeper/pool.go",
    "x/dex/keeper/pools_meta.go",
    "x/dex/keeper/query_params.go",
    "x/dex/keeper/query_pool_uids.go",
    "x/dex/keeper/query_pool.go",
    "x/dex/keeper/query_pools_meta.go",
    "x/dex/keeper/query_swap_in.go",
    "x/dex/keeper/query_swap_out.go",
    "x/dex/keeper/query.go",
    "x/dex/migrations/new_migrator.go",
    "x/dex/migrations/v2_migration.go",
    "x/dex/module/autocli.go",
    "x/dex/module/genesis.go",
    "x/dex/module/module.go",
    "x/dex/module/simulation.go",
    "x/dex/simulation/add_liquidity.go",
    "x/dex/simulation/create_pool.go",
    "x/dex/simulation/helpers.go",
    "x/dex/simulation/remove_liquidity.go",
    "x/dex/simulation/swap.go",
    "x/dex/testutil/common/bank_keeper_with_pool.go",
    "x/dex/testutil/expected_keepers_mocks.go",
    "x/dex/testutil/mock/types_module_module.go",
    "x/dex/types/codec.go",
    "x/dex/types/errors.go",
    "x/dex/types/events_ibc.go",
    "x/dex/types/events.go",
    "x/dex/types/expected_keepers.go",
    "x/dex/types/genesis.go",
    "x/dex/types/genesis.pb.go",
    "x/dex/types/key_pool_uids.go",
    "x/dex/types/key_pool.go",
    "x/dex/types/keys.go",
    "x/dex/types/message_add_liquidity.go",
    "x/dex/types/message_remove_liquidity.go",
    "x/dex/types/message_swap_exact_in.go",
    "x/dex/types/message_swap_exact_out.go",
    "x/dex/types/message_update_params.go",
    "x/dex/types/messages_create_pool.go",
    "x/dex/types/packet.pb.go",
    "x/dex/types/params.go",
    "x/dex/types/params.pb.go",
    "x/dex/types/pool_address.go",
    "x/dex/types/pool_uids.go",
    "x/dex/types/pool_uids.pb.go",
    "x/dex/types/pool.pb.go",
    "x/dex/types/pools_meta.pb.go",
    "x/dex/types/query.pb.go",
    "x/dex/types/query.pb.gw.go",
    "x/dex/types/tx.pb.go",
    "x/dex/types/types.go",
    "x/factory/events/emit.go",
    "x/factory/keeper/auth.go",
    "x/factory/keeper/denom_auth.go",
    "x/factory/keeper/invariants.go",
    "x/factory/keeper/k_get_all_denom.go",
    "x/factory/keeper/k_get_denom.go",
    "x/factory/keeper/k_get_set_params.go",
    "x/factory/keeper/k_set_denom.go",
    "x/factory/keeper/keeper.go",
    "x/factory/keeper/msg_server_burn_tokens.go",
    "x/factory/keeper/msg_server_claim_denom_admin.go",
    "x/factory/keeper/msg_server_create_denom.go",
    "x/factory/keeper/msg_server_disable_denom_admin.go",
    "x/factory/keeper/msg_server_mint_and_send_tokens.go",
    "x/factory/keeper/msg_server_propose_denom_admin.go",
    "x/factory/keeper/msg_server_set_denom_metadata.go",
    "x/factory/keeper/msg_server_update_denom_metadata_auth.go",
    "x/factory/keeper/msg_server_update_denom_minting_cap.go",
    "x/factory/keeper/msg_server_update_denom_uri.go",
    "x/factory/keeper/msg_server_withdraw_module_fees.go",
    "x/factory/keeper/msg_server.go",
    "x/factory/keeper/msg_update_params.go",
    "x/factory/keeper/query_denom_all.go",
    "x/factory/keeper/query_denom_auth.go",
    "x/factory/keeper/query_denom_by_admin.go",
    "x/factory/keeper/query_denom_get.go",
    "x/factory/keeper/query_params.go",
    "x/factory/keeper/query.go",
    "x/factory/migrations/new_migrator.go",
    "x/factory/migrations/v2_migration.go",
    "x/factory/module/autocli.go",
    "x/factory/module/genesis.go",
    "x/factory/module/module.go",
    "x/factory/module/simulation.go",
    "x/factory/simulation/burn_token.go",
    "x/factory/simulation/create_denom.go",
    "x/factory/simulation/denom_auth.go",
    "x/factory/simulation/helpers.go",
    "x/factory/simulation/mint_and_send_tokens.go",
    "x/factory/simulation/set_denom_metadata.go",
    "x/factory/simulation/update_denom_metadata_auth.go",
    "x/factory/simulation/update_denom_minting_cap.go",
    "x/factory/simulation/update_denom_uri.go",
    "x/factory/simulation/withdraw_module_fees.go",
    "x/factory/testutil/expected_keepers_mocks.go",
    "x/factory/testutil/mock/types_module_module.go",
    "x/factory/types/codec.go",
    "x/factory/types/denom_auth.pb.go",
    "x/factory/types/denom.pb.go",
    "x/factory/types/denoms.go",
    "x/factory/types/errors.go",
    "x/factory/types/events.go",
    "x/factory/types/expected_keepers.go",
    "x/factory/types/genesis.go",
    "x/factory/types/genesis.pb.go",
    "x/factory/types/key_denom_auth.go",
    "x/factory/types/key_denom.go",
    "x/factory/types/keys.go",
    "x/factory/types/message_burn_token.go",
    "x/factory/types/message_claim_denom_admin.go",
    "x/factory/types/message_mint_and_send_tokens.go",
    "x/factory/types/message_propose_denom_admin.go",
    "x/factory/types/message_set_denom_metadata.go",
    "x/factory/types/message_update_denom_metadata_auth.go",
    "x/factory/types/message_update_denom_minting_cap.go",
    "x/factory/types/message_update_denom_uri.go",
    "x/factory/types/message_withdraw_module_fees.go",
    "x/factory/types/msg_create_denom.go",
    "x/factory/types/msg_update_params.go",
    "x/factory/types/params.go",
    "x/factory/types/params.pb.go",
    "x/factory/types/query.pb.go",
    "x/factory/types/query.pb.gw.go",
    "x/factory/types/tx.pb.go",
    "x/factory/types/types.go",
    "x/tokenwrapper/client/cli/tx.go",
    "x/tokenwrapper/keeper/keeper.go",
    "x/tokenwrapper/keeper/msg_server_add_pauser_address.go",
    "x/tokenwrapper/keeper/msg_server_claim_operator_address.go",
    "x/tokenwrapper/keeper/msg_server_disable_token_wrapper.go",
    "x/tokenwrapper/keeper/msg_server_enable_token_wrapper.go",
    "x/tokenwrapper/keeper/msg_server_fund_module_wallet.go",
    "x/tokenwrapper/keeper/msg_server_propose_operator_address.go",
    "x/tokenwrapper/keeper/msg_server_recover_zig.go",
    "x/tokenwrapper/keeper/msg_server_remove_pauser_address.go",
    "x/tokenwrapper/keeper/msg_server_update_ibc_settings.go",
    "x/tokenwrapper/keeper/msg_server_withdraw_from_module_wallet.go",
    "x/tokenwrapper/keeper/msg_server.go",
    "x/tokenwrapper/keeper/msg_update_params.go",
    "x/tokenwrapper/keeper/params.go",
    "x/tokenwrapper/keeper/query_module_info.go",
    "x/tokenwrapper/keeper/query_params.go",
    "x/tokenwrapper/keeper/query_total_transfers.go",
    "x/tokenwrapper/keeper/query.go",
    "x/tokenwrapper/migrations/new_migrator.go",
    "x/tokenwrapper/migrations/v2_migration.go",
    "x/tokenwrapper/module/autocli.go",
    "x/tokenwrapper/module/genesis.go",
    "x/tokenwrapper/module/handlers.go",
    "x/tokenwrapper/module/ibc_module.go",
    "x/tokenwrapper/module/ics4_wrapper.go",
    "x/tokenwrapper/module/module.go",
    "x/tokenwrapper/module/on_acknowledgment_packet.go",
    "x/tokenwrapper/module/on_recv_packet.go",
    "x/tokenwrapper/module/on_timeout_packet.go",
    "x/tokenwrapper/module/send_packet.go",
    "x/tokenwrapper/module/simulation.go",
    "x/tokenwrapper/module/validators.go",
    "x/tokenwrapper/simulation/helpers.go",
    "x/tokenwrapper/simulation/operations.go",
    "x/tokenwrapper/simulation/recover_zig.go",
    "x/tokenwrapper/simulation/simulation.go",
    "x/tokenwrapper/testutil/expected_ibc_keeper_mocks.go",
    "x/tokenwrapper/testutil/expected_keepers_mocks.go",
    "x/tokenwrapper/testutil/mock/types_module_module.go",
    "x/tokenwrapper/types/codec.go",
    "x/tokenwrapper/types/errors.go",
    "x/tokenwrapper/types/events_ibc.go",
    "x/tokenwrapper/types/expected_ibc_keeper.go",
    "x/tokenwrapper/types/expected_keepers.go",
    "x/tokenwrapper/types/genesis.go",
    "x/tokenwrapper/types/genesis.pb.go",
    "x/tokenwrapper/types/ibc_settings.go",
    "x/tokenwrapper/types/keys.go",
    "x/tokenwrapper/types/message_add_pauser_address.go",
    "x/tokenwrapper/types/message_claim_operator_address.go",
    "x/tokenwrapper/types/message_disable_token_wrapper.go",
    "x/tokenwrapper/types/message_enable_token_wrapper.go",
    "x/tokenwrapper/types/message_fund_module_wallet.go",
    "x/tokenwrapper/types/message_propose_operator_address.go",
    "x/tokenwrapper/types/message_recover_zig.go",
    "x/tokenwrapper/types/message_remove_pauser_address.go",
    "x/tokenwrapper/types/message_update_ibc_settings.go",
    "x/tokenwrapper/types/message_withdraw_from_module_wallet.go",
    "x/tokenwrapper/types/msg_update_params.go",
    "x/tokenwrapper/types/params.go",
    "x/tokenwrapper/types/params.pb.go",
    "x/tokenwrapper/types/query.pb.go",
    "x/tokenwrapper/types/query.pb.gw.go",
    "x/tokenwrapper/types/tx.pb.go",
    "x/tokenwrapper/types/types.go",
    "zutils/constants/denom.go",
    "zutils/constants/global.go",
    "zutils/constants/ibc.go",
    "zutils/constants/pool.go",
    "zutils/debug/print.go",
    "zutils/tests/rand.go",
    "zutils/validators/address.go",
    "zutils/validators/coins.go",
    "zutils/validators/ibc.go",
    "zutils/validators/strings.go",
]

def question_format(question: str) -> str:
    """
    Generates a comprehensive security audit prompt for ZigChain blockchain.

    Args:
        question: A specific security question to investigate

    Returns:
        A formatted prompt string for vulnerability analysis
    """
    prompt = f"""      
You are an **Elite Cosmos SDK Security Auditor** specializing in       
IBC vulnerabilities, consensus attacks, token bridge exploits,       
and cross-chain protocol security. Your task is to analyze the **ZigChain**       
codebase—a Cosmos SDK blockchain with custom TokenWrapper, Factory, and DEX modules—through the lens of this single security question:       
      
**Security Question (scope for this run):** {question}      
      
**ZIGCHAIN CONTEXT:**      
      
**Architecture**: ZigChain is a Cosmos SDK v0.53.4 blockchain with CometBFT v0.38.19 consensus, responsible for       
cross-chain token bridging via IBC, token factory operations, and decentralized exchange functionality.       
It implements custom modules for token wrapping/unwrapping, permissionless token creation, and AMM pools.       
Critical components include the TokenWrapper middleware, Factory token management, DEX liquidity pools, and CosmWasm integration.      
      
Think in invariant violations      
Check every logic entry that could affect consensus or node security based on the question provided       
Look at the exact files provided and other places also if they can cause severe vulnerabilities       
Think in an elite way because there is always a logic vulnerability that could occur      
      
**Key Components**:       
      
* **TokenWrapper Module**: `x/tokenwrapper/` (IBC middleware, decimal conversion, bridge operations),       
  `app/ibc.go` (IBC middleware stack), `x/tokenwrapper/keeper/` (state management, wrapping logic)      
      
* **Factory Module**: `x/factory/` (token creation, minting caps, admin management),       
  `x/factory/keeper/` (denom management, token operations)      
      
* **DEX Module**: `x/dex/` (AMM pools, liquidity operations, swaps),       
  `x/dex/keeper/` (pool management, swap calculations)      
      
* **CosmWasm Integration**: `app/wasm.go` (custom plugins, contract interactions),       
  `x/wasm/` (smart contract runtime)      
      
* **IBC Stack**: `ibc-go/v10` (core IBC implementation),       
  `packet-forward-middleware`, `rate-limiting` (middleware layers)      
      
**Files in Scope**: All source files in the repository, excluding test files and documentation.       
Focus on custom modules, IBC integration, and cross-chain token operations.      
      
**CRITICAL INVARIANTS (derived from Cosmos SDK specification and ZigChain implementation):**      
      
1. **IBC Atomicity**: Cross-chain transfers must be atomic - either complete fully or rollback completely      
2. **Token Conservation**: Total token supply across chains must remain constant during transfers      
3. **Decimal Precision**: Decimal conversions between 18-decimal Axelar tokens and 6-decimal native ZIG must be exact      
4. **Consensus Rules**: Block validation must enforce CometBFT consensus rules strictly      
5. **State Consistency**: State transitions must be atomic and reversible on IBC failure      
6. **Access Control**: Administrative functions must be properly protected by operator/governance roles      
7. **AMM Invariant**: Liquidity pool reserves must maintain constant product formula (x*y=k)      
8. **Minting Caps**: Token creation must respect configured maximum supply limits      
9. **Module Balance**: TokenWrapper module wallet must maintain sufficient balance for wrapping operations      
10. **IBC Protocol Compliance**: All IBC messages must be validated according to ICS-20 specification      
      
**YOUR INVESTIGATION MISSION:**      
      
Accept the premise of the security question and explore **all** relevant       
code paths, data structures, state transitions, and system interactions related to it.       
Trace execution flows through IBC packet handling → token wrapping/unwrapping → state updates →       
block validation → consensus finalization.      
      
Your goal is to find **one** concrete, exploitable vulnerability tied to       
the question that an attacker, malicious relayer, or transaction sender could exploit.       
Focus on:       
      
* IBC protocol violations (packet replay, double-spending, stuck tokens)      
* Token bridge exploits (decimal manipulation, balance draining)      
* AMM implementation bugs (price manipulation, liquidity drain)      
* Factory module vulnerabilities (unlimited minting, admin bypass)      
* CosmWasm integration risks (malicious contract interactions)      
* State manipulation bugs (storage corruption, inconsistent state)      
* Access control bypasses (operator impersonation, privilege escalation)      
* Resource exhaustion attacks (gas manipulation, memory DoS)      
* Cryptographic weaknesses (signature verification, hash collisions)      
* Governance exploits (parameter manipulation, malicious proposals)      
      
**ATTACK SURFACE EXPLORATION:**      
      
1. **TokenWrapper Operations** (`x/tokenwrapper/`):      
   - Decimal conversion errors causing token loss/creation during wrapping      
   - IBC packet replay attacks enabling double-spending across chains      
   - Module wallet drainage through insufficient balance checks      
   - Malicious IBC settings causing tokens to be stuck on Axelar      
   - Recovery mechanism bypasses or exploits in `MsgRecoverZig`      
      
2. **Factory Module** (`x/factory/`):      
   - Minting cap bypasses enabling unlimited token creation      
   - Admin transfer vulnerabilities in proposal/claim system      
   - Denom creation exploits allowing malicious token metadata      
   - Access control failures in token management functions      
      
3. **DEX Module** (`x/dex/`):      
   - AMM calculation errors enabling price manipulation or liquidity drain      
   - Slippage protection bypasses causing unfavorable trades      
   - Pool creation vulnerabilities allowing malicious pool parameters      
   - Liquidity token minting/burning inconsistencies      
      
4. **IBC Protocol** (`app/ibc.go`, `ibc-go/`):      
   - Packet forwarding middleware vulnerabilities enabling token misrouting      
   - Rate limiting bypasses enabling spam or DoS attacks      
   - Acknowledgement handling errors causing state inconsistency      
   - Timeout packet exploits enabling token duplication or loss      
      
5. **CosmWasm Integration** (`app/wasm.go`):      
   - Custom plugin vulnerabilities allowing unauthorized token operations      
   - Contract interaction bugs enabling state manipulation      
   - Gas calculation errors in contract execution      
   - Access control failures in plugin permissions      
      
6. **State Management** (various keepers):      
   - KVStore manipulation vulnerabilities      
   - State migration errors during upgrades      
   - Genesis state validation bypasses      
   - Merkle proof manipulation in state queries      
      
**ZIGCHAIN-SPECIFIC ATTACK VECTORS:**      
      
- **Decimal Conversion Exploits**: Can attackers manipulate the 10^12 scaling factor between 18-decimal and 6-decimal tokens?      
- **Bridge Drainage**: Can attackers drain the TokenWrapper module wallet through crafted IBC packets?      
- **AMM Flash Loan Attacks**: Can attackers exploit the DEX module for price manipulation or liquidity draining?      
- **Factory Minting Exploits**: Can attackers bypass minting caps to create unlimited tokens?      
- **IBC Packet Replay**: Can attackers replay IBC packets to double-spend tokens across chains?      
- **Recovery Mechanism Abuse**: Can attackers exploit `MsgRecoverZig` to steal tokens or bypass controls?      
- **Governance Parameter Manipulation**: Can attackers manipulate module parameters to enable exploits?      
- **CosmWasm Plugin Vulnerabilities**: Can attackers use smart contracts to bypass module access controls?      
- **Middleware Stack Bypasses**: Can attackers bypass IBC middleware validations to send malicious packets?      
- **State Consistency Attacks**: Can attackers create state inconsistencies between modules to cause consensus failures?      
      
**TRUST MODEL:**      
      
**Trusted Roles**: ZigChain core developers, validator operators, governance participants, module operators.       
Do **not** assume these actors behave maliciously unless the question explicitly explores insider threats.      
      
**Untrusted Actors**: Any IBC relayer, transaction sender, contract deployer, or       
malicious actor attempting to exploit protocol vulnerabilities. Focus on bugs exploitable       
without requiring validator access or collusion.      
      
**KNOWN ISSUES / EXCLUSIONS:**      
      
- Cryptographic primitives (Cosmos SDK crypto functions) are assumed secure      
- Network-level attacks (DDoS, BGP hijacking) at infrastructure level      
- Social engineering, phishing, or key theft      
- Performance optimizations unless they introduce security vulnerabilities      
- Code style, documentation, or non-critical bugs      
- Test file issues (tests are out of scope)      
- Economic attacks requiring market manipulation      
- Validator collusion or 1/3+ Byzantine validators      
      
**VALID IMPACT CATEGORIES:**      
      
**Critical Severity**:      
- Cross-chain token duplication or unlimited creation      
- Complete bridge compromise or token drainage      
- Consensus failures or chain splits      
- Network-wide DoS affecting majority of validators      
      
**High Severity**:      
- Single validator compromise or crash      
- Significant token loss (user or protocol)      
- IBC communication failures or stuck tokens      
- AMM liquidity draining or price manipulation      
      
**Medium Severity**:      
- Limited token duplication or loss      
- Module state inconsistency requiring manual intervention      
- Partial IBC functionality disruption      
- Governance parameter manipulation without immediate token loss      
      
**Low Severity**:      
- Minor information leaks in IBC packets      
- Non-critical DoS affecting limited functionality      
- Minor implementation bugs without security impact      
      
**OUTPUT REQUIREMENTS:**      
      
If you discover a valid vulnerability related to the security question,       
produce a **full report** following the format below. Your report must include:       
- Exact file paths and function names      
- Code quotations from the relevant source files      
- Step-by-step exploitation path with realistic parameters      
- Clear explanation of which invariant is broken      
- Impact quantification (affected tokens, potential damage)      
- Likelihood assessment (attacker requirements, complexity)      
- Concrete recommendation with code fix      
- Proof of Concept (Go test or reproduction steps)      
      
If **no** valid vulnerability emerges after thorough investigation, state exactly:       
`#NoVulnerability found for this question.`      
      
**Do not fabricate or exaggerate issues.** Only concrete, exploitable bugs with       
clear attack paths and realistic impact count.      
      
**VALIDATION CHECKLIST (Before Reporting):**      
- [ ] Vulnerability lies within the ZigChain codebase (not tests or docs)      
- [ ] Exploitable by unprivileged attacker (no validator access required)      
- [ ] Attack path is realistic with correct parameters and feasible execution      
- [ ] Impact meets Critical, High, or Medium severity criteria      
- [ ] PoC can be implemented as Go test or clear reproduction steps      
- [ ] Issue breaks at least one documented invariant      
- [ ] Not a known issue from previous security audits      
- [ ] Clear security harm demonstrated (tokens, consensus, availability)      
      
---      
      
**AUDIT REPORT FORMAT** (if vulnerability found):      
      
Audit Report      
      
## Title       
The Title Of the Report       
      
## Summary      
A short summary of the issue, keep it brief.      
      
## Finding Description      
A more detailed explanation of the issue. Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.      
      
## Impact Explanation      
Elaborate on why you've chosen a particular impact assessment.      
      
## Likelihood Explanation      
Explain how likely this is to occur and why.      
      
## Recommendation      
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.      
      
## Proof of Concept      
A proof of concept demonstrating the vulnerability. Must be able to compile and run successfully.      
      
**Remember**: False positives harm credibility more than missed findings. Assume claims are invalid until overwhelming evidence proves otherwise.      
      
**Now perform STRICT validation of the claim above.**      
      
**Output ONLY:**      
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format      
- `#NoVulnerability found for this question.` (if **any** check fails)      
      
**Be ruthlessly skeptical. The bar for validity is EXTREMELY high.**      
"""
    return prompt

def validation_format(report: str) -> str:
    """
    Generates a comprehensive validation prompt for ZigChain security claims.

    Args:
        report: A security vulnerability report to validate

    Returns:
        A formatted validation prompt string for ruthless technical scrutiny
    """
    prompt = f"""    
You are an **Elite Cosmos SDK Security Judge** with deep expertise in IBC vulnerabilities, token bridge exploits, consensus attacks, and cross-chain protocol security. Your ONLY task is **ruthless technical validation** of security claims against the ZigChain codebase.    
    
Note: ZigChain core developers, validator operators, and governance participants are trusted roles.    
    
**SECURITY CLAIM TO VALIDATE:**    
{report}    
    
================================================================================    
## **ZIGCHAIN VALIDATION FRAMEWORK**    
    
### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**    
Reject immediately (`#NoVulnerability`) if **ANY** apply:    
    
#### **A. Scope Violations**    
- ❌ Affects files **not** in ZigChain source code (`x/`, `app/`, `zutils/`, `cmd/`)    
- ❌ Targets any file under test directories (`*_test.go`, `testdata/`) - tests are out of scope    
- ❌ Claims about documentation, comments, code style, or logging (not security issues)    
- ❌ Focuses on external Cosmos SDK modules or third-party dependencies    
    
**In-Scope Components:**    
- **TokenWrapper Module**: `x/tokenwrapper/` (IBC bridging, decimal conversion, recovery)    
- **Factory Module**: `x/factory/` (token creation, minting caps, admin management)    
- **DEX Module**: `x/dex/` (AMM pools, liquidity operations, swaps)    
- **Validation Utilities**: `zutils/validators/` (address, coin, IBC validation)    
- **IBC Integration**: `app/ibc.go` (middleware stack, channel handling)    
- **CosmWasm Integration**: `app/wasm.go` (custom plugins, contract interactions)    
    
**Verify**: Check that every file path cited in the report matches the ZigChain source structure.    
    
#### **B. Threat Model Violations**    
- ❌ Requires compromised ZigChain core developers or validator operators    
- ❌ Assumes 1/3+ Byzantine validators (consensus compromise)    
- ❌ Needs IBC relayer collusion across multiple chains    
- ❌ Assumes cryptographic primitives in Cosmos SDK are broken    
- ❌ Depends on social engineering, phishing, or key theft    
- ❌ Relies on infrastructure attacks: DDoS, BGP hijacking, DNS poisoning    
    
**Trusted Roles**: ZigChain core developers, validator operators, governance participants, module operators. Do **not** assume these actors behave maliciously.    
    
**Untrusted Actors**: Any IBC relayer, transaction sender, contract deployer, or malicious actor attempting to exploit protocol vulnerabilities.    
    
#### **C. Known Issues / Exclusions**    
- ❌ Any finding already documented in CHANGELOG.md or security advisories    
- ❌ Issues inherited from Cosmos SDK or IBC-go modules    
- ❌ Performance optimizations unless they introduce security vulnerabilities    
- ❌ Gas optimization or efficiency improvements without security impact    
- ❌ Code style, documentation, or non-critical bugs    
    
#### **D. Non-Security Issues**    
- ❌ Performance improvements, memory optimizations, or micro-optimizations    
- ❌ Code style, naming conventions, or refactoring suggestions    
- ❌ Missing events, logs, error messages, or better user experience    
- ❌ Documentation improvements, README updates, or comment additions    
- ❌ "Best practices" recommendations with no concrete exploit scenario    
- ❌ Minor precision errors with negligible impact (<0.01%)    
    
#### **E. Invalid Exploit Scenarios**    
- ❌ Requires impossible inputs: negative token amounts, invalid IBC packets    
- ❌ Cannot be triggered through any realistic transaction or IBC message    
- ❌ Depends on calling internal keeper functions not exposed through messages    
- ❌ Relies on race conditions prevented by blockchain's atomic nature    
- ❌ Needs multiple coordinated blocks with no economic incentive    
- ❌ Requires attacker to control validator set or governance    
- ❌ Depends on IBC timeout manipulation beyond protocol rules    
    
### **PHASE 2: ZIGCHAIN-SPECIFIC DEEP CODE VALIDATION**    
    
#### **Step 1: TRACE COMPLETE EXECUTION PATH THROUGH COSMOS SDK ARCHITECTURE**    
    
**ZigChain Flow Patterns:**    
    
1. **Message Processing Flow**:    
   Transaction → `app.go` router → module handler → keeper → state update → events    
    
2. **IBC Packet Flow**:    
   IBC packet → middleware stack → `OnRecvPacket` → token wrapping/unwrapping → state update → acknowledgement    
    
3. **TokenWrapper Flow**:    
   `MsgWrap/Unwrap` → validation → decimal conversion → bank keeper → module wallet → IBC transfer    
    
4. **Factory Token Flow**:    
   `MsgCreateDenom` → validation → minting cap check → bank keeper → token creation    
    
5. **DEX Swap Flow**:    
   `MsgSwap` → pool validation → AMM calculation → token transfer → liquidity update    
    
For each claim, reconstruct the entire execution path:    
    
1. **Identify Entry Point**: Which message or IBC packet triggers the issue?    
2. **Follow Internal Calls**: Trace through all keeper and handler calls    
3. **State Before Exploit**: Document initial state (balances, allowances, parameters)    
4. **State Transitions**: Enumerate all changes (balance updates, parameter modifications)    
5. **Check Protections**: Verify if existing validations prevent the exploit    
6. **Final State**: Show how the exploit results in incorrect state or token loss    
    
#### **Step 2: VALIDATE EVERY CLAIM WITH CODE EVIDENCE**    
    
For **each assertion** in the report, demand:    
    
**✅ Required Evidence:**    
- Exact file path and line numbers (e.g., `x/tokenwrapper/keeper/msg_server_wrap.go:123-127`)    
- Direct Go code quotes showing the vulnerable logic    
- Call traces with actual parameter values demonstrating execution path    
- Calculations showing decimal conversions, balance changes, or state updates incorrectly    
- References to specific IBC protocol violations or Cosmos SDK invariants    
    
**🚩 RED FLAGS (indicate INVALID):**    
    
1. **"Missing Validation" Claims**:    
   - ❌ Invalid unless report shows input bypasses *all* validation layers:    
     - Message validation in `ValidateBasic()` methods    
     - Keeper-level validation in handler functions    
     - Bank keeper validation in token operations    
     - IBC middleware validation in packet handling    
   - ✅ Valid if a specific input type genuinely has no validation path    
    
2. **"Decimal Conversion" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Incorrect scaling in `ScaleDownTokenPrecision` or `ScaleUpTokenPrecision`    
     - Precision loss causing token creation/destruction    
     - Overflow/underflow in conversion calculations    
   - ✅ Valid if decimal errors enable token duplication or loss    
    
3. **"Access Control" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Unauthorized access to operator functions    
     - Bypass of pauser/role validation in message handlers    
     - Privilege escalation through parameter manipulation    
   - ✅ Valid if access control bypass enables token theft or module control    
    
4. **"IBC Protocol" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Packet replay attacks enabling double-spending    
     - Acknowledgement forging causing state inconsistency    
     - Timeout exploits enabling token duplication    
   - ✅ Valid if IBC bugs affect cross-chain token transfers    
    
5. **"AMM Manipulation" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Price calculation errors in swap functions    
     - Liquidity drain through mathematical exploits    
     - Slippage protection bypasses    
   - ✅ Valid if AMM bugs enable token drainage or price manipulation    
    
6. **"Factory Minting" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - Minting cap bypasses enabling unlimited token creation    
     - Admin transfer vulnerabilities in token management    
     - Denom creation exploits allowing malicious tokens    
   - ✅ Valid if factory bugs enable unlimited token minting    
    
7. **"Recovery Mechanism" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - `MsgRecoverZig` bypasses operator restrictions    
     - Decimal conversion errors in recovery process    
     - Module wallet drainage through recovery exploits    
   - ✅ Valid if recovery bugs enable token theft or duplication    
    
8. **"State Consistency" Claims**:    
   - ❌ Invalid unless report demonstrates:    
     - KVStore manipulation vulnerabilities    
     - State migration errors during upgrades    
     - Genesis state validation bypasses    
   - ✅ Valid if state bugs cause consensus failures or token loss    
    
#### **Step 3: CROSS-REFERENCE WITH ZIGCHAIN SPECIFIC VULNERABILITIES**    
    
Check against known ZigChain vulnerability patterns:    
    
1. **Historical Patterns**: Does this match known vulnerability types?    
   - Decimal conversion errors in TokenWrapper    
   - Access control bypasses in operator functions    
   - IBC packet handling vulnerabilities    
    
2. **Fixed Issues**: Is this already fixed in current versions?    
   - Check CHANGELOG.md for security fixes    
   - Verify if the report affects current codebase    
    
3. **Test Coverage**: Would existing tests catch this?    
   - Check `x/tokenwrapper/keeper/msg_server_*_test.go`    
   - Review validation tests in `zutils/validators/*_test.go`    
   - Examine integration tests for IBC flows    
    
**Test Case Realism Check**: PoCs must use realistic Cosmos SDK state, valid transactions, and respect IBC protocol rules.    
    
### **PHASE 3: IMPACT & EXPLOITABILITY VALIDATION**    
    
#### **Impact Must Be CONCRETE and ALIGN WITH ZIGCHAIN SECURITY SCOPE**    
    
**✅ Valid CRITICAL Severity Impacts:**    
    
1. **Cross-Chain Token Duplication (Critical)**:    
   - Ability to create unlimited tokens across chains    
   - IBC bridge compromise allowing double-spending    
   - Example: "Decimal conversion bug allows token duplication in IBC transfers"    
    
2. **Complete Bridge Drainage (Critical)**:    
   - Module wallet drained through vulnerability    
   - All wrapped tokens become unrecoverable    
   - Example: "Recovery mechanism bypass drains TokenWrapper module wallet"    
    
3. **Consensus Failures (Critical)**:    
   - State inconsistencies causing chain splits    
   - Validator disagreement on state transitions    
   - Example: "State manipulation bug causes different validators to compute different states"    
    
4. **Network-Wide DoS (Critical)**:    
   - Vulnerability crashes majority of validators    
   - IBC communication halted across network    
   - Example: "Packet handling bug crashes all validators on IBC message"    
    
**✅ Valid HIGH Severity Impacts:**    
    
5. **Significant Token Loss (High)**:    
   - Single user or protocol token drainage    
   - AMM liquidity draining exploits    
   - Factory token creation bypasses    
    
6. **IBC Communication Failures (High)**:    
   - Tokens stuck in transit between chains    
   - Partial bridge functionality disruption    
   - Timeout or acknowledgement bugs    
    
**✅ Valid MEDIUM Severity Impacts:**    
    
7. **Limited Token Duplication (Medium)**:    
   - Small-scale token creation or loss    
   - Module state inconsistency requiring manual intervention    
   - Parameter manipulation without immediate token loss    
    
**❌ Invalid "Impacts":**    
    
- Minor performance degradation    
- Theoretical vulnerabilities without exploit    
- Market risk or price manipulation    
- "Could be problematic if..." without concrete path    
- Minor gas overpayment (<0.1% of transaction)    
    
#### **Likelihood Reality Check**    
    
Assess exploit feasibility:    
    
1. **Attacker Profile**:    
   - Any ZigChain user? ✅ Likely    
   - IBC relayer? ✅ Possible    
   - Contract deployer? ✅ Possible    
   - Token holder? ✅ Possible    
    
2. **Preconditions**:    
   - Normal network operation? ✅ High likelihood    
   - Specific IBC channel? ✅ Attacker can create    
   - Token balances? ✅ Attacker can acquire    
   - Specific module parameters? ✅ Possible but not required    
    
3. **Execution Complexity**:    
   - Single transaction? ✅ Simple    
   - IBC packet sequence? ✅ Moderate    
   - Complex contract interaction? ✅ Attacker can create    
   - Precise timing? ⚠️ Higher complexity    
    
4. **Economic Cost**:    
   - Gas fees for attack? ✅ Attacker-controlled    
   - Initial capital required? ✅ Varies by attack    
   - Potential profit vs. cost? ✅ Must be positive    
    
### **PHASE 4: FINAL VALIDATION CHECKLIST**    
    
Before accepting any vulnerability, verify:    
    
1. **Scope Compliance**: Vulnerability affects ZigChain source code (not tests/docs)    
2. **Not Known Issue**: Check against CHANGELOG.md and security advisories    
3. **Trust Model**: Exploit doesn't require trusted role compromise    
4. **Impact Severity**: Meets Critical/High/Medium criteria    
5. **Technical Feasibility**: Exploit can be reproduced without modifications    
6. **IBC Protocol Impact**: Clearly breaks IBC or Cosmos SDK rules    
7. **PoC Completeness**: Go test compiles and runs successfully with proper setup    
    
**Remember**: False positives harm credibility. Assume claims are invalid until overwhelming evidence proves otherwise.    
    
---    
    
**AUDIT REPORT FORMAT** (if vulnerability found):    
    
Audit Report    
    
## Title    
The Title Of the Report    
    
## Summary    
A short summary of the issue, keep it brief.    
    
## Finding Description    
A more detailed explanation of the issue. Poorly written or incorrect findings may result in rejection and a decrease of reputation score.    
    
Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.    
    
## Impact Explanation    
Elaborate on why you've chosen a particular impact assessment.    
    
## Likelihood Explanation    
Explain how likely this is to occur and why.    
    
## Recommendation    
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.    
    
## Proof of Concept    
A proof of concept is normally required for Critical, High and Medium Submissions for reviewers under 80 reputation points. Please check the competition page for more details, otherwise your submission may be rejected by the judges.    
Very important the test function using their test must be provided in here and pls it must be able to compile and run successfully    
    
**Remember**: False positives harm credibility more than missed findings. Assume claims are invalid until overwhelming evidence proves otherwise.    
    
**Now perform STRICT validation of the claim above.**    
    
**Output ONLY:**    
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format    
- `#NoVulnerability found for this question.` (if **any** check fails) very important    
    
**Be ruthlessly skeptical. The bar for validity is EXTREMELY high.**    
"""
    return prompt
def question_generator(target_file: str) -> str:
    """
    Generates targeted security audit questions for a specific ZigChain file.

    Args:
        target_file: The specific file path to focus question generation on
                    (e.g., "x/tokenwrapper/keeper/msg_server_wrap.go" or "x/factory/keeper/denom.go")

    Returns:
        A formatted prompt string for generating security questions
    """
    prompt = f"""    
# **Generate 150+ Targeted Security Audit Questions for ZigChain**    
    
## **Context**    
    
The target project is **ZigChain**, a Cosmos SDK v0.53.4 blockchain with CometBFT v0.38.19 consensus, responsible for cross-chain token bridging via IBC, token factory operations, and decentralized exchange functionality. ZigChain implements custom modules for token wrapping/unwrapping, permissionless token creation, and AMM pools.    
    
ZigChain uses IBC (Inter-Blockchain Communication) protocol for cross-chain token transfers, with a TokenWrapper middleware that handles decimal conversion between 18-decimal Axelar tokens and 6-decimal native ZIG tokens. The system includes a Factory module for permissionless token creation with minting caps, and a DEX module for automated market maker operations.    
    
## **Scope**    
    
**CRITICAL TARGET FILE**: Focus question generation EXCLUSIVELY on `{target_file}`    
    
Note: The questions must be generated from **`{target_file}`** only. If you cannot generate enough questions from this single file, provide as many quality questions as you can extract from the file's logic and interactions. **DO NOT return empty results** - give whatever questions you can derive from the target file.    
    
If you cannot reach 150 questions from this file alone, generate as many high-quality questions as the file's complexity allows (minimum target: 50-100 questions for large critical files, 20-50 for smaller files).    
    
**Full Context - Critical ZigChain Components (for reference only):**    
If a file is more than a thousand lines you can generate as many as 300+ questions as you can, but always generate as many as you can - don't give other responses.    
If there are cryptographic operations, math logic, or state transition functions, generate comprehensive questions covering all edge cases and attack vectors.    
    
### **Core ZigChain Components**    
    
```python    
core_components = [    
    # TokenWrapper Module    
    "x/tokenwrapper/keeper/msg_server_wrap.go",        # Token wrapping logic    
    "x/tokenwrapper/keeper/msg_server_unwrap.go",      # Token unwrapping logic    
    "x/tokenwrapper/keeper/msg_server_recover_zig.go", # Recovery mechanism    
    "x/tokenwrapper/keeper/msg_server_update_ibc_settings.go", # IBC settings    
    "x/tokenwrapper/keeper/keeper.go",                 # Core keeper functions    
    "x/tokenwrapper/keeper/ibc_middleware.go",         # IBC middleware handling    
        
    # Factory Module    
    "x/factory/keeper/msg_server_create_denom.go",     # Token creation    
    "x/factory/keeper/msg_server_mint_and_send.go",    # Token minting    
    "x/factory/keeper/msg_server_burn_tokens.go",      # Token burning    
    "x/factory/keeper/keeper.go",                      # Factory keeper    
    "x/factory/keeper/denom.go",                       # Denom management    
        
    # DEX Module    
    "x/dex/keeper/msg_server_create_pool.go",          # Pool creation    
    "x/dex/keeper/msg_server_swap.go",                 # Swap operations    
    "x/dex/keeper/msg_server_add_liquidity.go",        # Liquidity provision    
    "x/dex/keeper/keeper.go",                          # DEX keeper    
    "x/dex/keeper/pool.go",                            # Pool management    
        
    # Validation Utilities    
    "zutils/validators/coins.go",                      # Coin validation    
    "zutils/validators/ibc.go",                        # IBC validation    
    "zutils/validators/address.go",                    # Address validation    
        
    # IBC Integration    
    "app/ibc.go",                                      # IBC middleware stack    
    "x/tokenwrapper/ibc_hooks.go",                     # IBC hooks    
        
    # CosmWasm Integration    
    "app/wasm.go",                                     # Custom plugins    
    "wasmbinding/query_plugin.go",                     # Query plugins    
]
ZigChain Architecture & Critical Security Layers
TokenWrapper Module (Cross-Chain Bridge)
Decimal Conversion: Handles 18→6 decimal precision conversion using 10^12 scaling factor
IBC Middleware: Processes IBC packets for cross-chain transfers
Recovery Mechanism: Permissionless recovery of stuck tokens via MsgRecoverZig
Module Wallet: Holds native ZIG tokens for wrapping operations
Operator Controls: Administrative functions for bridge management
Factory Module (Token Creation)
Permissionless Creation: Anyone can create new tokens
Minting Caps: Configurable maximum supply limits per token
Admin Management: Proposal/claim system for denom admin transfers
Metadata Control: Token metadata management with role-based access
DEX Module (AMM Operations)
Constant Product AMM: Uses x*y=k formula for price determination
Liquidity Pools: User-provided liquidity for token swaps
Slippage Protection: Minimum output calculations for swaps
Pool Tokens: LP tokens representing liquidity provider shares
IBC Protocol Layer
Packet Forwarding: Middleware for routing IBC packets
Rate Limiting: Anti-spam protection for IBC operations
Acknowledgement Handling: Success/failure processing for transfers
Timeout Management: Handling of timed-out IBC packets
Validation Layer
Address Validation: Bech32 address format checking
Coin Validation: Amount and denomination validation
IBC Parameter Validation: Channel and port validation
State Consistency: KVStore integrity checks
Critical Security Invariants
TokenWrapper Security

Decimal Precision: 18→6 decimal conversion must be exact with no precision loss
Token Conservation: Total supply across chains must remain constant
Module Balance: Module wallet must have sufficient native tokens for unwrapping
Operator Exclusion: Recovery mechanism cannot be used by operator address
IBC Atomicity: Cross-chain transfers must be atomic (all or nothing)
Factory Security

Minting Cap Enforcement: Token creation cannot exceed configured limits
Access Control: Admin functions must be properly protected
Denom Uniqueness: Each denom must be unique and non-collidable
Metadata Integrity: Token metadata cannot be manipulated arbitrarily
DEX Security

AMM Invariant: Liquidity pool reserves must maintain x*y=k
Price Manipulation: Swaps cannot be exploited for price manipulation
Liquidity Token Integrity: LP token minting/burning must match liquidity changes
Slippage Protection: Minimum output calculations must be accurate
IBC Security

Packet Uniqueness: IBC packets cannot be replayed or double-spent
Acknowledgement Authenticity: Packet acknowledgments must be valid
Timeout Enforcement: Expired packets cannot be processed
Channel Validation: All IBC channel operations must be validated
In-Scope Vulnerability Categories
Focus questions on vulnerabilities that lead to these impacts:

Critical Severity

Cross-Chain Token Duplication: Creating unlimited tokens across chains
Complete Bridge Drainage: Draining all tokens from module wallet
Consensus Failures: State inconsistencies causing chain splits
Network-Wide DoS: Crashing majority of validators via IBC bugs
High Severity

Significant Token Loss: Draining user or protocol funds
IBC Communication Failures: Tokens stuck in transit
AMM Liquidity Draining: Exploiting price calculation bugs
Factory Minting Bypass: Creating unlimited tokens
Medium Severity

Limited Token Duplication: Small-scale token creation/loss
State Inconsistency: Requiring manual intervention
Parameter Manipulation: Governance parameter exploits
Partial IBC Disruption: Limited bridge functionality loss
Goals for Question Generation
Real Exploit Scenarios: Each question describes a plausible attack by relayers, users, or malicious actors
Concrete & Actionable: Reference specific functions, variables, structs in {target_file}
High Impact: Prioritize questions leading to Critical/High/Medium impacts
Deep Technical Detail: Focus on subtle bugs: decimal conversion errors, race conditions, state transitions, IBC protocol violations
Breadth Within Target File: Cover all major functions, edge cases, and state-changing operations in {target_file}
Respect Trust Model: Assume validators may be Byzantine (up to 1/3); focus on protocol-level security
No Generic Questions: Avoid "are there access control issues?" → Instead: "In {target_file}: functionName(), if condition X occurs during decimal conversion, can attacker exploit Y to duplicate tokens, leading to cross-chain token duplication?"
Question Format Template
Each question MUST follow this Python list format:

questions = [    
    "[File: {target_file}] [Function: functionName()] [Vulnerability Type] Specific question describing attack vector, preconditions, and impact with severity category?",    
        
    "[File: {target_file}] [Function: anotherFunction()] [Vulnerability Type] Another specific question with concrete exploit scenario?",    
        
    # ... continue with all generated questions    
]
Example Format (if target_file is x/tokenwrapper/keeper/msg_server_recover_zig.go):

questions = [    
    "[File: x/tokenwrapper/keeper/msg_server_recover_zig.go] [Function: RecoverZig()] [Decimal conversion] Can an attacker exploit the ScaleDownTokenPrecision function during recovery to manipulate the 10^12 conversion factor, causing token duplication when converting 18-decimal IBC vouchers to 6-decimal native ZIG? (Critical)",    
        
    "[File: x/tokenwrapper/keeper/msg_server_recover_zig.go] [Function: RecoverZig()] [Access control] Does the operator address check properly validate all possible address formats, or can an attacker craft a specially formatted address that bypasses the operator exclusion to drain the module wallet through the recovery mechanism? (High)",    
        
    "[File: x/tokenwrapper/keeper/msg_server_recover_zig.go] [Function: RecoverZig()] [State inconsistency] Can an attacker trigger a race condition between the IBC voucher lock and native token release operations, causing state inconsistency where vouchers are locked but native tokens are not released, leading to permanent token loss? (Medium)",    
        
    "[File: x/tokenwrapper/keeper/msg_server_recover_zig.go] [Function: RecoverZig()] [Module balance] Can an attacker exploit insufficient balance checks in the recovery mechanism to trigger partial recoveries that drain the module wallet below required thresholds, causing bridge functionality to fail for all users? (High)",    
]
Output Requirements
Generate security audit questions focusing EXCLUSIVELY on {target_file} that:

Target ONLY {target_file} - all questions must reference this file
Reference specific functions, methods, structs, or logic sections within {target_file}
Describe concrete attack vectors (not "could there be a bug?" but "can attacker do X by exploiting Y in {target_file}?")
Tie to impact categories (token duplication, bridge drainage, consensus failure, DoS, state corruption)
Include severity classification (Critical/High/Medium/Low) based on impact
Respect trust model (assume up to 1/3 Byzantine validators; focus on protocol security)
Cover diverse attack surfaces within {target_file}: validation logic, state transitions, error handling, edge cases, decimal conversions, IBC operations
Focus on high-severity bugs: prioritize Critical > High > Medium > Low
Avoid out-of-scope issues: gas optimization, code style, already-fixed upstream bugs, smart contract vulnerabilities
Use the exact Python list format shown above
Be detailed and technical: assume auditor has deep Cosmos SDK/IBC knowledge; use precise terminology
Consider Go-specific issues: race conditions, panic/recover, nil pointer dereference, integer overflow, slice bounds, goroutine leaks
Target Question Count
For large critical files (>1000 lines like keeper.go, ibc_middleware.go): Aim for 150-300 questions
For medium files (500-1000 lines like msg_server_*.go): Aim for 80-150 questions
For smaller files (<500 lines like validators/*.go): Aim for 30-80 questions
Provide as many quality questions as the file's complexity allows - do NOT return empty results
Special Considerations for ZigChain Code
Decimal Conversion: Pay special attention to ScaleDownTokenPrecision and ScaleUpTokenPrecision functions
IBC Protocol: Focus on packet handling, acknowledgments, and timeout logic
State Transitions: Atomic operations and rollback scenarios
Access Control: Operator, pauser, and admin role validations
Module Interactions: Cross-module dependencies and state sharing
Error Handling: Proper error propagation and state cleanup
Resource Management: Gas costs and memory usage in operations
Begin generating questions for {target_file} now.
"""
    return prompt