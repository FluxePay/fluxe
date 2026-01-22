# FLUXE Client SDK

The `FluxeClient` provides a Rust SDK for interacting with the FLUXE API server. It handles proof generation, serialization, and API communication.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
fluxe-api = { path = "../fluxe-api" }
fluxe-core = { path = "../fluxe-core" }
fluxe-circuits = { path = "../fluxe-circuits" }
ark-bn254 = "0.5"
ark-groth16 = "0.5"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use fluxe_api::client::FluxeClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client
    let client = FluxeClient::new("http://localhost:3000".to_string());

    // Check server health
    let is_healthy = client.health_check().await?;
    println!("Server healthy: {}", is_healthy);

    // Get current state roots
    let roots = client.get_roots().await?;
    println!("CMT Root: {}", roots.cmt_root);

    Ok(())
}
```

## Client Initialization

### `FluxeClient::new`

Create a new client instance.

```rust
pub fn new(base_url: String) -> Self
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `base_url` | `String` | Base URL of the FLUXE API server |

**Example:**

```rust
// Local development
let client = FluxeClient::new("http://localhost:3000".to_string());

// Production
let client = FluxeClient::new("https://api.fluxe.network".to_string());
```

---

## Transaction Methods

### `submit_mint`

Submit a mint transaction to deposit assets into FLUXE.

```rust
pub async fn submit_mint(
    &self,
    asset_type: AssetType,
    amount: u64,
    recipient_addr: F,
    proving_key: &ProvingKey<Bn254>,
) -> Result<String, Box<dyn Error>>
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `asset_type` | `AssetType` | Asset type identifier (e.g., 1 for USDC) |
| `amount` | `u64` | Amount to mint in smallest unit |
| `recipient_addr` | `F` | Recipient's address (field element) |
| `proving_key` | `&ProvingKey<Bn254>` | Groth16 proving key for mint circuit |

**Returns:** Transaction ID string on success.

**Example:**

```rust
use ark_bn254::Fr as F;
use ark_ff::UniformRand;
use fluxe_circuits::mint::MintCircuit;

async fn mint_example(client: &FluxeClient) -> Result<(), Box<dyn std::error::Error>> {
    // Load proving key (generated during setup)
    let pk = load_proving_key("mint.pk")?;

    // Generate recipient address
    let mut rng = rand::thread_rng();
    let recipient = F::rand(&mut rng);

    // Submit mint: 1000 USDC (asset_type = 1)
    let tx_id = client.submit_mint(
        1,           // asset_type: USDC
        1_000_000,   // amount: 1 USDC (6 decimals)
        recipient,
        &pk,
    ).await?;

    println!("Mint transaction submitted: {}", tx_id);
    Ok(())
}
```

---

### `submit_burn`

Submit a burn transaction to withdraw assets from FLUXE.

```rust
pub async fn submit_burn(
    &self,
    note: Note,
    value: u64,
    value_randomness: F,
    owner_sk: F,
    nk: F,
    cm_path: MerklePath,
    proving_key: &ProvingKey<Bn254>,
    nft_root_old: F,
    exit_root_old: F,
) -> Result<String, Box<dyn Error>>
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `note` | `Note` | The note to burn |
| `value` | `u64` | Value contained in the note |
| `value_randomness` | `F` | Randomness used in the value commitment |
| `owner_sk` | `F` | Owner's secret key |
| `nk` | `F` | Nullifier key |
| `cm_path` | `MerklePath` | Merkle path for the note commitment |
| `proving_key` | `&ProvingKey<Bn254>` | Groth16 proving key for burn circuit |
| `nft_root_old` | `F` | Current nullifier tree root |
| `exit_root_old` | `F` | Current exit tree root |

**Returns:** Transaction ID string on success.

**Example:**

```rust
use fluxe_core::merkle::MerklePath;

async fn burn_example(
    client: &FluxeClient,
    note: Note,
    value: u64,
    value_randomness: F,
    owner_sk: F,
    nk: F,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load proving key
    let pk = load_proving_key("burn.pk")?;

    // Get current state roots
    let roots = client.get_roots().await?;
    let nft_root = parse_field(&roots.nft_root)?;
    let exit_root = parse_field(&roots.exit_root)?;

    // Get commitment proof from API
    let cm = note.commitment();
    let proof_response = client.get_commitment_proof(&cm).await?;
    let cm_path = build_merkle_path(&proof_response)?;

    // Submit burn
    let tx_id = client.submit_burn(
        note,
        value,
        value_randomness,
        owner_sk,
        nk,
        cm_path,
        &pk,
        nft_root,
        exit_root,
    ).await?;

    println!("Burn transaction submitted: {}", tx_id);
    Ok(())
}
```

---

### `submit_transfer`

Submit a private transfer transaction.

```rust
pub async fn submit_transfer(
    &self,
    notes_in: Vec<Note>,
    values_in: Vec<u64>,
    value_randomness_in: Vec<F>,
    notes_out: Vec<Note>,
    values_out: Vec<u64>,
    value_randomness_out: Vec<F>,
    nks: Vec<F>,
    owner_sks: Vec<F>,
    cm_paths: Vec<MerklePath>,
    proving_key: &ProvingKey<Bn254>,
    old_roots: (F, F),
) -> Result<String, Box<dyn Error>>
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `notes_in` | `Vec<Note>` | Input notes to spend |
| `values_in` | `Vec<u64>` | Values of input notes |
| `value_randomness_in` | `Vec<F>` | Randomness for input value commitments |
| `notes_out` | `Vec<Note>` | Output notes to create |
| `values_out` | `Vec<u64>` | Values of output notes |
| `value_randomness_out` | `Vec<F>` | Randomness for output value commitments |
| `nks` | `Vec<F>` | Nullifier keys for input notes |
| `owner_sks` | `Vec<F>` | Owner secret keys for input notes |
| `cm_paths` | `Vec<MerklePath>` | Merkle paths for input commitments |
| `proving_key` | `&ProvingKey<Bn254>` | Groth16 proving key for transfer circuit |
| `old_roots` | `(F, F)` | Tuple of (cmt_root_old, nft_root_old) |

**Returns:** Transaction ID string on success.

**Example:**

```rust
async fn transfer_example(
    client: &FluxeClient,
    input_note: Note,
    input_value: u64,
    input_randomness: F,
    recipient_addr: F,
    nk: F,
    owner_sk: F,
) -> Result<(), Box<dyn std::error::Error>> {
    let pk = load_proving_key("transfer.pk")?;

    // Get current roots
    let roots = client.get_roots().await?;
    let cmt_root = parse_field(&roots.cmt_root)?;
    let nft_root = parse_field(&roots.nft_root)?;

    // Get commitment proof
    let cm = input_note.commitment();
    let proof_response = client.get_commitment_proof(&cm).await?;
    let cm_path = build_merkle_path(&proof_response)?;

    // Create output note
    let params = PedersenParams::setup_value_commitment();
    let out_randomness = F::rand(&mut rand::thread_rng());
    let out_v_comm = PedersenCommitment::commit(
        &params,
        input_value - 10, // Subtract fee
        &PedersenRandomness { r: out_randomness },
    );

    let output_note = Note::new(
        input_note.asset_type,
        out_v_comm,
        recipient_addr,
        rand::random(),
        1,
    );

    // Submit transfer
    let tx_id = client.submit_transfer(
        vec![input_note],
        vec![input_value],
        vec![input_randomness],
        vec![output_note],
        vec![input_value - 10],
        vec![out_randomness],
        vec![nk],
        vec![owner_sk],
        vec![cm_path],
        &pk,
        (cmt_root, nft_root),
    ).await?;

    println!("Transfer submitted: {}", tx_id);
    Ok(())
}
```

---

## State Query Methods

### `get_roots`

Get current state roots.

```rust
pub async fn get_roots(&self) -> Result<StateRootsResponse, Box<dyn Error>>
```

**Returns:** `StateRootsResponse` containing all Merkle roots.

**Example:**

```rust
async fn query_roots(client: &FluxeClient) -> Result<(), Box<dyn std::error::Error>> {
    let roots = client.get_roots().await?;

    println!("Commitment Root: {}", roots.cmt_root);
    println!("Nullifier Root: {}", roots.nft_root);
    println!("Object Root: {}", roots.obj_root);
    println!("Callback Root: {}", roots.cb_root);
    println!("Ingress Root: {}", roots.ingress_root);
    println!("Exit Root: {}", roots.exit_root);
    println!("Sanctions Root: {}", roots.sanctions_root);
    println!("Pool Rules Root: {}", roots.pool_rules_root);

    Ok(())
}
```

---

### `get_supply`

Get supply information for an asset.

```rust
pub async fn get_supply(&self, asset_type: AssetType) -> Result<SupplyResponse, Box<dyn Error>>
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `asset_type` | `AssetType` | Asset type identifier |

**Returns:** `SupplyResponse` with supply statistics.

**Example:**

```rust
async fn query_supply(client: &FluxeClient) -> Result<(), Box<dyn std::error::Error>> {
    // Query USDC supply (asset_type = 1)
    let supply = client.get_supply(1).await?;

    println!("Asset Type: {}", supply.asset_type);
    println!("Total Minted: {}", supply.minted_total);
    println!("Total Burned: {}", supply.burned_total);
    println!("Current Supply: {}", supply.current_supply);

    Ok(())
}
```

---

## Proof Query Methods

### `get_commitment_proof`

Get a membership proof for a note commitment.

```rust
pub async fn get_commitment_proof(&self, cm: &F) -> Result<ProofResponse, Box<dyn Error>>
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `cm` | `&F` | Commitment field element |

**Returns:** `ProofResponse` with Merkle path if commitment exists.

**Example:**

```rust
async fn check_commitment(
    client: &FluxeClient,
    note: &Note,
) -> Result<bool, Box<dyn std::error::Error>> {
    let cm = note.commitment();
    let proof = client.get_commitment_proof(&cm).await?;

    if proof.exists {
        println!("Note is in the commitment tree at index {}", proof.index.unwrap());
        println!("Merkle path has {} siblings", proof.path.unwrap().len());
        Ok(true)
    } else {
        println!("Note not found in commitment tree");
        Ok(false)
    }
}
```

---

### `get_nullifier_proof`

Get a membership or non-membership proof for a nullifier.

```rust
pub async fn get_nullifier_proof(&self, nf: &F) -> Result<ProofResponse, Box<dyn Error>>
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `nf` | `&F` | Nullifier field element |

**Returns:** `ProofResponse` indicating if nullifier exists (note already spent).

**Example:**

```rust
async fn check_note_spent(
    client: &FluxeClient,
    note: &Note,
    nk: &F,
) -> Result<bool, Box<dyn std::error::Error>> {
    let nf = note.nullifier(nk);
    let proof = client.get_nullifier_proof(&nf).await?;

    if proof.exists {
        println!("Note has already been spent!");
        Ok(true)
    } else {
        println!("Note is unspent and can be used");
        Ok(false)
    }
}
```

---

## Batch Processing Methods

### `process_batch`

Trigger batch processing of pending transactions.

```rust
pub async fn process_batch(&self) -> Result<String, Box<dyn Error>>
```

**Returns:** Status message with block number.

**Example:**

```rust
async fn trigger_batch(client: &FluxeClient) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.process_batch().await?;
    println!("Batch processed: {}", result);
    Ok(())
}
```

---

### `get_batch_status`

Get current batch processing status.

```rust
pub async fn get_batch_status(&self) -> Result<String, Box<dyn Error>>
```

**Returns:** JSON string with batch status information.

---

### `health_check`

Check if the API server is healthy.

```rust
pub async fn health_check(&self) -> Result<bool, Box<dyn Error>>
```

**Returns:** `true` if server is healthy.

**Example:**

```rust
async fn check_health(client: &FluxeClient) -> Result<(), Box<dyn std::error::Error>> {
    match client.health_check().await {
        Ok(true) => println!("Server is healthy"),
        Ok(false) => println!("Server returned unhealthy status"),
        Err(e) => println!("Failed to reach server: {}", e),
    }
    Ok(())
}
```

---

## Complete Example

```rust
use ark_bn254::Fr as F;
use ark_ff::UniformRand;
use fluxe_api::client::FluxeClient;
use fluxe_core::data_structures::Note;
use fluxe_core::crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client
    let client = FluxeClient::new("http://localhost:3000".to_string());

    // Check health
    if !client.health_check().await? {
        return Err("Server not healthy".into());
    }

    // Get current state
    let roots = client.get_roots().await?;
    println!("Current CMT Root: {}", roots.cmt_root);

    // Check supply
    let supply = client.get_supply(1).await?;
    println!("USDC Supply: {}", supply.current_supply);

    // Generate keys for a new user
    let mut rng = rand::thread_rng();
    let owner_sk = F::rand(&mut rng);
    let nk = F::rand(&mut rng);
    let owner_addr = poseidon_hash(&[owner_sk]); // Simplified

    // Create a note
    let params = PedersenParams::setup_value_commitment();
    let value = 1_000_000u64; // 1 USDC
    let randomness = PedersenRandomness::new(&mut rng);
    let v_comm = PedersenCommitment::commit(&params, value, &randomness);

    let note = Note::new(
        1,              // asset_type: USDC
        v_comm,
        owner_addr,
        rand::random(), // psi
        1,              // pool_id
    );

    println!("Note commitment: {:?}", note.commitment());

    // Submit mint (requires proving key)
    // let pk = load_proving_key("mint.pk")?;
    // let tx_id = client.submit_mint(1, value, owner_addr, &pk).await?;

    Ok(())
}
```

---

## Error Handling

The client returns `Box<dyn Error>` for flexibility. Common error types include:

```rust
use std::error::Error;

async fn handle_errors(client: &FluxeClient) {
    match client.get_roots().await {
        Ok(roots) => {
            println!("Success: {}", roots.cmt_root);
        }
        Err(e) => {
            // Network errors
            if e.to_string().contains("connection refused") {
                println!("Server not reachable");
            }
            // API errors (returned in response body)
            else if e.to_string().contains("Chain is not enabled") {
                println!("Chain configuration error");
            }
            // Other errors
            else {
                println!("Unknown error: {}", e);
            }
        }
    }
}
```

---

## Thread Safety

`FluxeClient` uses `reqwest::Client` internally which is designed for concurrent use. You can safely share a `FluxeClient` across threads using `Arc`:

```rust
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let client = Arc::new(FluxeClient::new("http://localhost:3000".to_string()));

    let client1 = Arc::clone(&client);
    let handle1 = tokio::spawn(async move {
        client1.get_roots().await
    });

    let client2 = Arc::clone(&client);
    let handle2 = tokio::spawn(async move {
        client2.get_supply(1).await
    });

    let (roots, supply) = tokio::join!(handle1, handle2);
    // Process results...
}
```
