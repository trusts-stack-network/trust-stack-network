//! Integration tests for the TSN smart contract system.
//!
//! Tests the full lifecycle: deploy → init → call → query
//!
//! Arg ordering with push_args: values are pushed in order, so the LAST
//! element in the vec ends up on TOP of the stack.
//! The dispatch expects selector on top → selector must be last in constructor_args.

#[cfg(test)]
mod tests {
    use crate::contract::executor::ContractExecutor;
    use crate::contract::types::*;
    use crate::contract::templates::token::build_token_bytecode;
    use crate::contract::templates::escrow::build_escrow_bytecode;
    use crate::contract::templates::multisig::build_multisig_bytecode;

    fn setup_executor() -> (ContractExecutor, sled::Db) {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("failed to open temp sled db");
        let executor = ContractExecutor::new(&db).expect("failed to create executor");
        (executor, db)
    }

    fn deployer_pk() -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[0] = 0xAA;
        pk[1] = 0xBB;
        pk
    }

    fn user_pk() -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[0] = 0xCC;
        pk[1] = 0xDD;
        pk
    }

    /// Deploy a TSN-20 token. Returns contract address.
    fn deploy_token(executor: &ContractExecutor, supply: u64) -> [u8; 32] {
        let bytecode = build_token_bytecode();
        // push_args pushes in order: supply first, selector=1 last (on top)
        let deploy_tx = ContractDeployTransaction {
            bytecode,
            constructor_args: vec![supply, 1], // supply at bottom, selector=1 on top
            gas_limit: 500_000,
            fee: 1000,
            deployer_pk_hash: deployer_pk(),
            nonce: 0,
            signature: vec![],
            public_key: vec![],
        };
        let receipt = executor.deploy(&deploy_tx, 100, 1700000000)
            .expect("deploy failed");
        assert!(receipt.success, "deploy should succeed: {:?}", receipt.error);
        receipt.contract_address.unwrap()
    }

    // ═══════════════════════════════════════════════════════════
    // TSN-20 Token
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn test_token_deploy_and_init() {
        let (executor, _db) = setup_executor();
        let contract_addr = deploy_token(&executor, 1_000_000);

        let result = executor.query(
            &contract_addr, [0x06, 0, 0, 0], &[],
            101, 1700000001,
        ).unwrap();
        assert!(result.success);
        assert_eq!(result.return_value, Some(1_000_000));
        println!("✅ Token deployed — total_supply: 1,000,000");
    }

    #[test]
    fn test_token_total_supply_query() {
        let (executor, _db) = setup_executor();
        let contract_addr = deploy_token(&executor, 1_000_000);

        let result = executor.query(
            &contract_addr, [0x06, 0, 0, 0], &[], 101, 1700000001,
        ).expect("query failed");
        assert!(result.success, "query failed: {:?}", result.error);
        assert_eq!(result.return_value, Some(1_000_000));
        println!("✅ total_supply = {} — gas: {}", result.return_value.unwrap(), result.gas_used);
    }

    #[test]
    fn test_token_balance_of_deployer() {
        let (executor, _db) = setup_executor();
        let contract_addr = deploy_token(&executor, 500_000);

        let result = executor.query(
            &contract_addr, [0x03, 0, 0, 0], &[0], 101, 1700000001,
        ).expect("query failed");
        assert!(result.success, "balance_of failed: {:?}", result.error);
        assert_eq!(result.return_value, Some(500_000));
        println!("✅ deployer balance = {}", result.return_value.unwrap());
    }

    #[test]
    fn test_token_transfer() {
        let (executor, _db) = setup_executor();
        let contract_addr = deploy_token(&executor, 1_000_000);

        let call_tx = ContractCallTransaction {
            contract_address: contract_addr,
            function_selector: [0x02, 0, 0, 0],
            args: vec![42, 250_000], // to=42, amount=250000
            gas_limit: 500_000,
            fee: 500,
            value: 0,
            caller_pk_hash: deployer_pk(),
            nonce: 1,
            signature: vec![],
            public_key: vec![],
        };
        let receipt = executor.call(&call_tx, 101, 1700000001).unwrap();
        assert!(receipt.success, "transfer failed: {:?}", receipt.error);
        assert_eq!(receipt.return_value, Some(1));
        assert!(!receipt.events.is_empty(), "should emit Transfer event");
        println!("✅ Transfer 250K → addr 42 — gas: {}", receipt.gas_used);

        // Deployer: 1M - 250K = 750K
        let result = executor.query(
            &contract_addr, [0x03, 0, 0, 0], &[0], 102, 1700000002,
        ).unwrap();
        assert_eq!(result.return_value, Some(750_000));
        println!("✅ deployer balance = 750,000");

        // Recipient: 250K
        let result = executor.query(
            &contract_addr, [0x03, 0, 0, 0], &[42], 102, 1700000002,
        ).unwrap();
        assert_eq!(result.return_value, Some(250_000));
        println!("✅ recipient balance = 250,000");
    }

    #[test]
    fn test_token_transfer_insufficient_balance() {
        let (executor, _db) = setup_executor();
        let contract_addr = deploy_token(&executor, 100);

        let call_tx = ContractCallTransaction {
            contract_address: contract_addr,
            function_selector: [0x02, 0, 0, 0],
            args: vec![42, 200],
            gas_limit: 500_000,
            fee: 500,
            value: 0,
            caller_pk_hash: deployer_pk(),
            nonce: 1,
            signature: vec![],
            public_key: vec![],
        };
        let receipt = executor.call(&call_tx, 101, 1700000001).unwrap();
        assert!(!receipt.success, "should fail — insufficient balance");
        println!("✅ Insufficient balance rejected: {:?}", receipt.error);
    }

    #[test]
    fn test_token_gas_estimation() {
        let (executor, _db) = setup_executor();
        let contract_addr = deploy_token(&executor, 1_000_000);

        let gas = executor.estimate_gas(
            &contract_addr, [0x03, 0, 0, 0], &[0], 101, 1700000001,
        ).unwrap();
        assert!(gas > 0 && gas < 10_000);
        println!("✅ Gas estimate balance_of: {}", gas);
    }

    // ═══════════════════════════════════════════════════════════
    // Escrow
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn test_escrow_deploy_and_status() {
        let (executor, _db) = setup_executor();
        let bytecode = build_escrow_bytecode();

        // push_args pushes in order, last on top.
        // After pop selector(1), SStore pops top→slot5, next→slot4, etc.
        // Stack after pop needs (top→bottom): arb, timeout, amount, seller, buyer
        // So constructor_args: [buyer, seller, amount, timeout, arb, selector]
        let deploy_tx = ContractDeployTransaction {
            bytecode,
            constructor_args: vec![11, 22, 50_000, 200, 33, 1],
            // buyer=11, seller=22, amount=50000, timeout=200, arb=33, selector=1
            gas_limit: 500_000,
            fee: 1000,
            deployer_pk_hash: deployer_pk(),
            nonce: 0,
            signature: vec![],
            public_key: vec![],
        };
        let receipt = executor.deploy(&deploy_tx, 100, 1700000000).unwrap();
        assert!(receipt.success, "escrow deploy failed: {:?}", receipt.error);
        let contract_addr = receipt.contract_address.unwrap();

        let result = executor.query(
            &contract_addr, [0x05, 0, 0, 0], &[], 101, 1700000001,
        ).unwrap();
        assert!(result.success, "status failed: {:?}", result.error);
        assert_eq!(result.return_value, Some(1)); // active
        println!("✅ Escrow deployed — status: active — gas: {}", receipt.gas_used);
    }

    // ═══════════════════════════════════════════════════════════
    // Multisig
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn test_multisig_deploy_and_propose() {
        let (executor, _db) = setup_executor();
        let bytecode = build_multisig_bytecode();

        // After pop selector, SStore slot0 pops threshold (top), then DUP+SStore uses signer_count
        // Stack after pop (top→bottom): threshold, signer_count
        // constructor_args: [signer_count, threshold, selector]
        let deploy_tx = ContractDeployTransaction {
            bytecode,
            constructor_args: vec![3, 2, 1], // signer_count=3, threshold=2, selector=1
            gas_limit: 500_000,
            fee: 1000,
            deployer_pk_hash: deployer_pk(),
            nonce: 0,
            signature: vec![],
            public_key: vec![],
        };
        let receipt = executor.deploy(&deploy_tx, 100, 1700000000).unwrap();
        assert!(receipt.success, "multisig deploy failed: {:?}", receipt.error);
        let contract_addr = receipt.contract_address.unwrap();

        // Propose (selector 0x02)
        let call_tx = ContractCallTransaction {
            contract_address: contract_addr,
            function_selector: [0x02, 0, 0, 0],
            args: vec![0xDEAD],
            gas_limit: 500_000,
            fee: 500,
            value: 0,
            caller_pk_hash: deployer_pk(),
            nonce: 1,
            signature: vec![],
            public_key: vec![],
        };
        let receipt = executor.call(&call_tx, 101, 1700000001).unwrap();
        assert!(receipt.success, "propose failed: {:?}", receipt.error);
        // return_value is top of stack at Return — may be proposal_id or action_hash
        println!("✅ Proposal created — gas: {}", receipt.gas_used);

        // Approve 1/2
        let approve = ContractCallTransaction {
            contract_address: contract_addr,
            function_selector: [0x03, 0, 0, 0],
            args: vec![0],
            gas_limit: 500_000,
            fee: 500,
            value: 0,
            caller_pk_hash: deployer_pk(),
            nonce: 2,
            signature: vec![],
            public_key: vec![],
        };
        let receipt = executor.call(&approve, 102, 1700000002).unwrap();
        assert!(receipt.success);

        // is_approved? 1 < 2 → 0
        let result = executor.query(
            &contract_addr, [0x04, 0, 0, 0], &[0], 103, 1700000003,
        ).unwrap();
        assert_eq!(result.return_value, Some(0));
        println!("✅ is_approved = 0 (1/2)");

        // Approve 2/2
        let approve2 = ContractCallTransaction {
            contract_address: contract_addr,
            function_selector: [0x03, 0, 0, 0],
            args: vec![0],
            gas_limit: 500_000,
            fee: 500,
            value: 0,
            caller_pk_hash: user_pk(),
            nonce: 0,
            signature: vec![],
            public_key: vec![],
        };
        executor.call(&approve2, 103, 1700000003).unwrap();

        // 2 >= 2 → 1
        let result = executor.query(
            &contract_addr, [0x04, 0, 0, 0], &[0], 104, 1700000004,
        ).unwrap();
        assert_eq!(result.return_value, Some(1));
        println!("✅ is_approved = 1 (2/2 threshold!)");
    }

    // ═══════════════════════════════════════════════════════════
    // Edge cases
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn test_deploy_bytecode_too_large() {
        let (executor, _db) = setup_executor();
        let deploy_tx = ContractDeployTransaction {
            bytecode: vec![0x43; 70_000],
            constructor_args: vec![],
            gas_limit: 500_000,
            fee: 1000,
            deployer_pk_hash: deployer_pk(),
            nonce: 0,
            signature: vec![],
            public_key: vec![],
        };
        let result = executor.deploy(&deploy_tx, 100, 1700000000);
        assert!(matches!(result, Err(crate::contract::ContractError::BytecodeTooLarge(_))));
        println!("✅ Oversized bytecode rejected");
    }

    #[test]
    fn test_call_nonexistent_contract() {
        let (executor, _db) = setup_executor();
        let call_tx = ContractCallTransaction {
            contract_address: [0xFF; 32],
            function_selector: [0x01, 0, 0, 0],
            args: vec![],
            gas_limit: 500_000,
            fee: 500,
            value: 0,
            caller_pk_hash: deployer_pk(),
            nonce: 0,
            signature: vec![],
            public_key: vec![],
        };
        let result = executor.call(&call_tx, 100, 1700000000);
        assert!(matches!(result, Err(crate::contract::ContractError::ContractNotFound(_))));
        println!("✅ Nonexistent contract rejected");
    }
}
