use cosmwasm_std::{attr, entry_point, to_binary, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Order, Response, StdError, StdResult, WasmMsg, SubMsg, ReplyOn, Reply, ContractResult, SubcallResponse};

use crate::msg::{
    ConfigResponse, ExecuteMsg, GetRandomResponse, InstantiateMsg, LatestRandomResponse, QueryMsg,
};
use crate::state::{BeaconInfoState, Config, BEACONS, CONFIG};
use groupy::{CurveAffine, CurveProjective};
use paired::bls12_381::{G2Affine, G2};
use paired::{ExpandMsgXmd, HashToCurve};
use sha2::{Digest, Sha256};
use crate::error::ContractError;

const DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// Note, you can use StdResult in some functions where you do not
// make use of the custom errors
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let config = Config {
        drand_step2_contract_address: deps
            .api
            .addr_canonicalize(&msg.drand_step2_contract_address)?,
    };
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Drand {
            round,
            previous_signature,
            signature,
        } => add_random(deps, env, info, round, previous_signature, signature),
        ExecuteMsg::VerifyCallBack {
            round,
            randomness,
            valid,
            worker,
        } => verify_call_back(deps, env, info, round, randomness, valid, worker),
    }
}

fn round_to_bytes(round: u64) -> [u8; 8] {
    round.to_be_bytes()
}

fn message(current_round: u64, prev_sig: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update(prev_sig);
    hasher.update(round_to_bytes(current_round));
    hasher.finalize().to_vec()
}
fn msg_to_curve(msg: &[u8]) -> G2Affine {
    let g = <G2 as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, DOMAIN);
    g.into_affine()
}
fn verify_step1(round: u64, previous_signature: &[u8]) -> G2Affine {
    let msg = message(round, previous_signature);
    msg_to_curve(&msg)
}

fn encode_msg(msg: QueryMsg, address: String) -> StdResult<SubMsg> {
    Ok(WasmMsg::Execute {
        contract_addr: address,
        msg: to_binary(&msg)?,
        funds: vec![]
    }
    .into())
}

pub fn add_random(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    round: u64,
    previous_signature: Binary,
    signature: Binary,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    // Handle sender is not sending funds
    if !info.funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with add_random"));
    }

    let verify_step1 = verify_step1(round, &previous_signature.as_slice());
    let msg = QueryMsg::Verify {
        signature,
        msg_g2: Binary::from(verify_step1.into_compressed().as_ref()),
        worker: info.sender.to_string(),
        round,
    };

    let contract_address = deps
        .api
        .addr_humanize(&config.drand_step2_contract_address)?;
    let res = encode_msg(msg, contract_address.to_string())?;

    Ok(Response {
        messages: vec![res],
        attributes: vec![],
        events: vec![],
        data: None,
    })
}

pub fn verify_call_back(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    round: u64,
    randomness: Binary,
    valid: bool,
    worker: String,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    let canonical_address = deps.api.addr_canonicalize(&worker)?;
    let drand_step2_contract_address = deps
        .api
        .addr_humanize(&config.drand_step2_contract_address)?;

    //env.message.sender
    if info.sender != drand_step2_contract_address {
        return Err(StdError::generic_err("Not authorized"));
    }
    if !valid {
        return Err(StdError::generic_err("The randomness is not valid"));
    }
    let beacon = &BeaconInfoState {
        round,
        randomness,
        worker: canonical_address,
    };
    // Handle sender are not adding existing rounds
    match BEACONS.may_load(deps.storage, &round.to_be_bytes())? {
        Some(_) => {
            return Err(StdError::generic_err("Randomness already added"));
        }
        None => BEACONS.save(deps.storage, &round.to_be_bytes(), beacon)?,
    };

    Ok(Response {
        messages: vec![],
        attributes: vec![attr("isValidRandomness", "true")],
        events: vec![],
        data: None,
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError>{
    match msg.id {
       _ => reply_operation(deps, env, msg.result)
    }
}

pub fn reply_operation(_deps: DepsMut, _env: Env, res: ContractResult<SubcallResponse>) -> Result<Response, ContractError>{
    match res {
        ContractResult::Err(_) => Err(ContractError::InvalidSignature {}),
        ContractResult::Ok(_) => { }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?)?,
        QueryMsg::GetRandomness { round } => to_binary(&query_get(deps, round)?)?,
        QueryMsg::LatestDrand {} => to_binary(&query_latest(deps)?)?,
        QueryMsg::Verify { .. } => to_binary(&query_verify(deps)?)?,
    };
    Ok(response)
}
fn query_verify(_deps: Deps) -> StdResult<Response> {
    Err(StdError::generic_err("Not Authorized"))
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(config)
}
// Query beacon by round
fn query_get(deps: Deps, round: u64) -> StdResult<GetRandomResponse> {
    let beacon = BEACONS.load(deps.storage, &round.to_be_bytes())?;

    Ok(GetRandomResponse {
        randomness: beacon.randomness,
        worker: deps.api.addr_humanize(&beacon.worker)?.to_string(),
    })
}
// Query latest beacon
fn query_latest(deps: Deps) -> StdResult<LatestRandomResponse> {

    let mut iter = BEACONS.range(deps.storage, None, None, Order::Descending);
    let (_, value) = iter
        .next()
        .ok_or_else(|| StdError::generic_err("Not found"))??;

    Ok(LatestRandomResponse {
        round: value.round,
        randomness: value.randomness,
        worker: deps.api.addr_humanize(&value.worker)?.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use hex;

    mod verify_call_back {
        use super::*;
        use cosmwasm_std::testing::mock_info;

        #[test]
        fn success() {
            let mut deps = mock_dependencies(&[]);
            let contract_address = "addr0000".to_string();
            let init_msg = InstantiateMsg {
                drand_step2_contract_address: contract_address,
            };
            let env = mock_env();
            let info = mock_info("addr0000", &[]);
            instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

            let msg = ExecuteMsg::VerifyCallBack {
                round: 2234234,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: true,
                worker: "addr0001".to_string()
            };
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            let log_res: bool = res.attributes[0].value.parse().unwrap();
            assert!(log_res);

            // Add other one
            let msg = ExecuteMsg::VerifyCallBack {
                round: 2234230,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: true,
                worker: "addr0002".to_string()
            };
            execute(deps.as_mut(), env, info, msg).unwrap();

            // get latest round
            let state = query_latest(deps.as_ref()).unwrap();
            assert_eq!("addr0001".to_string(), state.worker);

            // get custom round
            let state = query_get(deps.as_ref(), 2234230).unwrap();
            assert_eq!("addr0002".to_string(), state.worker);
        }

        #[test]
        fn not_valid_randomness() {
            let mut deps = mock_dependencies(&[]);
            let contract_address = "addr0000".to_string();
            let init_msg = InstantiateMsg {
                drand_step2_contract_address: contract_address,
            };
            let env = mock_env();
            let info = mock_info("addr0000", &[]);
            instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

            let msg = ExecuteMsg::VerifyCallBack {
                round: 2234234,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: false,
                worker: "addr0000".to_string()
            };

            let res = execute(deps.as_mut(), env, info, msg);

            match res {
                Err(StdError::GenericErr { msg, .. }) => {
                    assert_eq!("The randomness is not valid", msg)
                }

                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn sender_is_not_authorized() {
            let mut deps = mock_dependencies(&[]);
            let contract_address = "addr0000".to_string();
            let unauthorized_sender = "addr0001".to_string();
            let init_msg = InstantiateMsg {
                drand_step2_contract_address: contract_address,
            };
            let env = mock_env();
            let info = mock_info(&unauthorized_sender, &[]);
            instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

            let msg = ExecuteMsg::VerifyCallBack {
                round: 2234234,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: true,
                worker: "addr0000".to_string()
            };

            let res = execute(deps.as_mut(), env, info, msg);

            match res {
                Err(StdError::GenericErr { msg, .. }) => assert_eq!("Not authorized", msg),

                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn handle_adding_randomness_multiple_times_error() {
            let mut deps = mock_dependencies(&[]);
            let contract_address = "addr0000".to_string();
            let init_msg = InstantiateMsg {
                drand_step2_contract_address: contract_address,
            };
            let env = mock_env();
            let info = mock_info("addr0000", &[]);
            instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

            let msg = ExecuteMsg::VerifyCallBack {
                round: 2234234,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: true,
                worker: "addr0000".to_string()
            };

            execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
            let msg = ExecuteMsg::VerifyCallBack {
                round: 2234234,
                randomness: hex::decode("aeed0765b92cc221959c6c7e4f154d83252cf7f6eb7ad8f416de8b0c49ce1f848c8b19dc31a34a7ca0abbb2fbeb198530da8519a7bc7947015fb8973e9d403ef420fa69324030b2efa5c4dc7c87e3db58eec79f20565bc8a3473095dbdb1fbb1").unwrap().into(),
                valid: true,
                worker: "addr0001".to_string()
            };

            let res = execute(deps.as_mut(), env, info, msg);
            match res {
                Err(StdError::GenericErr { msg, .. }) => {
                    assert_eq!("Randomness already added", msg)
                }

                _ => panic!("Unexpected error"),
            }
        }
    }

    #[test]
    fn add_random_test() {
        let mut deps = mock_dependencies(&[]);
        let contract_address = "addr0000".to_string();
        let init_msg = InstantiateMsg {
            drand_step2_contract_address: contract_address,
        };
        let env = mock_env();
        let info = mock_info("addr0000", &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

        let round = 545216;
        let prev_sign = Binary::from_base64("gIO9RFHWCjKIq9lQrERpO1hEjdbroVuFuKRtWJuuPf+1HIYBHJkTIJCAwjf+ycA5BA0pHjnYsgSfqD5nsMpxvhPOArAknwuAYXFQOx+NZxoxzXOr+cdndFOl953+sXii").unwrap();
        let sign = Binary::from_base64("imgTaZQ/2cjJn+SG+i8FlqBIgQ8kuA1Izbg5BVh0pn/rbKAaysP5GSN8cjupq6kMC6JXBSpo61MDITzSNjqrEcJ1BPf4Qer2Hh2uOcR9+LHL/SFn6w9L/6Bv3PR4mMAE").unwrap();
        let msg = ExecuteMsg::Drand {
            round,
            previous_signature: prev_sign,
            signature: sign,
        };
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(1, res.messages.len());
    }
}
