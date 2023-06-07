use jsonrpc_core::{
    futures_util::future::{Either, FutureExt},
    Call, Failure, FutureOutput, FutureResponse, Id, MethodCall, Middleware, Output, Request,
    Response, Version,
};
use log::*;
use rand::{thread_rng, Rng};
use std::sync::Arc;

use crate::rpc::{BatchId, JsonRpcRequestProcessor};

// Expected batch id format 'b<generated batch id>:<original id type><original id>
// original id type can be either n (for numeric id) or s (for string id)
fn decode_batch_id(id: &Id) -> Option<(BatchId, Id)> {
    if let Id::Str(id_str) = id {
        let (&prefix, s) = id_str.as_bytes().split_first()?;
        if prefix == b'b' {
            let mut split = s.split(|&b| b == b':');
            let batch_id = std::str::from_utf8(split.next()?).ok()?;
            let batch_id: BatchId = batch_id.parse().ok()?;
            let rest = split.next()?;
            let (&t, id_str) = rest.split_first()?;
            let id_str = std::str::from_utf8(id_str).ok()?;
            return if t == b'n' {
                id_str.parse().ok().map(|num: u64| (batch_id, Id::Num(num)))
            } else if t == b's' {
                Some((batch_id, Id::Str(id_str.to_string())))
            } else {
                None
            };
        }
    }
    None
}

pub fn patch_calls(calls: impl IntoIterator<Item = Call>, id: BatchId) -> Vec<Call> {
    let id_str = id.to_string();
    calls
        .into_iter()
        .map(|call| {
            if let Call::MethodCall(mut method_call) = call {
                let new_id = match method_call.id.clone() {
                    Id::Num(num) => Id::Str(format!("b{}:n{}", id_str, num)),
                    Id::Str(s) => Id::Str(format!("b{}:s{}", id_str, s)),
                    Id::Null => Id::Null,
                };
                method_call.id = new_id;
                Call::MethodCall(method_call)
            } else {
                call
            }
        })
        .collect()
}

pub fn restore_original_call(call: Call) -> Result<(MethodCall, BatchId), Call> {
    match call {
        Call::MethodCall(mut method_call) => match decode_batch_id(&method_call.id) {
            Some((batch_id, id)) => {
                method_call.id = id;
                Ok((method_call, batch_id))
            }
            None => Err(Call::MethodCall(method_call)),
        },
        _ => Err(call),
    }
}