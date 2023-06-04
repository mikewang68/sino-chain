use crate::{CallScheme, Context, CreateScheme, ExitFatal, ExitReason};

use log::trace;
use primitive_types::{H160 as Address, U256};

#[derive(Debug, Clone)]
pub struct Res {
    pub gas_used: U256,
    pub contract: Option<Address>,
    pub output: Vec<u8>,
    pub reason: ExitReason,
}

impl Default for Res {
    fn default() -> Self {
        Self {
            gas_used: 0.into(),
            contract: None,
            output: Vec::new(),
            // No result was found, this mean we didnt handle output in call_inner/create_inner
            reason: ExitReason::Fatal(ExitFatal::UnhandledInterrupt),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Action {
    Call {
        code: Address,
        context: Context,
        gas: U256,
        input: Vec<u8>,
        call_type: Option<CallScheme>,
    },
    Create {
        caller: Address,
        value: U256,
        gas: U256,
        init_code: Vec<u8>,
        creation_method: CreateScheme,
    },
    // TODO: Trace suicide?!
    // Suicide {
    //     address: Address,
    //     refund_address: Address,
    //     balance: U256,
    // },
}
impl Action {
    pub fn caller(&self) -> Address {
        match self {
            Action::Call { context, .. } => context.caller,
            Action::Create { caller, .. } => *caller,
        }
    }
    pub fn code(&self) -> Option<Address> {
        match self {
            Action::Call { code, .. } => Some(*code),
            Action::Create { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Trace {
    pub action: Action,
    pub result: Res,
    pub subtraces: usize,
    pub trace_address: Vec<usize>,
}

impl Trace {
    /// Creates new Trace from action.
    /// Result should be added later.
    pub fn from_action(action: Action, trace_address: Vec<usize>) -> Trace {
        Trace {
            action,
            result: Default::default(),
            subtraces: 0,
            trace_address,
        }
    }
}
#[derive(Debug, Copy, Clone, Default)]
pub struct StackEntry {
    /// Address of current Trace element in array.
    global_address: usize,
    /// Count of subcalls in current stack frame.
    number_of_completed_subcalls: usize,
}

#[derive(Debug, Clone)]
pub struct TraceTracker {
    traces: Vec<Trace>,
    traces_stack: Vec<StackEntry>,
}

impl TraceTracker {
    pub fn new() -> TraceTracker {
        TraceTracker {
            traces: Vec::new(),
            traces_stack: Vec::new(),
        }
    }

    fn trace_address(&self) -> Vec<usize> {
        self.traces_stack
            .iter()
            .map(|s| s.number_of_completed_subcalls)
            .collect()
    }

    pub fn start_create(
        &mut self,
        caller: Address,
        value: U256,
        gas: U256,
        init_code: Vec<u8>,
        creation_method: CreateScheme,
    ) {
        let action = Action::Create {
            caller,
            value,
            gas,
            init_code,
            creation_method,
        };

        trace!("start routine, {:?}", action);

        for trace_id in &self.traces_stack {
            self.traces[trace_id.global_address].subtraces += 1;
        }
        let trace_address = self.trace_address();
        self.traces_stack.push(StackEntry {
            global_address: self.traces.len(),
            number_of_completed_subcalls: 0,
        });
        self.traces.push(Trace::from_action(action, trace_address));
    }

    pub fn start_call(
        &mut self,
        code: Address,
        context: Context,
        gas: U256,
        input: Vec<u8>,
        call_type: Option<CallScheme>,
    ) {
        let action = Action::Call {
            code,
            context,
            gas,
            input,
            call_type,
        };
        trace!("start routine, {:?}", action);

        for trace_id in &self.traces_stack {
            self.traces[trace_id.global_address].subtraces += 1;
        }
        let trace_address = self.trace_address();
        self.traces_stack.push(StackEntry {
            global_address: self.traces.len(),
            number_of_completed_subcalls: 0,
        });
        self.traces.push(Trace::from_action(action, trace_address));
    }

    pub fn end_subroutine(
        &mut self,
        gas_used: U256,
        contract: Option<Address>,
        output: Vec<u8>,
        reason: ExitReason,
    ) {
        trace!("End routine, {:?}", self);

        let stack_item = self
            .traces_stack
            .pop()
            .expect("Expecting end_call after start_call");

        // None only possible on multiple rootlevel calls.
        self.traces_stack
            .last_mut()
            .map(|entry| entry.number_of_completed_subcalls += 1);

        let trace = self
            .traces
            .get_mut(stack_item.global_address)
            .expect("Expecting to find trace by its global address in stack");

        trace.result = Res {
            reason,
            gas_used,
            output,
            contract,
        };
    }

    pub fn trace_by_address(&mut self, address: &[usize]) -> Option<&mut Trace> {
        assert!(
            self.traces_stack.is_empty(),
            "trace_by_address should be called only when tracing is finished"
        );
        let mut addr = address.iter();
        let mut id = 0;
        loop {
            let addr = addr.next();
            if let Some(addr) = addr {
                id += 1;
                for _addr in 0..*addr {
                    let trace = self.traces.get(id)?;
                    // skip subchilds of current traces
                    id += trace.subtraces + 1;
                }
            } else {
                return self.traces.get_mut(id);
            }
        }
    }
    pub fn take_traces(&mut self) -> Vec<Trace> {
        assert!(
            self.traces_stack.is_empty(),
            "take_traces should be called only when tracing is finished"
        );
        std::mem::replace(&mut self.traces, Vec::new())
    }
}

#[cfg(test)]
mod test {

    use crate::ExitSucceed;

    use super::*;

    // Givven next calls:
    //
    // A
    // CALLs B
    //   CALLs D
    // CALLs C
    //   CALLs D
    //
    // Should produce next addresses:
    // [ {A: []}, {B: [0]}, {D: [0, 0]}, {C: [1]}, {D: [1, 0]} ]
    #[test]
    fn test_trace_from_openethereum_docs() {
        let mut tracker = TraceTracker::new();
        let caller_address = Address::zero();
        let a_address = Address::repeat_byte(0xa);
        let b_address = Address::repeat_byte(0xb);
        let d_address = Address::repeat_byte(0xd);
        let c_address = Address::repeat_byte(0xc);

        tracker.start_call(
            a_address,
            Context {
                caller: caller_address,
                address: a_address,
                apparent_value: 0.into(),
            },
            0.into(),
            vec![],
            None,
        );
        {
            tracker.start_call(
                b_address,
                Context {
                    caller: a_address,
                    address: b_address,
                    apparent_value: 0.into(),
                },
                0.into(),
                vec![],
                None,
            );
            {
                tracker.start_call(
                    d_address,
                    Context {
                        caller: b_address,
                        address: d_address,
                        apparent_value: 0.into(),
                    },
                    0.into(),
                    vec![],
                    None,
                );
                tracker.end_subroutine(
                    0.into(),
                    None,
                    vec![],
                    ExitReason::Succeed(ExitSucceed::Returned),
                );
            }
            tracker.end_subroutine(
                0.into(),
                None,
                vec![],
                ExitReason::Succeed(ExitSucceed::Returned),
            );
        }
        {
            tracker.start_call(
                c_address,
                Context {
                    caller: a_address,
                    address: c_address,
                    apparent_value: 0.into(),
                },
                0.into(),
                vec![],
                None,
            );
            {
                tracker.start_call(
                    d_address,
                    Context {
                        caller: c_address,
                        address: d_address,
                        apparent_value: 0.into(),
                    },
                    0.into(),
                    vec![],
                    None,
                );
                tracker.end_subroutine(
                    0.into(),
                    None,
                    vec![],
                    ExitReason::Succeed(ExitSucceed::Returned),
                );
            }
            tracker.end_subroutine(
                0.into(),
                None,
                vec![],
                ExitReason::Succeed(ExitSucceed::Returned),
            );
        }
        tracker.end_subroutine(
            0.into(),
            None,
            vec![],
            ExitReason::Succeed(ExitSucceed::Returned),
        );
        let addresses: Vec<_> = tracker
            .traces
            .into_iter()
            .map(|t| (t.action.code().unwrap(), t.trace_address, t.subtraces))
            .collect();
        let expected = vec![
            (a_address, vec![], 4),
            (b_address, vec![0], 1),
            (d_address, vec![0, 0], 0),
            (c_address, vec![1], 1),
            (d_address, vec![1, 0], 0),
        ];
        assert_eq!(addresses, expected)
    }

    // Givven next calls:
    //
    // A
    // CALLs B
    //   CALLs D
    //     CALLs E
    //     CALLs D
    // CALLs C
    //   CALLs D
    //
    // Should produce next addresses:
    // [ {A: []}, {B: [0]}, {D: [0, 0]}, {E:[0,0,0]}, {D:[0,0,1]}, {C: [1]}, {D: [1, 0]} ]
    #[test]
    fn test_persist_result_and_multiple_levels() {
        let mut tracker = TraceTracker::new();
        let caller_address = Address::zero();
        let a_address = Address::repeat_byte(0xa);
        let b_address = Address::repeat_byte(0xb);
        let d_address = Address::repeat_byte(0xd);
        let c_address = Address::repeat_byte(0xc);
        let e_address = Address::repeat_byte(0xe);

        tracker.start_call(
            a_address,
            Context {
                caller: caller_address,
                address: a_address,
                apparent_value: 0.into(),
            },
            0.into(),
            vec![],
            None,
        );
        {
            tracker.start_call(
                b_address,
                Context {
                    caller: a_address,
                    address: b_address,
                    apparent_value: 0.into(),
                },
                0.into(),
                vec![],
                None,
            );
            {
                tracker.start_call(
                    d_address,
                    Context {
                        caller: b_address,
                        address: d_address,
                        apparent_value: 0.into(),
                    },
                    0.into(),
                    vec![],
                    None,
                );
                {
                    tracker.start_call(
                        e_address,
                        Context {
                            caller: d_address,
                            address: e_address,
                            apparent_value: 0.into(),
                        },
                        0.into(),
                        vec![],
                        None,
                    );
                    tracker.end_subroutine(
                        0.into(),
                        None,
                        vec![],
                        ExitReason::Succeed(ExitSucceed::Returned),
                    );
                }
                {
                    tracker.start_call(
                        d_address,
                        Context {
                            caller: d_address,
                            address: d_address,
                            apparent_value: 0.into(),
                        },
                        0.into(),
                        vec![],
                        None,
                    );
                    tracker.end_subroutine(
                        0.into(),
                        None,
                        vec![],
                        ExitReason::Succeed(ExitSucceed::Returned),
                    );
                }
                tracker.end_subroutine(
                    0.into(),
                    None,
                    vec![],
                    ExitReason::Succeed(ExitSucceed::Returned),
                );
            }
            tracker.end_subroutine(
                0.into(),
                None,
                vec![],
                ExitReason::Succeed(ExitSucceed::Returned),
            );
        }
        {
            tracker.start_call(
                c_address,
                Context {
                    caller: a_address,
                    address: c_address,
                    apparent_value: 0.into(),
                },
                0.into(),
                vec![],
                None,
            );
            {
                tracker.start_call(
                    d_address,
                    Context {
                        caller: c_address,
                        address: d_address,
                        apparent_value: 0.into(),
                    },
                    0.into(),
                    vec![],
                    None,
                );
                tracker.end_subroutine(
                    0.into(),
                    None,
                    vec![],
                    ExitReason::Succeed(ExitSucceed::Returned),
                );
            }
            tracker.end_subroutine(
                0.into(),
                None,
                vec![],
                ExitReason::Succeed(ExitSucceed::Returned),
            );
        }
        tracker.end_subroutine(
            0.into(),
            None,
            vec![],
            ExitReason::Succeed(ExitSucceed::Returned),
        );
        let addresses: Vec<_> = tracker
            .traces
            .iter()
            .cloned()
            .map(|t| (t.action.code().unwrap(), t.trace_address, t.subtraces))
            .collect();
        let expected = vec![
            (a_address, vec![], 6),
            (b_address, vec![0], 3),
            (d_address, vec![0, 0], 2),
            (e_address, vec![0, 0, 0], 0),
            (d_address, vec![0, 0, 1], 0),
            (c_address, vec![1], 1),
            (d_address, vec![1, 0], 0),
        ];
        assert_eq!(addresses, expected);

        let trace = tracker.trace_by_address(&[0, 0, 1]).unwrap();
        assert_eq!(trace.subtraces, 0);
        assert_eq!(trace.action.code().unwrap(), d_address);

        let trace = tracker.trace_by_address(&[0, 0, 0]).unwrap();
        assert_eq!(trace.subtraces, 0);
        assert_eq!(trace.action.code().unwrap(), e_address);

        let trace = tracker.trace_by_address(&[0, 0]).unwrap();
        assert_eq!(trace.subtraces, 2);
        assert_eq!(trace.action.code().unwrap(), d_address);

        let trace = tracker.trace_by_address(&[]).unwrap();
        assert_eq!(trace.subtraces, 6);
        assert_eq!(trace.action.code().unwrap(), a_address);

        let trace = tracker.trace_by_address(&[0]).unwrap();
        assert_eq!(trace.subtraces, 3);
        assert_eq!(trace.action.code().unwrap(), b_address);

        let trace = tracker.trace_by_address(&[1]).unwrap();
        assert_eq!(trace.action.code().unwrap(), c_address);
        assert_eq!(trace.subtraces, 1);

        let trace = tracker.trace_by_address(&[1, 0]).unwrap();
        assert_eq!(trace.action.code().unwrap(), d_address);
        assert_eq!(trace.subtraces, 0);
    }
}
