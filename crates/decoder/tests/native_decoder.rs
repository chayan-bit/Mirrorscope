//! Integration tests for issue #17: exercises the public `decoder` API the
//! way an external consumer (replay, DAP) would — through `Box<dyn
//! SemanticDecoder>` and a hand-rolled `ProcessView`, never reaching into
//! crate internals.

use decoder::model::{FrameOrigin, TaskId, TaskKind};
use decoder::process_view::{PhysicalFrame, ProcessView, Registers, ThreadId};
use decoder::{select_decoder, DecoderError, NativeThreadsDecoder, SemanticDecoder};

struct TwoThreadView;

impl ProcessView for TwoThreadView {
    fn thread_ids(&self) -> Vec<ThreadId> {
        vec![ThreadId::new(1), ThreadId::new(2)]
    }

    fn registers(&self, thread: ThreadId) -> Result<Registers, DecoderError> {
        match thread.0 {
            1 | 2 => Ok(Registers { pc: 0, sp: 0 }),
            _ => Err(DecoderError::UnknownThread(thread)),
        }
    }

    fn read_memory(&self, _addr: u64, len: usize) -> Result<Vec<u8>, DecoderError> {
        Ok(vec![0; len])
    }

    fn physical_frames(&self, thread: ThreadId) -> Result<Vec<PhysicalFrame>, DecoderError> {
        match thread.0 {
            1 => Ok(vec![PhysicalFrame {
                pc: 0x1000,
                sp: 0x7f00,
                function_name: Some("main".to_string()),
                location: None,
            }]),
            2 => Ok(vec![PhysicalFrame {
                pc: 0x2000,
                sp: 0x7e00,
                function_name: Some("worker".to_string()),
                location: None,
            }]),
            _ => Err(DecoderError::UnknownThread(thread)),
        }
    }
}

/// Holding a `Box<dyn SemanticDecoder>` and calling every method through
/// the trait object is the object-safety proof: this would fail to compile
/// if any method took a generic parameter or a `Self: Sized` bound.
#[test]
fn semantic_decoder_is_object_safe_and_usable_boxed() {
    let decoder: Box<dyn SemanticDecoder> = Box::new(NativeThreadsDecoder::new());
    let view = TwoThreadView;

    let tree = decoder.decode_tasks(&view).expect("decode succeeds");
    assert_eq!(tree.len(), 2);

    for &task in tree.flatten_preorder().iter() {
        let node = tree.node(task).expect("node exists");
        assert_eq!(node.kind, TaskKind::Thread);

        let stack = decoder
            .logical_stack(&view, task)
            .expect("logical stack resolves");
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].origin, FrameOrigin::Physical);

        let wake = decoder
            .wake_cause(&view, task)
            .expect("wake cause resolves");
        assert_eq!(wake, decoder::model::WakeCause::Unknown);

        let locals = decoder
            .locals_at(&view, task, &stack[0])
            .expect("locals resolve");
        assert!(locals.is_empty());
    }
}

#[test]
fn select_decoder_returns_a_usable_boxed_decoder() {
    let decoder = select_decoder();
    let view = TwoThreadView;
    let tree = decoder.decode_tasks(&view).expect("decode succeeds");
    assert_eq!(tree.len(), 2);
}

#[test]
fn unknown_task_id_is_reported_not_guessed() {
    let decoder = NativeThreadsDecoder::new();
    let view = TwoThreadView;
    let err = decoder
        .logical_stack(&view, TaskId::new(999))
        .expect_err("task 999 does not exist");
    assert!(matches!(err, DecoderError::UnknownTask(TaskId(999))));
}
