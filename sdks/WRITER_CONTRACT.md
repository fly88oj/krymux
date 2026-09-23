# Krymux SDK writer/flow-control contract

Normative note for every SDK's session writer and stream flow control (Rust
reference: `crates/krymux/src/mux.rs` `writer_task`; SDKs: Go
`pkg/mux/session.go` `writeLoop`, TS `src/mux.ts` `_writeData` +
`src/stream.ts` `_drainSendQ`, Python `krymux/mux.py` `_writer_loop`).
Wire formats are unchanged; this document pins the *behavioral* invariants
each port must keep so interleaved multi-stream traffic stays correct and
memory stays bounded.

1. **Drain only what is already queued.** Burst coalescing never waits for
   more frames to appear: after taking one frame, drain the frames already
   sitting in the queue (non-blocking checks), write them as one buffer, and
   only then block for the next frame. The lone-frame case must not pay an
   extra copy or latency.

2. **Bounded per-write.** Each runtime caps its coalesced write by its own
   cheap unit of work — the caps differ per runtime and that is intentional:
   - Rust: 16 frames per batch (`MAX_BATCH_FRAMES`, a *frame* cap).
   - Go: 16 frames *and* 256 KiB per batch.
   - TS: 16 frames per socket write (`TX_BATCH_FRAMES`, stream-side DATA
     batching); control frames are single-frame writes.
   - Python: 256 KiB per transport write (`_WRITER_BATCH_BYTES`, a *byte*
     cap) and a bounded writer queue (256 frames) with awaited backpressure.

3. **Flush before park.** Whatever has been accumulated must reach the socket
   before any await that can block (credit waits, socket/queue backpressure,
   queue-empty waits). Already-encoded frames must never be dropped or
   reordered by a park.

4. **Flush on teardown.** On session close the writer drains the frames
   already queued (GOAWAY included, best-effort) before closing the
   transport; a full queue must not wedge teardown, and the writer task must
   not outlive the session.

5. **Credit on consumption.** Receive-window (WINDOW) grants are issued as
   the *application consumes* delivered data (threshold-batched with a
   ticker/tail flush), not on frame arrival. This bounds the receiver's
   buffered data to the advertised window. A grant the writer cannot queue
   must be restored to the pending accumulator and retried — a dropped grant
   permanently stalls the peer's sender.
