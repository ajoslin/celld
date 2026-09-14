// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! Cell-isolate dispatch decisions, reified sans-IO. A cell isolate runs one
//! event at a time. A top-level Worker fetch takes the resident-isolate fast
//! path only when the isolate is idle; if the isolate is already pumping an
//! actor event, the fetch must reschedule to the stateless Worker pool — never
//! run nested — carrying its request identity so the reply still lands
//! (`js.rs`). The executor and the production run loop hold the isolate
//! channels and the pool; this is the pure routing they consult, so a
//! deterministic executor can drive it directly.
//!
//! Small protocol sequencing choices also live here when the executor owns
//! the bytes but not the decision. That keeps the shell mechanical and lets
//! callers exercise the same branch production takes.

/// Return whether a close code can appear in a WebSocket close frame.
///
/// RFC 6455 uses 1005, 1006, and 1015 only for local reporting, so an endpoint
/// cannot put them on the wire. Code 1004 is reserved. The IANA registry
/// assigns the remaining standard codes through 1014, and codes from 3000
/// through 4999 are available to applications and libraries.
pub fn websocket_close_code_is_allowed(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// Select the protocol close code the shell must echo after the application
/// close handler has run and all of its output has been written.
///
/// An application-selected close wins. Otherwise RFC 6455 requires a clean
/// peer close to receive a close response; 1005 is the local sentinel for a
/// frame with no status and cannot itself appear on the wire, so it becomes
/// the normal close code 1000. A parsed protocol failure receives its permitted
/// error code, while an abnormal transport end receives no frame.
pub fn websocket_echo_close(
    peer_code: u16,
    peer_was_clean: bool,
    handler_sent_close: bool,
) -> Option<u16> {
    if handler_sent_close {
        None
    } else if !peer_was_clean {
        matches!(peer_code, 1002 | 1007).then_some(peer_code)
    } else if peer_code == 1005 {
        Some(1000)
    } else {
        Some(peer_code)
    }
}

/// Track whether a Close frame has crossed a byte stream of server-to-client
/// WebSocket frames.
///
/// A hop that splices bytes between an owner and its client cannot see
/// frames, yet it must decide after the owner side ends whether the client
/// already received the owner's Close. Writing a second Close after one that
/// already crossed violates RFC 6455 section 5.5.1, and browsers fail the
/// connection with a protocol error ("Close received after close") instead
/// of ignoring it. The scanner keeps only the frame boundary state, so it
/// costs no copy of the payload.
#[derive(Debug, Default)]
pub struct WebSocketCloseScanner {
    state: ScanState,
    close_seen: bool,
}

#[derive(Debug, Default)]
enum ScanState {
    /// Between frames; the next byte is the first header byte.
    #[default]
    Opcode,
    /// The second header byte: mask bit and short length.
    Length,
    /// Reading an extended length of `remaining` bytes into `value`.
    ExtendedLength {
        masked: bool,
        remaining: u8,
        value: u64,
    },
    /// Skipping `remaining` bytes of masking key and payload.
    Skip { remaining: u64 },
}

impl WebSocketCloseScanner {
    const CLOSE_OPCODE: u8 = 0x8;

    /// Feed the bytes that were copied toward the client, in order.
    pub fn observe(&mut self, bytes: &[u8]) {
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            match &mut self.state {
                ScanState::Skip { remaining } => {
                    let available = (bytes.len() - index) as u64;
                    let taken = available.min(*remaining);
                    *remaining -= taken;
                    index += taken as usize;
                    if *remaining == 0 {
                        self.state = ScanState::Opcode;
                    }
                    continue;
                }
                ScanState::Opcode => {
                    // The opcode is known here; the rest of the frame only has
                    // to be skipped, so it is recorded now and not carried.
                    if byte & 0x0f == Self::CLOSE_OPCODE {
                        self.close_seen = true;
                    }
                    self.state = ScanState::Length;
                }
                ScanState::Length => {
                    let masked = byte & 0x80 != 0;
                    self.state = match byte & 0x7f {
                        126 => ScanState::ExtendedLength {
                            masked,
                            remaining: 2,
                            value: 0,
                        },
                        127 => ScanState::ExtendedLength {
                            masked,
                            remaining: 8,
                            value: 0,
                        },
                        length => Self::skip(masked, u64::from(length)),
                    };
                }
                ScanState::ExtendedLength {
                    masked,
                    remaining,
                    value,
                } => {
                    *value = (*value << 8) | u64::from(byte);
                    *remaining -= 1;
                    if *remaining == 0 {
                        self.state = Self::skip(*masked, *value);
                    }
                }
            }
            index += 1;
        }
    }

    /// Whether a Close frame header has crossed.
    pub fn close_seen(&self) -> bool {
        self.close_seen
    }

    fn skip(masked: bool, payload: u64) -> ScanState {
        let remaining = payload + if masked { 4 } else { 0 };
        if remaining == 0 {
            ScanState::Opcode
        } else {
            ScanState::Skip { remaining }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x80 | opcode];
        match payload.len() {
            len if len < 126 => bytes.push(len as u8),
            len if len < 65_536 => {
                bytes.push(126);
                bytes.extend((len as u16).to_be_bytes());
            }
            len => {
                bytes.push(127);
                bytes.extend((len as u64).to_be_bytes());
            }
        }
        bytes.extend(payload);
        bytes
    }

    #[test]
    fn close_frame_is_seen_after_text_frames() {
        let mut scanner = WebSocketCloseScanner::default();
        scanner.observe(&frame(0x1, b"hello"));
        scanner.observe(&frame(0x1, &vec![b'x'; 300]));
        assert!(!scanner.close_seen());
        scanner.observe(&frame(0x8, &[0x03, 0xe8, b'b', b'y', b'e']));
        assert!(scanner.close_seen());
    }

    #[test]
    fn close_opcode_inside_a_payload_is_ignored() {
        let mut scanner = WebSocketCloseScanner::default();
        scanner.observe(&frame(0x2, &[0x88, 0x00, 0x88, 0x02, 0x03, 0xe8]));
        assert!(!scanner.close_seen());
    }

    #[test]
    fn frames_split_across_reads_are_reassembled() {
        let mut scanner = WebSocketCloseScanner::default();
        let bytes = [frame(0x1, &vec![b'y'; 70_000]), frame(0x8, &[])].concat();
        for chunk in bytes.chunks(7) {
            scanner.observe(chunk);
        }
        assert!(scanner.close_seen());
    }

    #[test]
    fn masked_frames_skip_the_key() {
        let mut scanner = WebSocketCloseScanner::default();
        let mut masked = vec![0x88, 0x80 | 2, 1, 2, 3, 4, 0xaa, 0xbb];
        masked.extend(frame(0x1, b"after"));
        scanner.observe(&masked);
        assert!(scanner.close_seen());
        assert!(matches!(scanner.state, ScanState::Opcode));
    }
}
