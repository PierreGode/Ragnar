"""
Passive TCP stream reassembly for DNS over TCP.

WHY THIS EXISTS. Every detector in this module that reads a DNS
message larger than one segment was capped without it:

  * DNSD-044 (SIGRed, CVE-2020-1350) needs a ~64 kB response. The
    attack message does not fit in any MTU, so a single-segment
    sensor sees the first 1460 bytes and a truncated parse.
  * DNSD-060..063 (AXFR/IXFR disclosure and structure) read a stream
    of records whose shape is the finding. A transfer that spans
    segments was being judged on its first segment.
  * DNSD-040..044 (DNSSEC integrity) read RRSIG and DNSKEY sets that
    routinely exceed an MTU.

Before this module the TCP path in parse.py stripped the two-byte
DNS/TCP length prefix and handed the rest to the DNS parser WITHOUT
EVER COMPARING THE PREFIX TO WHAT ARRIVED. A message split across
segments was parsed from its first segment as though complete, and a
segment carrying several pipelined messages yielded only the first --
with the remainder read as trailing garbage.

WHAT IT DELIBERATELY IS NOT. This is not a TCP stack. It does not
track windows, congestion, timestamps, SACK, or options of any kind.
It never sends anything -- not an ACK, not a RST, nothing. It is a
byte-ordering buffer with a framer on top, and it is as small as that
job allows.

THE FOUR THINGS THAT MAKE PASSIVE REASSEMBLY HARD, and what is done
about each:

1. SEQUENCE WRAPAROUND. Sequence numbers are 32-bit and wrap. Every
   comparison here goes through seq_delta(), which does signed
   modular arithmetic. A direct `a > b` on raw sequence numbers is
   correct for about 2 GB of a stream and then silently inverts, and
   a long AXFR is exactly the traffic that gets there.

2. NO HANDSHAKE. A tap is normally attached to a network that is
   already carrying conversations, so most streams are first seen
   mid-flight with no SYN. That is the normal case, not an error:
   the first segment seen sets the base offset and reassembly
   proceeds from there. Refusing SYN-less streams would make the
   sensor useless for the first minutes of every deployment.

3. OVERLAP. Two segments can cover the same sequence range with
   different bytes. This module resolves overlap FIRST-WINS and
   reports the contradiction as DNSD-160, because the divergence is
   the attack: a resolver that resolves last-wins and a sensor that
   resolves first-wins parse different DNS messages out of one
   stream, which is how a passive tap is made to see something other
   than what the resolver acted on (Ptacek and Newsham, 1998).

   THE DETECTION WINDOW IS BOUNDED AND THAT IS STATED RATHER THAN
   HIDDEN. A contradicting segment is compared against bytes still
   buffered, plus a small trailing shadow of bytes already framed
   (tcp_reasm_shadow_bytes, 2 kB by default). Beyond that the
   original bytes are gone and there is nothing to compare against.
   The bound is the right shape for the threat: to change what the
   SENSOR parses, the contradicting segment has to arrive before the
   sensor frames the message, and that is inside the window by
   construction. The shadow extends coverage to late retransmissions
   that could still have changed what the RESOLVER saw.

4. MEMORY. A 64 kB message needs a 64 kB buffer, and this is the
   only part of the module that is genuinely memory-hungry. Every
   buffer is bounded: per stream, across all streams, and by age.
   Nothing here grows without a cap, every drop is counted, and the
   counters are reported.

GAPS ARE NEVER FILLED IN. Out-of-order segments are held, and bytes
are handed to the framer only when they are contiguous from the
delivery point. If a gap never closes the stream ages out and its
partial message is dropped and counted. A reassembler that guessed
at missing bytes would be inventing DNS messages, and the findings
built on them would be fabrications.
"""

import parse

# ----------------------------------------------------------------------
# 32-bit sequence arithmetic
# ----------------------------------------------------------------------

_SEQ_MOD = 1 << 32
_SEQ_HALF = 1 << 31


def seq_delta(a, b):
    """a - b in signed 32-bit modular space (RFC 1982 serial
    arithmetic, which is also how TCP compares sequence numbers).

    Returns a value in [-2**31, 2**31). Every ordering decision in
    this module goes through here. The naive `a - b` is right until a
    stream crosses the wrap point, and then a later segment compares
    as 4 GB earlier than an earlier one -- which presents as a
    permanent gap and a silently dead stream, not as an error.
    """
    d = (a - b) % _SEQ_MOD
    return d - _SEQ_MOD if d >= _SEQ_HALF else d


class ReasmStats:
    """Counters. Every byte this module refuses to keep is counted, so
    a quiet sensor can be told apart from a saturated one."""
    __slots__ = ("segments", "messages", "bytes_held", "overlaps_identical",
                 "overlaps_mismatch", "evicted_streams", "aged_streams",
                 "dropped_bytes", "framing_errors", "before_window",
                 "streams_opened", "streams_closed", "pending_dropped",
                 "reset_streams", "reused_keys", "fin_streams",
                 "unsynced_waits")

    def __init__(self):
        for f in self.__slots__:
            setattr(self, f, 0)

    def snapshot(self):
        return {f: getattr(self, f) for f in self.__slots__}


class TcpStream:
    """One direction of one TCP conversation.

    Offsets are RELATIVE to the first sequence number seen, so the
    32-bit space is left behind after the first segment and the rest
    of this class does ordinary Python integer arithmetic.
    """
    __slots__ = ("key", "base", "consumed", "buf", "pending", "pending_bytes",
                 "shadow", "shadow_start", "first_seen", "last_seen",
                 "saw_syn", "closed", "mismatch_reported", "synced")

    def __init__(self, key, seq, now, saw_syn=False):
        self.key = key
        # If the SYN was seen, its sequence number is the ISN and the
        # first data byte is ISN+1. Without it the first segment seen
        # defines offset zero -- the mid-flight case, which is most of
        # them on a tap.
        self.base = (seq + 1) & 0xFFFFFFFF if saw_syn else seq
        self.consumed = 0          # relative offset of buf[0]
        self.buf = bytearray()     # contiguous, not yet framed
        self.pending = {}          # rel_offset -> bytes, ahead of buf
        self.pending_bytes = 0
        self.shadow = bytearray()  # trailing copy of already-framed bytes
        self.shadow_start = 0
        self.first_seen = now
        self.last_seen = now
        self.saw_syn = saw_syn
        self.closed = False
        self.mismatch_reported = False
        # Is buf[0] known to be a MESSAGE BOUNDARY? Only the SYN
        # proves it: with the handshake in hand the first data byte is
        # ISN+1 and therefore the first byte of the first message.
        # Without it the buffer may start in the middle of a message,
        # and the two octets at its head are body bytes rather than a
        # length prefix. See _plausible_dns.
        self.synced = saw_syn

    @property
    def next_rel(self):
        """The next contiguous relative offset expected."""
        return self.consumed + len(self.buf)

    def held(self):
        return len(self.buf) + self.pending_bytes + len(self.shadow)


def _plausible_dns(buf, mlen):
    """Could `buf[2:2+mlen]` be a DNS message?

    THIS IS NOT VALIDATION, it is resynchronisation. It answers one
    question: are the two octets at the head of this buffer a length
    prefix, or are they body bytes from the middle of a message?

    The question is unavoidable. A sensor without the handshake does
    not know where message boundaries are, and that is the common
    case on a tap. It also arises with ordinary out-of-order
    delivery: while earlier segments are still arriving the buffer
    start keeps moving backwards, and until it settles buf[0] is not
    a boundary. The first version of this module framed whatever was
    at the head of the buffer, so a reversed 47-segment stream
    produced a 23130-byte "message" -- 23130 being 0x5A5A, which is
    to say the two padding letters "ZZ" read as a length.

    A mis-frame is not merely a lost message: every later message in
    the stream inherits the wrong boundary, so the output is garbage
    that parses. Hence the gate.
    """
    if mlen < 12:
        return False                       # shorter than a DNS header
    if len(buf) < 14:
        return False
    flags = (buf[4] << 8) | buf[5]
    opcode = (flags >> 11) & 0x0F
    if opcode > 5:
        return False                       # 0-5 assigned, 6+ unassigned
    qd = (buf[6] << 8) | buf[7]
    an = (buf[8] << 8) | buf[9]
    ns = (buf[10] << 8) | buf[11]
    ar = (buf[12] << 8) | buf[13]
    # RFC 1035 allows one question; nothing on TCP/53 sends more, and
    # a few is generous.
    if qd > 4:
        return False
    # The cheapest possible record is a root owner plus the ten fixed
    # octets of type, class, TTL and rdlength. A count that cannot fit
    # in the message it claims to describe is not a count.
    if qd * 5 + (an + ns + ar) * 11 > mlen:
        return False
    return True


def _sync_ok(buf, mlen):
    """Is `buf` positioned at a real message boundary?

    _plausible_dns alone is not enough, and the cross-check tier is
    what established that: a 43 kB response delivered in reversed
    536-byte segments produced a 14132-byte "message", because a
    prefix formed by two bytes of TXT rdata 16 kB into the stream
    happened to sit in front of twelve bytes that passed the header
    check. The buffer start keeps moving backwards while earlier
    segments arrive, so there are thousands of chances for one of
    them to look right.

    So the candidate has to clear the header check AND one of three
    corroborations, each of which the bogus candidate above failed:

      * it consumes the buffer exactly -- nothing left over;
      * the bytes immediately after it are themselves a plausible
        prefix, so the framing CHAINS;
      * it parses as a DNS message without being malformed.

    The last one is deliberately not the only test. A malformed DNS
    message is itself a finding here (DNSD-007, DNSD-008), and a gate
    that demanded clean parsing would quietly drop exactly the
    messages this module exists to report, on any stream whose
    handshake the sensor did not see.
    """
    if not _plausible_dns(buf, mlen):
        return False
    rest = len(buf) - (2 + mlen)
    if rest == 0:
        return True                        # exact fit
    if rest >= 14:
        nxt = (buf[2 + mlen] << 8) | buf[2 + mlen + 1]
        if _plausible_dns(buf[2 + mlen:], nxt):
            return True                    # the framing chains
    try:
        if not parse.parse_dns(bytes(buf[2:2 + mlen])).malformed:
            return True                    # it is a DNS message
    except Exception:                      # noqa: BLE001
        return False
    return False


class Reassembler:
    """The stream table.

    add() takes one segment and returns (messages, events):
    complete DNS messages in stream order, and reassembly events the
    engine turns into findings.
    """

    def __init__(self, cfg, stats=None):
        self.cfg = cfg
        self.stats = stats if stats is not None else ReasmStats()
        self.streams = {}          # key -> TcpStream, insertion-ordered (LRU)
        self.total_bytes = 0

    # -- housekeeping ---------------------------------------------------

    def _touch(self, key, st):
        """Move to the LRU tail. dict preserves insertion order, so
        re-inserting is the move."""
        del self.streams[key]
        self.streams[key] = st

    def _drop(self, key, counter):
        st = self.streams.pop(key, None)
        if st is None:
            return
        self.total_bytes -= st.held()
        self.stats.dropped_bytes += len(st.buf) + st.pending_bytes
        setattr(self.stats, counter, getattr(self.stats, counter) + 1)
        self.stats.streams_closed += 1

    def expire(self, now):
        """Age out streams whose gap never closed. Called from add()
        so there is no timer thread; a stream that stops arriving is
        only reclaimed when some other stream is active, which is the
        right trade for a sensor with no clock of its own."""
        limit = self.cfg.tcp_reasm_timeout
        stale = [k for k, st in self.streams.items()
                 if now - st.last_seen > limit]
        for k in stale:
            self._drop(k, "aged_streams")

    def _make_room(self, want):
        """Evict least-recently-used streams until `want` more bytes
        fit under the global cap."""
        cap = self.cfg.tcp_reasm_max_bytes
        while self.streams and self.total_bytes + want > cap:
            self._drop(next(iter(self.streams)), "evicted_streams")

    # -- the hot path ---------------------------------------------------

    def add(self, key, seq, data, flags, now):
        """Feed one segment. Returns (messages, events)."""
        events = []
        self.expire(now)

        rst = bool(flags & parse.TCP_RST)
        syn = bool(flags & parse.TCP_SYN)
        fin = bool(flags & parse.TCP_FIN)

        if rst:
            # A reset abandons whatever was buffered. Nothing can be
            # recovered from a partial message and guessing is not an
            # option, so it is dropped and counted.
            self._drop(key, "reset_streams")
            return [], events

        st = self.streams.get(key)

        if st is not None and syn and not data:
            # A SYN on a key that already has state is a NEW
            # connection reusing the 4-tuple, not a continuation. The
            # old stream's bytes belong to a different conversation
            # and must not be concatenated with the new one's -- that
            # would splice two conversations into one DNS message.
            self._drop(key, "reused_keys")
            st = None

        if st is None:
            if len(self.streams) >= self.cfg.tcp_reasm_max_streams:
                self._drop(next(iter(self.streams)), "evicted_streams")
            st = TcpStream(key, seq, now, saw_syn=syn)
            self.streams[key] = st
            self.stats.streams_opened += 1

        st.last_seen = now
        self.stats.segments += 1

        if data:
            events += self._absorb(st, seq, data, now)

        messages = self._frame(st)

        if fin or st.closed:
            # Messages already framed above are returned; whatever is
            # left is a partial message, and a partial message at FIN
            # stays partial. Dropped and counted, never guessed at.
            self._drop(key, "fin_streams")
        else:
            self._touch(key, st)

        return messages, events

    def _absorb(self, st, seq, data, now):
        """Place a segment's bytes, first-wins, checking overlap."""
        events = []
        rel = seq_delta(seq, st.base)
        end = rel + len(data)

        # ---- REBASE -------------------------------------------------
        # A segment starting before the base means the base came from
        # a segment that was itself out of order: on a tap the first
        # segment SEEN is not necessarily the first segment SENT, and
        # without a SYN there is nothing else to anchor offset zero
        # to. This is the ordinary case, not a corner one -- the
        # first version of this module discarded the earlier segment
        # and silently lost the whole message whenever the two
        # arrived in the wrong order.
        #
        # Offsets are relative, so rebasing means shifting everything
        # already held forward by the same amount.
        # Not gated on having seen a SYN. A SYN consumes its own
        # sequence number, so data in a SYN segment nominally starts
        # at ISN+1 -- but a sensor that insisted on that would lose
        # the whole stream to an off-by-one whenever the assumption
        # does not hold for the sender in front of it. While nothing
        # has been framed there are no decisions to invalidate, so
        # anchoring on the data actually seen is strictly better than
        # being right about the ISN and parsing nothing.
        if (rel < 0 and st.consumed == 0 and not st.shadow
                and -rel <= self.cfg.tcp_reasm_stream_max_bytes):
            d = -rel
            shifted = {k + d: v for k, v in st.pending.items()}
            if st.buf:
                # buf sat at relative 0; it now sits at d.
                shifted[d] = bytes(st.buf)
                st.pending_bytes += len(st.buf)
                st.buf = bytearray()
            st.pending = shifted
            st.base = seq
            rel, end = 0, len(data)
            # The buffer start just moved, so whatever was believed
            # about the boundary no longer holds -- unless the SYN
            # anchored it, in which case a rebase should not have
            # been possible at all.
            if not st.saw_syn:
                st.synced = False
        elif rel < 0:
            # Either something has already been framed (so offset
            # zero is fixed), or the distance is implausible and this
            # is a wrap artefact or a different conversation. Only
            # the part overlapping the checkable window is of any use.
            pass

        # Entirely behind everything still checkable. THIS HAS TO COME
        # AFTER THE REBASE: with rel negative and nothing yet framed,
        # `end` is at or below shadow_start by arithmetic, so running
        # this check first discarded exactly the segments the rebase
        # exists to recover -- which is to say every out-of-order
        # message, counted as "before_window" while the stream sat
        # there waiting for bytes it had already been given.
        if end <= st.shadow_start and (st.consumed or st.shadow):
            self.stats.before_window += 1
            return events
        if end <= 0:
            self.stats.before_window += 1
            return events

        # ---- overlap: compare against bytes we still have ----------
        ov = self._check_overlap(st, rel, data)
        if ov is not None:
            same, at, mine, theirs = ov
            if same:
                self.stats.overlaps_identical += 1
            else:
                self.stats.overlaps_mismatch += 1
                # One event per stream. A retransmitting attacker
                # would otherwise produce one finding per segment.
                if not st.mismatch_reported:
                    st.mismatch_reported = True
                    events.append({
                        "event": "overlap_mismatch", "key": st.key,
                        "rel_offset": at, "length": len(data),
                        "first_bytes": bytes(mine[:16]),
                        "later_bytes": bytes(theirs[:16]),
                        "seq": seq, "stream_age": now - st.first_seen,
                    })

        # ---- place only the bytes we do not already have -----------
        # OPTIMISATION, NOT A GUARD. Removing this branch is
        # observationally equivalent: the trim below would reduce a
        # pure retransmission to zero bytes and _append would do
        # nothing with them. Verified by running a corpus of segment
        # orderings through both variants and comparing the delivered
        # messages byte for byte -- which is why a mutation that
        # removes it escapes every tier, and correctly so.
        # Retransmissions are common enough on a real tap to be worth
        # the early exit.
        if end <= st.next_rel:
            return events                      # pure retransmission
        # THIS ONE IS A GUARD. It enforces first-wins for a segment
        # that overlaps the delivery point and extends PAST it: the
        # already-delivered prefix is discarded and only the new tail
        # is kept. Removing it does not merely cost performance -- a
        # stream containing such a segment then delivers nothing at
        # all, because the segment is parked behind the delivery
        # point and the drain cannot use it.
        if rel < st.next_rel:
            data = data[st.next_rel - rel:]    # first-wins on the prefix
            rel = st.next_rel

        if rel == st.next_rel:
            self._append(st, data)
            self._drain_pending(st)
        else:
            self._hold(st, rel, data)
        return events

    def _check_overlap(self, st, rel, data):
        """Compare `data` against the overlapping part of buf or the
        shadow. Returns (identical, offset, ours, theirs) or None.

        Only the buffered and shadowed ranges can be checked, which is
        the documented bound on DNSD-160.
        """
        # buf covers [consumed, next_rel); shadow covers
        # [shadow_start, consumed).
        for lo, hi, store, store_lo in (
                (st.consumed, st.next_rel, st.buf, st.consumed),
                (st.shadow_start, st.consumed, st.shadow, st.shadow_start)):
            a, b = max(rel, lo), min(rel + len(data), hi)
            if a >= b:
                continue
            ours = store[a - store_lo:b - store_lo]
            theirs = data[a - rel:b - rel]
            if bytes(ours) != bytes(theirs):
                return (False, a, ours, theirs)
            return (True, a, ours, theirs)
        return None

    def _append(self, st, data):
        room = self.cfg.tcp_reasm_stream_max_bytes - len(st.buf)
        if room <= 0:
            self.stats.dropped_bytes += len(data)
            return
        if len(data) > room:
            # A stream claiming more than the per-stream cap is not
            # going to produce a parseable message; keep what fits so
            # the framer can still reject it, and count the rest.
            self.stats.dropped_bytes += len(data) - room
            data = data[:room]
        self._make_room(len(data))
        st.buf += data
        self.total_bytes += len(data)
        self.stats.bytes_held += len(data)

    def _hold(self, st, rel, data):
        """Park an out-of-order segment."""
        if st.pending_bytes + len(data) > self.cfg.tcp_reasm_stream_max_bytes:
            self.stats.pending_dropped += 1
            self.stats.dropped_bytes += len(data)
            return
        if rel in st.pending and len(st.pending[rel]) >= len(data):
            return                             # already held, first-wins
        if rel in st.pending:
            self.total_bytes -= len(st.pending[rel])
            st.pending_bytes -= len(st.pending[rel])
        self._make_room(len(data))
        st.pending[rel] = bytes(data)
        st.pending_bytes += len(data)
        self.total_bytes += len(data)

    def _drain_pending(self, st):
        """Move held segments into buf while they are contiguous."""
        while st.pending:
            nxt = st.next_rel
            seg = st.pending.pop(nxt, None)
            if seg is None:
                # Nothing starts exactly at the hole. A segment that
                # STARTS earlier and reaches past it can still close
                # it -- that is the out-of-order-plus-overlap case.
                cands = [r for r in st.pending if r < nxt and r + len(st.pending[r]) > nxt]
                if not cands:
                    break
                r = min(cands)
                seg = st.pending.pop(r)
                st.pending_bytes -= len(seg)
                self.total_bytes -= len(seg)
                seg = seg[nxt - r:]
                st.buf += seg
                self.total_bytes += len(seg)
                continue
            st.pending_bytes -= len(seg)
            self.total_bytes -= len(seg)
            self._append(st, seg)

    def _frame(self, st):
        """Pull complete DNS messages out of the contiguous buffer.

        RFC 1035 s4.2.2: each message is preceded by a two-octet
        length. Both halves of that prefix can arrive in different
        segments, and one segment can carry several whole messages,
        so this loops rather than looking at the head once.
        """
        out = []
        while len(st.buf) >= 2:
            mlen = (st.buf[0] << 8) | st.buf[1]
            # UNSYNCHRONISED STREAM: buf[0] is not known to be a
            # message boundary, so the prefix has to earn belief
            # before it is acted on. Once one message frames
            # plausibly the boundary is established and everything
            # after it follows by construction.
            if not st.synced:
                if len(st.buf) < 2 + mlen:
                    break                  # not enough to judge yet
                if not _sync_ok(st.buf, mlen):
                    # Earlier segments may still arrive and move the
                    # buffer start backwards. Wait rather than guess.
                    # If they never come, the per-stream cap and the
                    # age-out reclaim this.
                    self.stats.unsynced_waits += 1
                    break
                st.synced = True
            if mlen == 0:
                # Not a legal DNS message. Resyncing on a stream whose
                # framing is already wrong would be guessing, so the
                # stream is abandoned: a wrong frame boundary turns
                # every later message into garbage, and garbage that
                # parses is worse than nothing.
                self.stats.framing_errors += 1
                self._consume(st, len(st.buf))
                st.closed = True
                break
            if len(st.buf) < 2 + mlen:
                break                          # wait for more bytes
            out.append(bytes(st.buf[2:2 + mlen]))
            self._consume(st, 2 + mlen)
            self.stats.messages += 1
        return out

    def _consume(self, st, n):
        """Drop n bytes from the head of buf into the shadow."""
        gone = st.buf[:n]
        del st.buf[:n]
        self.total_bytes -= n
        st.consumed += n
        # The shadow keeps the tail of what was framed, so a late
        # contradicting retransmission can still be compared.
        keep = self.cfg.tcp_reasm_shadow_bytes
        if keep <= 0:
            st.shadow_start = st.consumed
            return
        self.total_bytes -= len(st.shadow)
        st.shadow += gone
        if len(st.shadow) > keep:
            del st.shadow[:len(st.shadow) - keep]
        st.shadow_start = st.consumed - len(st.shadow)
        self.total_bytes += len(st.shadow)

    # -- introspection --------------------------------------------------

    def __len__(self):
        return len(self.streams)
