#include "check.hpp"
// aether - receiver flow control: the advertised receive window.
//
// Backpressure alone never loses data silently, but the sender only discovers the receiver's limit by
// retransmitting into it, and every refused attempt spends one of the message's retries. The
// advertised credit lets the sender stop first. What is pinned here: a receiver that is keeping up
// advertises NOTHING (a healthy link must not pay for this), a restricted one advertises and the
// sender actually stops, a reopen resumes it, and the decoder rejects hostile bytes.
//
// Note the cap binds on a WITHIN-TICK burst: peerProcess drains every channel into events on every
// tick, so the receive buffer only accumulates from the packets of a single tick.
#include "aether/channel.hpp"
#include "aether/connection.hpp"
#include "aether/peer.hpp"
#include "aether/testnet.hpp"

#include <cstdint>
#include <cstdio>

using namespace aether;
using aether::test::require;

namespace {

constexpr std::uint64_t tickNs = 16000000;   // ~60Hz

// A WindowUpdate arrives with a header like any other packet, and applyWindowUpdate reads its sequence
// to drop reordered ones.
PacketHeader windowHeader(std::uint16_t seq) {
    PacketHeader h{};
    h.type     = PacketType::WindowUpdate;
    h.sequence = SequenceNum{ seq };
    return h;
}
// Strictly newer than whatever this connection last applied. The handshake already delivers one
// advertisement (capacity is unconditional on connect), so a hand-built update has to clear that or
// the freshness check drops it before the payload is ever read.
PacketHeader freshWindowHeader(const Connection& c) {
    return windowHeader(static_cast<std::uint16_t>(c.windowUpdateAppliedSeq.value + 1));
}

struct Pair {
    NetPeer  server;
    NetPeer  client;
    PeerId   sp;
    PeerId   cp;
    TestLink link;
};

MonoTime connectPair(Pair& p, const NetworkConfig& cfg, MonoTime now) {
    const Address sa = addrV4(0x0A000001, 1000), ca = addrV4(0x0A000002, 2000);
    p.sp     = PeerId{ sa };
    p.cp     = PeerId{ ca };
    p.server = newPeerState(sa, cfg, now);
    p.client = newPeerState(ca, cfg, now);
    p.link   = newTestLink(p.server, p.sp, p.client, p.cp);
    peerConnect(p.client, p.sp, now);
    now = testLinkConnect(p.link, now, tickNs, 400);
    require(peerIsConnected(p.client, p.sp));
    require(peerIsConnected(p.server, p.cp));
    return now;
}

// Payload packets queued since index `from` -- what the channel actually got to send.
int payloadsQueuedSince(const Connection& c, std::size_t from) {
    int n = 0;
    for (std::size_t k = from; k < c.sendQueue.size(); ++k)
        if (c.sendQueue[k].type == PacketType::Payload || c.sendQueue[k].type == PacketType::PayloadBatch) ++n;
    return n;
}
bool queuedWindowUpdateSince(const Connection& c, std::size_t from) {
    for (std::size_t k = from; k < c.sendQueue.size(); ++k)
        if (c.sendQueue[k].type == PacketType::WindowUpdate) return true;
    return false;
}

NetworkConfig cappedConfig(int cap) {
    NetworkConfig cfg = aether::test::anonymousConfig<NetworkConfig>();
    ChannelConfig cc          = reliableOrderedChannel();
    cc.maxReceiveBufferSize   = cap;
    cfg.channelConfigs        = { cc };
    cfg.maxChannels           = 1;
    return cfg;
}

} // namespace

int main() {
    // ---- the capacity is advertised exactly once, then the link goes quiet ----
    //
    // The sender cannot guess how much the receiver can absorb, and assuming no limit makes it
    // overrun the buffer every tick and pay the difference in refusals and retransmits (measured:
    // 4672 messages through with the credit known, 288 without, on the same link). So the first
    // advertisement is unconditional. After that a receiver that keeps draining reports the same
    // figure forever, so the steady state is one packet per connection and nothing more.
    {
        constexpr int cap = 64;
        Pair     p;
        MonoTime now = connectPair(p, cappedConfig(cap), MonoTime{ 0 });
        Connection& srv = p.server.connections.at(p.cp);

        // Establishing the capacity is automatic: it rides the ordinary tick, with the application
        // doing nothing, so the sender is paced correctly from the start rather than after its first
        // overrun.
        for (int t = 0; t < 5; ++t) { now = MonoTime{ now.ns + tickNs }; testLinkStep(p.link, now); }
        require(srv.windowAdvertised);
        require(srv.advertisedCredit[0] == cap);
        require(p.client.connections.at(p.sp).peerCredit[0] == cap);   // ...and the sender has it

        for (int t = 0; t < 30; ++t) {                   // ...and it is never repeated while the receiver keeps up
            now = MonoTime{ now.ns + tickNs };
            const std::size_t before = srv.sendQueue.size();
            maybeAdvertiseWindow(srv, now);
            require(!queuedWindowUpdateSince(srv, before));
        }
    }

    // ---- a LOST reopen must not wedge the sender forever ----
    //
    // A WindowUpdate is not registered in the sent ring, so nothing retransmits it. The reopen that
    // follows a drain is a single datagram, and once it is sent the receiver is unrestricted with a
    // steady free count, so nothing triggers another. Losing that one datagram would leave the sender
    // at credit 0 with no way to ever hear otherwise: the channel would be dead on a healthy link.
    //
    // The cap MUST exceed windowLowCredit here. At cap <= 8 the channel can never have more than
    // windowLowCredit free, so it is permanently "restricted", the persist timer always fires, and a
    // lost reopen cannot be observed.
    {
        constexpr int cap = 64;
        static_assert(cap > windowLowCredit, "a cap at or below the threshold is always restricted");
        Pair     p;
        MonoTime now = connectPair(p, cappedConfig(cap), MonoTime{ 0 });
        Connection& srv = p.server.connections.at(p.cp);

        for (int t = 0; t < 5; ++t) { now = MonoTime{ now.ns + tickNs }; testLinkStep(p.link, now); }
        require(srv.advertisedCredit[0] == cap);

        // Fill the buffer so the receiver is restricted, and report it.
        for (int i = 0; i < cap; ++i)
            onMessageReceived(srv.channels[0], SequenceNum{ static_cast<std::uint16_t>(i) }, Bytes{ 0x01 }, now);
        now = MonoTime{ now.ns + tickNs };
        maybeAdvertiseWindow(srv, now);
        require(srv.advertisedCredit[0] == 0);

        // The application drains: the receiver crosses back out of restricted and emits the reopen.
        srv.channels[0].receiveBuffer.clear();
        now = MonoTime{ now.ns + tickNs };
        std::size_t before = srv.sendQueue.size();
        maybeAdvertiseWindow(srv, now);
        require(queuedWindowUpdateSince(srv, before));   // the reopen goes out...
        require(srv.advertisedCredit[0] == cap);
        require(!srv.windowUpdateAcked);                 // ...and is outstanding until a header covers it

        // Now LOSE it: never deliver the ack. The receiver is unrestricted and its free count is
        // steady, so nothing about its own state will ever prompt it again -- only the fact that the
        // peer never confirmed. It must keep re-sending on the refresh timer.
        bool resent = false;
        for (int t = 0; t < 60 && !resent; ++t) {        // ~1s at 60Hz, refresh is 250ms
            now    = MonoTime{ now.ns + tickNs };
            before = srv.sendQueue.size();
            maybeAdvertiseWindow(srv, now);
            resent = queuedWindowUpdateSince(srv, before);
        }
        require(resent);   // otherwise the sender stays at credit 0

        // And once the peer finally acknowledges it, the repeats stop: this must not become a
        // permanent 250ms heartbeat on an idle healthy link.
        PacketHeader ack{};
        ack.type    = PacketType::Keepalive;
        ack.ack     = srv.windowUpdateSeq;
        ack.ackBits = 0;
        processIncomingAcks(srv, ack, now);
        require(srv.windowUpdateAcked);
        for (int t = 0; t < 60; ++t) {
            now    = MonoTime{ now.ns + tickNs };
            before = srv.sendQueue.size();
            maybeAdvertiseWindow(srv, now);
            require(!queuedWindowUpdateSince(srv, before));   // confirmed: silent again
        }
    }

    // ---- a restricted receiver advertises, and the sender stops ----
    {
        constexpr int cap = 16;
        Pair     p;
        MonoTime now = connectPair(p, cappedConfig(cap), MonoTime{ 0 });
        Connection& srv = p.server.connections.at(p.cp);
        Connection& cli = p.client.connections.at(p.sp);

        for (int t = 0; t < 5; ++t) { now = MonoTime{ now.ns + tickNs }; testLinkStep(p.link, now); }
        require(srv.advertisedCredit[0] == cap);         // capacity established during the handshake

        // Now hold messages in the buffer: this models a collection that did not keep up, which is
        // the only way occupancy survives past a tick. Sequences from 0 so an ordered channel
        // delivers each one straight through rather than holding it in the reorder buffer.
        for (int i = 0; i < cap; ++i)
            onMessageReceived(srv.channels[0], SequenceNum{ static_cast<std::uint16_t>(i) }, Bytes{ 0x01 }, now);
        require(channelFreeReceiveSlots(srv.channels[0]) == 0);

        now = MonoTime{ now.ns + tickNs };
        const std::size_t before = srv.sendQueue.size();
        maybeAdvertiseWindow(srv, now);
        require(queuedWindowUpdateSince(srv, before));   // the restriction is reported
        require(srv.windowAdvertised);
        require(srv.advertisedCredit[0] == 0);

        // Deliver that advertisement to the sender.
        const Bytes upd       = encodeWindowUpdate(srv);
        const bool  delivered = applyWindowUpdate(cli, freshWindowHeader(cli), ByteSpan(upd.data(), upd.size()));
        require(delivered);
        require(cli.peerCredit[0] == 0);

        // With no credit the sender must admit nothing -- and must not lose it either. The messages
        // stay queued, which is what makes channelSend report BufferFull to the application instead
        // of the wire quietly eating one.
        for (int i = 0; i < 8; ++i) {
            const auto err = sendMessage(cli, ChannelId{ 0 }, Bytes(32, 0xAB), now);
            require(!err);
        }
        now = MonoTime{ now.ns + tickNs };
        const std::size_t q = cli.sendQueue.size();
        updateConnectedPure(cli, now);
        require(payloadsQueuedSince(cli, q) == 0);           // nothing went out
        require(cli.channels[0].sendBuffer.size() == 8);     // ...and nothing was dropped to make it so
        require(cli.channels[0].totalDropped == 0);

        // A blocked message must not burn its retry budget either: that burn is exactly the data
        // loss the advertised window exists to prevent.
        for (int t = 0; t < 20; ++t) {
            now = MonoTime{ now.ns + tickNs };
            updateConnectedPure(cli, now);
        }
        require(cli.channels[0].sendBuffer.size() == 8);
        require(cli.channels[0].totalDropped == 0);
        require(cli.channels[0].totalRetransmits == 0);

        // Reopen: the sender resumes immediately.
        cli.peerCredit[0] = 256;
        now = MonoTime{ now.ns + tickNs };
        const std::size_t q2 = cli.sendQueue.size();
        updateConnectedPure(cli, now);
        require(payloadsQueuedSince(cli, q2) > 0);
    }

    // ---- the window must never wedge a live connection ----
    //
    // A lost "reopened" update would strand the sender forever, which is why the receiver
    // re-advertises on a timer while restricted. End to end, every message still arrives.
    {
        constexpr int total = 120;
        Pair     p;
        MonoTime now = connectPair(p, cappedConfig(8), MonoTime{ 0 });

        TestLinkConfig lossy;
        lossy.lossRate = 0.10;   // updates get lost too
        testLinkImpair(p.link, lossy);

        int sent = 0, delivered = 0;
        for (int t = 0; t < 1200; ++t) {
            now = MonoTime{ now.ns + tickNs };
            while (sent < total) {   // offer as fast as the channel will take it
                if (peerSend(p.client, p.sp, ChannelId{ 0 }, Bytes(24, static_cast<std::uint8_t>(sent)), now)) break;
                ++sent;
            }
            const TestLinkStep s = testLinkStep(p.link, now);
            for (const PeerEvent& e : s.aEvents)
                if (e.kind == PeerEvent::Message) ++delivered;
            if (sent == total && delivered == total) break;
        }
        require(sent == total);
        require(delivered == total);   // the window throttled, it never stranded anything
        require(p.client.connections.at(p.sp).channels[0].totalDropped == 0);
    }

    // ---- a full REORDER buffer closes the advertised window ----
    //
    // A gap holds every later message in the reorder buffer, bufferOrdered refuses at
    // maxOrderedBufferSize, and a refused packet is left unacked so the sender retransmits. A credit
    // that counted only the receive buffer would advertise thousands of free slots while the reorder
    // buffer sat at its cap: the sender would keep pushing into a buffer that stays full until
    // orderedBufferTimeout -- an order of magnitude longer than a retry budget lasts -- and the run of
    // messages behind the gap would be destroyed rather than delayed.
    {
        NetworkConfig cfg = aether::test::anonymousConfig<NetworkConfig>();
        ChannelConfig cc        = reliableOrderedChannel();
        cc.maxOrderedBufferSize = 4;
        cc.maxReceiveBufferSize = 8192;
        cfg.channelConfigs      = { cc };
        cfg.maxChannels         = 1;

        Pair     p;
        MonoTime now = connectPair(p, cfg, MonoTime{ 0 });
        Connection& srv = p.server.connections.at(p.cp);
        Connection& cli = p.client.connections.at(p.sp);
        for (int t = 0; t < 5; ++t) { now = MonoTime{ now.ns + tickNs }; testLinkStep(p.link, now); }
        require(srv.advertisedCredit[0] == 8192);   // no gap yet: the receive buffer is the only limit

        // seq 0 is lost; 1..4 arrive and fill the reorder buffer, so the 5th has nowhere to go.
        for (std::uint16_t s = 1; s <= 4; ++s)
            onMessageReceived(srv.channels[0], SequenceNum{ s }, Bytes{ 0x01 }, now);
        const bool refused = onMessageReceived(srv.channels[0], SequenceNum{ 5 }, Bytes{ 0x01 }, now);
        require(!refused);
        require(srv.channels[0].totalRefused == 1);
        require(channelFreeReceiveSlots(srv.channels[0]) == 1);   // the credit SEES the reorder buffer

        now = MonoTime{ now.ns + tickNs };
        const std::size_t before = srv.sendQueue.size();
        maybeAdvertiseWindow(srv, now);
        require(queuedWindowUpdateSince(srv, before));           // ...and the receiver reports it
        require(srv.advertisedCredit[0] == 1);

        // Deliver it.
        const Bytes upd       = encodeWindowUpdate(srv);
        const bool  delivered = applyWindowUpdate(cli, freshWindowHeader(cli), ByteSpan(upd.data(), upd.size()));
        require(delivered);
        require(cli.peerCredit[0] == 1);

        // The sender stops at that one slot instead of pushing a run of messages into a buffer
        // that cannot take any of them -- and nothing is dropped to make it so.
        for (int i = 0; i < 8; ++i) {
            const auto err = sendMessage(cli, ChannelId{ 0 }, Bytes(32, 0xAB), now);
            require(!err);
        }
        now = MonoTime{ now.ns + tickNs };
        const std::size_t q = cli.sendQueue.size();
        updateConnectedPure(cli, now);
        require(payloadsQueuedSince(cli, q) == 1);             // exactly the room the receiver stated
        require(cli.channels[0].sendBuffer.size() == 8);
        require(cli.channels[0].totalDropped == 0);
        require(cli.channels[0].totalReliableDropped == 0);

        // The one-slot floor is what keeps this backpressure rather than deadlock: the message that
        // FILLS the gap is delivered straight through, so the window reopens on its own.
        const bool filled = onMessageReceived(srv.channels[0], SequenceNum{ 0 }, Bytes{ 0x01 }, now);
        require(filled);
        require(srv.channels[0].orderedBuffer.empty());
        require(channelFreeReceiveSlots(srv.channels[0]) == 8192 - 5);
    }

    // ---- the decoder rejects hostile bytes ----
    {
        Pair     p;
        MonoTime now = connectPair(p, cappedConfig(64), MonoTime{ 0 });
        (void)now;
        Connection& cli = p.client.connections.at(p.sp);

        const PacketHeader h = freshWindowHeader(cli);   // framing is judged before freshness, so one header serves
        const std::uint8_t tooMany[]    = { maxChannelCount + 1 };
        const std::uint8_t shortBuf[]   = { 1, 0, 0 };
        const std::uint8_t longBuf[]    = { 1, 0, 0, 5, 9 };
        const std::uint8_t badChannel[] = { 1, 7, 0, 5 };

        const bool rejEmpty   = applyWindowUpdate(cli, h, ByteSpan{});
        const bool rejCount   = applyWindowUpdate(cli, h, ByteSpan(tooMany, sizeof tooMany));
        const bool rejShort   = applyWindowUpdate(cli, h, ByteSpan(shortBuf, sizeof shortBuf));
        const bool rejLong    = applyWindowUpdate(cli, h, ByteSpan(longBuf, sizeof longBuf));
        const bool rejChannel = applyWindowUpdate(cli, h, ByteSpan(badChannel, sizeof badChannel));
        require(!rejEmpty);     // empty
        require(!rejCount);     // count past the channel max
        require(!rejShort);     // count 1 needs 4 bytes
        require(!rejLong);      // trailing byte: not what the encoder emits
        require(!rejChannel);   // channel 7, only 1 configured

        // A rejected update must leave credit exactly as it was: a two-entry update whose SECOND entry
        // names a channel we do not have must not write the first before returning false, which would
        // desync the channels it reached against the ones it did not.
        const std::uint16_t before    = cli.peerCredit[0];
        const std::uint8_t  halfBad[] = { 2, 0, 0x00, 0x05, 7, 0x00, 0x09 };
        const bool          rejHalf   = applyWindowUpdate(cli, h, ByteSpan(halfBad, sizeof halfBad));
        require(!rejHalf);
        require(cli.peerCredit[0] == before);   // untouched, not 5

        const std::uint16_t was     = cli.peerCredit[0];
        const std::uint8_t  good[]  = { 1, 0, 0x01, 0x2C };                        // channel 0 <- 300
        const bool          applied = applyWindowUpdate(cli, h, ByteSpan(good, sizeof good));
        require(applied);
        require(cli.peerCredit[0] == 300);
        require(was != 300);

        // Credit is absolute, so a REORDERED update must not overwrite a newer one. UDP delivering an
        // older "0 free" behind a newer "300 free" would otherwise shut the window with the receiver
        // already unrestricted and silent -- a permanent stall.
        const std::uint8_t stale[]   = { 1, 0, 0x00, 0x00 };
        const bool         rejStale  = applyWindowUpdate(cli, windowHeader(static_cast<std::uint16_t>(h.sequence.value - 1)),
                                                         ByteSpan(stale, sizeof stale));
        require(!rejStale);
        require(cli.peerCredit[0] == 300);
        const std::uint8_t fresher[] = { 1, 0, 0x00, 0x07 };
        const bool         appliedNewer = applyWindowUpdate(cli, windowHeader(static_cast<std::uint16_t>(h.sequence.value + 1)),
                                                            ByteSpan(fresher, sizeof fresher));
        require(appliedNewer);
        require(cli.peerCredit[0] == 7);    // a strictly newer sequence still lands
    }

    std::printf("flowcontrol_test: all assertions passed\n");
    return 0;
}
