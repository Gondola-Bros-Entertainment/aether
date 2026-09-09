#include "check.hpp"
// Integration and codec regression tests. Separate functions keep the fixtures for all
// scenarios from accumulating in a single debug-build stack frame.
#include "aether/bitserialize.hpp"
#include "aether/channel.hpp"
#include "aether/clocksync.hpp"
#include "aether/congestion.hpp"
#include "aether/config.hpp"
#include "aether/connection.hpp"
#include "aether/crypto.hpp"
#include "aether/delta.hpp"
#include "aether/fragment.hpp"
#include "aether/interest.hpp"
#include "aether/interpolation.hpp"
#include "aether/net.hpp"
#include "aether/packet.hpp"
#include "aether/peer.hpp"
#include "aether/priority.hpp"
#include "aether/random.hpp"
#include "aether/reflect.hpp"
#include "aether/reliability.hpp"
#include "aether/rendezvous.hpp"
#include "aether/replication.hpp"
#include "aether/security.hpp"
#include "aether/serialize.hpp"
#include "aether/socket.hpp"
#include "aether/stats.hpp"
#include "aether/testnet.hpp"
#include "aether/types.hpp"
#include "aether/util.hpp"
#include "aether/x25519.hpp"

#include <array>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <thread>

struct PlayerState {
    float               x{}, y{};
    std::uint8_t        health{};
    aether::SequenceNum seq{};
};

struct Vec3   { float x, y, z; };
struct Entity { Vec3 pos; std::uint32_t id; std::uint8_t hp; aether::ChannelId ch; };

namespace {

void testFoundation() {
    const PlayerState original{ 1.5f, -2.25f, 200, aether::SequenceNum{65535} };

    std::uint8_t buf[64];
    aether::Writer writer{ buf, sizeof buf, 0, true };
    write(writer, original.x);
    write(writer, original.y);
    write(writer, original.health);
    write(writer, original.seq.value);
    assert(writer.ok);

    aether::Reader reader{ buf, writer.pos, 0 };
    const auto readX      = aether::read<float>(reader);
    const auto readY      = aether::read<float>(reader);
    const auto readHealth = aether::read<std::uint8_t>(reader);
    const auto readSeq    = aether::read<std::uint16_t>(reader);
    assert(readX && readY && readHealth && readSeq);
    const PlayerState restored{ *readX, *readY, *readHealth, aether::SequenceNum{*readSeq} };

    assert(restored.x == original.x && restored.y == original.y
        && restored.health == original.health && restored.seq == original.seq);

    // large struct past the old 12-field cap: tieFields now reaches 32, so this instantiates
    // the highest decomposition case (the pre-raise code static_assert-failed at 13 fields).
    {
        struct Big32 {
            std::int32_t v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15,
                         v16,v17,v18,v19,v20,v21,v22,v23,v24,v25,v26,v27,v28,v29,v30,v31;
        };
        static_assert(aether::fieldCount<Big32>() == 32, "tieFields should reach 32 fields");
        Big32 big{ 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
                   16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,-31 };
        std::uint8_t bbuf[256];
        aether::Writer bw{ bbuf, sizeof bbuf, 0, true };
        aether::serialize(bw, big);
        assert(bw.ok);
        aether::Reader br{ bbuf, bw.pos, 0 };
        const auto rt = aether::deserialize<Big32>(br);
        assert(rt && aether::fieldEqual(*rt, big));

        Big32 moved = big; moved.v0 = 1000; moved.v31 = -9999;        // change first + last field
        aether::Writer dw{ bbuf, sizeof bbuf, 0, true };
        aether::deltaPack(dw, big, moved);
        assert(dw.ok);
        aether::Reader dr{ bbuf, dw.pos, 0 };
        const auto back = aether::deltaUnpack(dr, big);
        assert(back && aether::fieldEqual(*back, moved));
    }

    // wraparound: 0 is newer than 65535, never the reverse
    assert(aether::newer(aether::SequenceNum{0}, aether::SequenceNum{65535}));
    assert(!aether::newer(aether::SequenceNum{65535}, aether::SequenceNum{0}));

    std::printf("aether roundtrip OK: x=%.2f y=%.2f hp=%u seq=%u (%zu bytes)\n",
                static_cast<double>(restored.x), static_cast<double>(restored.y),
                static_cast<unsigned>(restored.health), static_cast<unsigned>(restored.seq.value), writer.pos);
}

void testPacketHeader() {
    const aether::PacketHeader h{ aether::PacketType::Payload, aether::SequenceNum{40000},
                                  aether::SequenceNum{39999}, 0xDEADBEEFu };
    std::uint8_t pbuf[aether::packetHeaderBytes];
    aether::Writer pw{ pbuf, sizeof pbuf, 0, true };
    aether::writeHeader(pw, h);
    assert(pw.ok && pw.pos == aether::packetHeaderBytes);

    aether::Reader pr{ pbuf, pw.pos, 0 };
    const auto got = aether::readHeader(pr);
    assert(got);
    assert(got->type == h.type && got->sequence == h.sequence &&
           got->ack == h.ack && got->ackBits == h.ackBits);
    std::printf("aether packet header OK: type=%u seq=%u ack=%u bits=%08x (%zu bytes)\n",
                static_cast<unsigned>(got->type), got->sequence.value, got->ack.value,
                got->ackBits, pw.pos);
}

void testNestedSerialization() {
    const Entity ent{ { 1.0f, 2.0f, 3.0f }, 777, 100, aether::ChannelId{5} };
    std::uint8_t gbuf[64];
    aether::Writer gw{ gbuf, sizeof gbuf, 0, true };
    aether::serialize(gw, ent);
    assert(gw.ok);

    aether::Reader gr{ gbuf, gw.pos, 0 };
    const auto got = aether::deserialize<Entity>(gr);
    assert(got);
    assert(got->pos.x == ent.pos.x && got->pos.z == ent.pos.z &&
           got->id == ent.id && got->hp == ent.hp && got->ch == ent.ch);
    std::printf("aether generic serialize OK: nested Entity, %zu bytes, zero boilerplate\n", gw.pos);
}

void testMemcpyWireLayout() {
    struct Packed { std::uint32_t a; std::uint16_t b; std::uint8_t c, d; float e; };   // 12 bytes, no padding
    static_assert(sizeof(Packed) == aether::serializedSize<Packed>(), "Packed must have no padding");
    const Packed p{ 0x11223344u, 0x5566, 0x77, 0x88, 1.5f };
    std::uint8_t fast[32], slow[32];
    aether::Writer wf{ fast, sizeof fast, 0, true }; aether::serialize(wf, p);   // memcpy path on LE
    aether::Writer ws{ slow, sizeof slow, 0, true }; aether::writeAny(ws, p);    // portable byte-wise
    assert(wf.ok && wf.pos == ws.pos && std::memcmp(fast, slow, wf.pos) == 0);
    aether::Reader rp{ fast, wf.pos, 0 };
    const auto back = aether::deserialize<Packed>(rp);
    assert(back && back->a == p.a && back->b == p.b && back->c == p.c && back->d == p.d && back->e == p.e);
    std::printf("aether memcpy-fastpath OK: %zu-byte struct, memcpy wire == byte-wise wire, round-trips\n", wf.pos);
}

void testUdpLoopback() {
    auto sock = aether::openUdp(aether::addrLocalhost(0));   // ephemeral port
    assert(sock);
    const aether::Address self = aether::localAddr(*sock);
    const std::uint8_t msg[] = { 0xAB, 0xCD, 0xEF };
    const int sent = aether::sendTo(*sock, msg, self);
    assert(sent == 3);

    std::uint8_t rbuf[16];
    aether::Address from{};
    int got = -1;   // -1 == no data yet (poll again); >= 0 == a datagram of that many bytes
    for (int i = 0; i < 10000 && got < 0; ++i) got = aether::recvFrom(*sock, rbuf, from);
    assert(got == 3 && rbuf[0] == 0xAB && rbuf[1] == 0xCD && rbuf[2] == 0xEF);
    std::printf("aether socket loopback OK: sent %d, recv %d on 127.0.0.1:%u\n",
                sent, got, aether::addrPort(self));
    aether::closeSocket(*sock);
}

void testPacketAcknowledgements() {
    aether::ReliableEndpoint ep{};
    const aether::ChannelId ch{ 0 };
    for (std::uint16_t i = 0; i < 3; ++i) {
        const aether::SequenceNum s{ i };
        aether::onPacketSent(ep, s, aether::MonoTime{ 0 }, ch, s, 100);
    }
    assert(aether::packetsInFlight(ep) == 3);

    aether::ReliableEndpoint peer{};
    const aether::SequenceNum recv[] = { aether::SequenceNum{ 0 }, aether::SequenceNum{ 1 }, aether::SequenceNum{ 2 } };
    aether::onPacketsReceived(peer, recv, 3);
    const auto [ackSeq, ackBits] = aether::getAckInfo(peer);
    assert(ackSeq == aether::SequenceNum{ 2 });

    const auto res = aether::processAcks(ep, ackSeq, ackBits, aether::MonoTime{ 50ull * 1000000 });
    assert(res.acked.size() == 3);
    assert(aether::packetsInFlight(ep) == 0);
    assert(ep.srtt > 49.0 && ep.srtt < 51.0);
    std::printf("aether reliability OK: 3 sent, %zu acked, inflight=%d, srtt=%.1fms rto=%.1fms\n",
                res.acked.size(), aether::packetsInFlight(ep), ep.srtt, ep.rto);
}

void testLossAccounting() {
    aether::ReliableEndpoint ep{};
    const aether::ChannelId ch{ 0 };
    for (std::uint16_t s = 0; s < 6; ++s)
        aether::onPacketSent(ep, aether::SequenceNum{ s }, aether::MonoTime{ 0 }, ch, aether::SequenceNum{ s }, 100);

    aether::ReliableEndpoint peer{};   // received all but seq 3 -> seq 3 is NACKed by the bitfield
    const aether::SequenceNum got[] = { aether::SequenceNum{ 0 }, aether::SequenceNum{ 1 }, aether::SequenceNum{ 2 },
                                        aether::SequenceNum{ 4 }, aether::SequenceNum{ 5 } };
    aether::onPacketsReceived(peer, got, 5);
    const auto [ackSeq, ackBits] = aether::getAckInfo(peer);

    aether::AckResult last;
    for (int i = 0; i < aether::fastRetransmitThreshold; ++i)
        last = aether::processAcks(ep, ackSeq, ackBits, aether::MonoTime{ 60ull * 1000000 });
    assert(!last.fastRetransmit.empty());           // seq 0 declared lost
    assert(ep.totalLost > 0);                        // the (previously dead) counter moves
    assert(aether::packetLossFraction(ep) > 0.0);     // ...and the metric is no longer pinned at 0
    std::printf("aether loss-metric OK: a NACKed packet registers as loss (totalLost=%llu, loss=%.0f%%)\n",
                static_cast<unsigned long long>(ep.totalLost), aether::packetLossFraction(ep) * 100.0);
}

void testReliableSendPipelining() {
    aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
    for (std::uint8_t i = 0; i < 4; ++i) {
        const auto r = aether::channelSend(ch, aether::Bytes{ i }, aether::MonoTime{ 0 });
        assert(r.error == aether::ChannelError::None);
    }
    int emitted = 0;
    for (;;) {
        const auto m = aether::peekOutgoingMessage(ch);
        if (!m) break;
        aether::commitOutgoingMessage(ch, m->sequence, aether::MonoTime{ 0 });
        ++emitted;
    }
    assert(emitted == 4);   // all four in flight at once (stop-and-wait would have emitted 1)
    std::printf("aether channel-pipeline OK: %d reliable messages in flight in one drain (was 1)\n", emitted);
}

void testRetransmitCommit() {
    aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
    const auto sr = aether::channelSend(ch, aether::Bytes{ 1, 2, 3 }, aether::MonoTime{ 0 });
    aether::commitOutgoingMessage(ch, sr.seq, aether::MonoTime{ 0 });   // in flight: retryCount 1, sendTime 0
    const aether::MonoTime later{ 200ull * 1000000 };          // 200ms > 100ms RTO
    const auto cands = aether::getRetransmitMessages(ch, later, 100.0);
    assert(cands.size() == 1);                                                                  // RTO elapsed -> candidate
    assert(ch.sendBuffer.at(sr.seq).retryCount == 1 && ch.sendBuffer.at(sr.seq).sendTime.ns == 0);   // peek did NOT mutate (was the bug)
    aether::commitRetransmit(ch, sr.seq, later);
    assert(ch.sendBuffer.at(sr.seq).retryCount == 2 && ch.sendBuffer.at(sr.seq).sendTime.ns == later.ns);   // state advances only on commit
    std::printf("aether retransmit-commit OK: candidate peeked without burning a retry; commit advances state\n");
}

void testAckWindowBoundary() {
    aether::ReliableEndpoint ep{};
    const aether::SequenceNum a{ 100 };
    aether::onPacketsReceived(ep, &a, 1);                      // remoteSeq = 100
    const aether::SequenceNum b{ static_cast<std::uint16_t>(132) };
    aether::onPacketsReceived(ep, &b, 1);                      // advance by exactly 32
    const auto [ackSeq, ackBits] = aether::getAckInfo(ep);
    assert(ackSeq.value == 132);
    assert((ackBits & (std::uint64_t(1) << 31)) != 0);         // seq 100 (now 32 back) still acked at bit 31
    std::printf("aether ack-bitfield OK: +32 advance keeps the prior ack at bit 31 (was dropped)\n");
}

void testNonceReplayWindow() {
    aether::ReplayWindow w;   // hoist each call out of assert() -- the side effect must run even under NDEBUG
    const bool r1 = aether::replayAccept(w, 5);   assert(r1);    // first seen
    const bool r2 = aether::replayAccept(w, 7);   assert(r2);    // forward
    const bool r3 = aether::replayAccept(w, 6);   assert(r3);    // reordered but unseen -> accepted (strict-increasing dropped this)
    const bool r4 = aether::replayAccept(w, 6);   assert(!r4);   // replay -> rejected
    const bool r5 = aether::replayAccept(w, 7);   assert(!r5);   // replay -> rejected
    const bool r6 = aether::replayAccept(w, 200); assert(r6);    // big forward jump
    const bool r7 = aether::replayAccept(w, 5);   assert(!r7);   // now far outside the window -> rejected
    std::printf("aether replay-window OK: reorder accepted, replays + stale rejected\n");
}

void testSendBackpressure() {
    aether::ChannelConfig cc = aether::reliableOrderedChannel();
    cc.messageBufferSize = 3;
    cc.blockOnFull       = false;   // even so, a RELIABLE channel must not drop
    aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cc);
    for (std::uint8_t i = 0; i < 3; ++i) {
        const auto sr = aether::channelSend(ch, aether::Bytes{ i }, aether::MonoTime{ 0 });
        assert(sr.error == aether::ChannelError::None);
    }
    const auto over = aether::channelSend(ch, aether::Bytes{ 99 }, aether::MonoTime{ 0 });
    assert(over.error == aether::ChannelError::BufferFull);                                    // backpressure...
    assert(ch.sendBuffer.size() == 3 && ch.sendBuffer.count(aether::SequenceNum{ 0 }) == 1);   // ...oldest still buffered
    std::printf("aether channel-backpressure OK: full reliable channel returns BufferFull (no silent drop)\n");
}

void testAssemblyCountLimit() {
    aether::FragmentAssembler a = aether::newFragmentAssembler(5000.0, 1 << 20, 8);   // cap 8 concurrent buffers
    const std::uint8_t f0[7] = { 0, 0, 0, 0, 0, 0, 0 };   // msgId 0, index 0, count 0 -> malformed
    const auto bad0 = aether::processFragment(a, f0, sizeof f0, aether::MonoTime{ 0 });
    assert(!bad0);
    assert(a.buffers.empty());
    for (std::uint32_t id = 1; id <= 100; ++id) {
        std::uint8_t f[8];
        aether::writeFragmentHeader(f, aether::FragmentHeader{ static_cast<aether::MessageId>(id), 0, 2 });   // 1 of 2, never completes
        f[6] = 0xAB; f[7] = 0xCD;
        aether::processFragment(a, f, sizeof f, aether::MonoTime{ 0 });
    }
    assert(static_cast<int>(a.buffers.size()) <= 8);   // bounded, not 100
    std::printf("aether fragment-cap OK: concurrent buffers bounded to %d (was unbounded), count==0 rejected\n",
                static_cast<int>(a.buffers.size()));
}

void testAssemblyByteLimit() {
    aether::FragmentAssembler a = aether::newFragmentAssembler(5000.0, 100, 256);   // 100-byte cap
    std::vector<std::uint8_t> big(static_cast<std::size_t>(aether::fragmentHeaderSize) + 200);   // one fragment > cap
    aether::writeFragmentHeader(big.data(), aether::FragmentHeader{ aether::MessageId{ 1 }, 0, 2 });
    const auto rej = aether::processFragment(a, big.data(), big.size(), aether::MonoTime{ 0 });
    assert(!rej && a.currentSize == 0 && a.buffers.empty());   // oversized fragment rejected, nothing buffered
    for (std::uint32_t id = 1; id <= 50; ++id) {               // flood smaller never-completing fragments
        std::uint8_t f[aether::fragmentHeaderSize + 40];
        aether::writeFragmentHeader(f, aether::FragmentHeader{ static_cast<aether::MessageId>(id), 0, 2 });
        aether::processFragment(a, f, sizeof f, aether::MonoTime{ 0 });
    }
    assert(a.currentSize <= 100);   // buffered total stays within the cap (was overshootable by a whole fragment)
    std::printf("aether fragment-bytecap OK: oversized rejected, buffered total <= cap (%zu bytes)\n", a.currentSize);
}

void testMonotonicTimeSaturation() {
    assert(aether::elapsedMs(aether::MonoTime{ 1000 }, aether::MonoTime{ 500 }) == 0.0);   // reversed -> 0, not huge
    assert(aether::elapsedMs(aether::MonoTime{ 500 }, aether::MonoTime{ 1000 }) > 0.0);     // forward still works
    std::printf("aether elapsedMs-saturate OK: reversed time -> 0 (no unsigned-wrap deadline storm)\n");
}

void testConfigurationValidation() {
    const aether::NetworkConfig c;   // defaults are valid
    assert(!aether::validateConfig(c));
    aether::NetworkConfig c1 = c; c1.maxFragments = 0;
    assert(aether::validateConfig(c1) == aether::ConfigError::InvalidMaxFragments);
    aether::NetworkConfig c2 = c; c2.maxReassemblyBufferSize = 0;
    assert(aether::validateConfig(c2) == aether::ConfigError::InvalidReassemblyBufferSize);
    aether::NetworkConfig c3 = c; c3.maxPending = 0;
    assert(aether::validateConfig(c3) == aether::ConfigError::InvalidMaxPending);
    aether::NetworkConfig c4 = c; c4.maxInFlight = 0;
    assert(aether::validateConfig(c4) == aether::ConfigError::InvalidMaxInFlight);
    aether::NetworkConfig c5 = c; c5.maxSequenceDistance = 0;
    assert(aether::validateConfig(c5) == aether::ConfigError::InvalidMaxSequenceDistance);
    aether::NetworkConfig c6 = c; c6.fragmentTimeoutMs = 0.0;
    assert(aether::validateConfig(c6) == aether::ConfigError::InvalidFragmentTimeout);
    aether::NetworkConfig c7 = c; c7.connectionRequestMaxRetries = -1;
    assert(aether::validateConfig(c7) == aether::ConfigError::InvalidConnectionRequestRetries);
    // maxInFlight past the sent ring's physical capacity is a lie the ring cannot honor (records
    // would displace a full cycle early rather than track more packets) -- rejected, not degraded.
    aether::NetworkConfig c8 = c; c8.maxInFlight = aether::sentBufferSize + 1;
    assert(aether::validateConfig(c8) == aether::ConfigError::InvalidMaxInFlight);
    aether::NetworkConfig c9 = c; c9.maxInFlight = aether::sentBufferSize;   // exactly the ring is fine
    assert(!aether::validateConfig(c9));
    std::printf("aether config-bounds OK: zero fragment/reassembly/pending/in-flight/seq-distance caps rejected\n");
}

void testOversizedMessageFailure() {
    aether::NetworkConfig cfg;                                     // NOT validated, deliberately:
    cfg.defaultChannelConfig.maxMessageSize = 400000;              // past the ~295KB fragmentable ceiling
    aether::Connection conn = aether::newConnection(cfg, 1, aether::MonoTime{ 0 });
    aether::markConnected(conn, aether::MonoTime{ 0 });

    const auto sendErr = aether::sendMessage(conn, aether::ChannelId{ 0 }, aether::Bytes(400000, 0x42), aether::MonoTime{ 0 });
    assert(!sendErr);
    aether::updateConnectedPure(conn, aether::MonoTime{ 1000000 });
    const aether::Channel& ch = conn.channels[0];
    assert(ch.totalDropped == 1);
    assert(ch.failure == aether::ChannelFailure::MessageTooLarge && ch.sendBuffer.size() == 1);
    aether::updateConnectedPure(conn, aether::MonoTime{ 400000000 });   // past the RTO: nothing re-qualifies
    assert(ch.totalDropped == 1 && conn.pendingWires.empty());
    std::printf("aether oversized-backstop OK: an unfragmentable reliable message fails delivery explicitly\n");
}

void testConfigurationPropagation() {
    aether::NetworkConfig cfg;
    cfg.maxInFlight         = 8;
    cfg.maxSequenceDistance = 1000;
    cfg.fragmentTimeoutMs   = 250.0;
    cfg.defaultChannelConfig.maxMessageSize = 4096;
    assert(!aether::validateConfig(cfg));

    const aether::Connection conn = aether::newConnection(cfg, 1, aether::MonoTime{ 0 });
    assert(conn.reliability.maxInFlight == 8);              // reached the reliability endpoint...
    assert(conn.reliability.maxSeqDistance == 1000);

    aether::Connection reset = conn;                         // ...and survives a reset (was reverting to defaults)
    aether::resetConnection(reset);
    assert(reset.reliability.maxInFlight == 8 && reset.reliability.maxSeqDistance == 1000);

    // maxInFlight really bounds the sent ring: the 9th packet evicts the oldest.
    aether::Connection ev = aether::newConnection(cfg, 2, aether::MonoTime{ 0 });
    const aether::ChannelId ch0{ 0 };
    for (std::uint16_t s = 0; s < 12; ++s)
        aether::onPacketSent(ev.reliability, aether::SequenceNum{ s }, aether::MonoTime{ s }, ch0, aether::SequenceNum{ s }, 10);
    assert(aether::packetsInFlight(ev.reliability) == 8 && ev.reliability.packetsEvicted == 4);

    // fragmentTimeoutMs reaches the reassembler the peer builds per source.
    const aether::Address addrS = aether::addrLocalhost(7401);
    aether::NetPeer S = aether::newPeerState(addrS, cfg, aether::MonoTime{ 0 });
    const aether::PeerId from{ aether::addrLocalhost(7402) };
    auto source = aether::newConnection(cfg, 1, aether::MonoTime{0});
    aether::markConnected(source, aether::MonoTime{0});
    S.connections.emplace(from, std::move(source));
    aether::Bytes frag(aether::fragmentHeaderSize + aether::maxFragmentChunk(cfg));
    aether::writeFragmentHeader(frag.data(), aether::FragmentHeader{ aether::MessageId{ 1 }, 0, 2 });
    aether::test::require(aether::handleFragment(S, from, aether::ChannelId{ 0 }, frag, aether::MonoTime{ 0 }));
    assert(S.fragmentAssemblers.at(from).timeoutMs == 250.0);
    assert(S.fragmentAssemblers.at(from).maxBufferSize == cfg.maxReassemblyBufferSize);
    std::printf("aether config-wiring OK: maxInFlight + maxSequenceDistance + fragmentTimeoutMs reach their objects\n");
}

void testFragmentRoundtrip() {
    aether::Bytes msg(2500);
    for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<std::uint8_t>(i * 31 + 7);
    const auto fr = aether::fragmentMessage(aether::MessageId{ 42 }, msg.data(), msg.size(), 1024);
    assert(!fr.tooMany && fr.fragments.size() == 3);

    aether::FragmentAssembler assembler = aether::newFragmentAssembler(5000.0, 1 << 20, 256);
    std::optional<aether::Bytes> done;
    for (const auto& f : fr.fragments) {
        auto out = aether::processFragment(assembler, f.data(), f.size(), aether::MonoTime{ 0 });
        if (out) done = out;
    }
    assert(done && *done == msg);
    std::printf("aether fragment OK: 2500 bytes -> %zu fragments -> reassembled exact\n", fr.fragments.size());
}

void testOrderedReceive() {
    aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
    const aether::Bytes m0{ 1 }, m1{ 2 }, m2{ 3 };
    aether::onMessageReceived(ch, aether::SequenceNum{ 0 }, m0, aether::MonoTime{ 0 });
    aether::onMessageReceived(ch, aether::SequenceNum{ 2 }, m2, aether::MonoTime{ 0 });   // arrives early
    aether::onMessageReceived(ch, aether::SequenceNum{ 1 }, m1, aether::MonoTime{ 0 });   // fills the gap
    const auto got = aether::channelReceive(ch);
    assert(got.size() == 3 && got[0] == m0 && got[1] == m1 && got[2] == m2);
    assert(ch.orderedExpected == aether::SequenceNum{ 3 });   // the reorder window advanced past all three
    std::printf("aether channel OK: out-of-order [0,2,1] -> in-order [0,1,2]\n");
}

void testBitSerialization() {
    struct Move {
        aether::Ranged<int, 0, 1023>       x;        // 10 bits
        aether::Ranged<int, 0, 1023>       y;        // 10 bits
        aether::Quantized<-1.0f, 1.0f, 12> aimYaw;   // 12 bits
        aether::Ranged<int, 0, 7>          button;   //  3 bits
        bool                               firing{};   //  1 bit
    };
    const Move in{ { 512 }, { 1000 }, { 0.5f }, { 5 }, true };   // 36 bits -> 5 bytes

    std::uint8_t bb[16];
    aether::BitWriter bw{ bb, sizeof bb };
    const std::size_t packed = aether::packBits(bw, in);
    assert(bw.ok);

    aether::BitReader br{ bb, packed };
    const auto out = aether::unpackBits<Move>(br);
    assert(out);
    assert(out->x.value == 512 && out->y.value == 1000 && out->button.value == 5 && out->firing);
    const float dy = out->aimYaw.value - in.aimYaw.value;
    assert(dy > -0.001f && dy < 0.001f);

    // same logical packet on the byte-aligned generic path, for comparison
    struct MovePlain { std::uint32_t x, y; float aimYaw; std::uint8_t button, firing; };
    std::uint8_t pb[32];
    aether::Writer pw{ pb, sizeof pb, 0, true };
    aether::serialize(pw, MovePlain{ 512, 1000, 0.5f, 5, 1 });
    std::printf("aether bitpack OK: bit-packed %zu bytes vs byte-path %zu bytes, round-trip exact\n",
                packed, pw.pos);
}

void testFieldDeltas() {
    struct Snapshot { int hp; int x; int y; float angle; std::uint16_t mana; bool alive; };
    const Snapshot prev{ 100, 10, 20, 1.5f, 50, true };
    Snapshot curr = prev;
    curr.x = 11;                              // one field changes this tick

    std::uint8_t fb[64];
    aether::Writer fw{ fb, sizeof fb, 0, true };
    aether::pack(fw, curr);                   // full snapshot

    std::uint8_t db[64];
    aether::Writer dw{ db, sizeof db, 0, true };
    aether::deltaPack(dw, prev, curr);        // delta against the baseline

    aether::Reader dr{ db, dw.pos, 0 };
    const auto back = aether::deltaUnpack(dr, prev);
    assert(back && back->x == 11 && back->hp == 100 && back->mana == 50 && back->alive);
    const float da = back->angle - curr.angle;
    assert(da > -0.001f && da < 0.001f);

    std::printf("aether magic OK: plain struct, full snapshot %zu bytes vs delta(1 field) %zu bytes, zero annotations\n",
                fw.pos, dw.pos);
}

void testVectorDecodeBounds() {
    struct Big     { std::uint64_t a, b, c, d, e, f, g, h; };
    struct WithVec { std::vector<Big> items; };
    WithVec orig; orig.items = { Big{ 1,2,3,4,5,6,7,8 }, Big{ 9,8,7,6,5,4,3,2 } };
    std::uint8_t vb[256];
    aether::Writer vw{ vb, sizeof vb, 0, true };
    aether::pack(vw, orig);
    assert(vw.ok);
    aether::Reader vr{ vb, vw.pos, 0 };
    const auto rt = aether::unpack<WithVec>(vr);
    assert(rt && rt->items.size() == 2 && rt->items[1].a == 9 && rt->items[1].h == 2);

    std::uint8_t hostile[8];
    aether::Writer hw{ hostile, sizeof hostile, 0, true };
    aether::writeVarU(hw, 5000000ull);       // claim 5M 64-byte elements in a 3-byte buffer
    aether::Reader hr{ hostile, hw.pos, 0 };
    assert(!aether::unpack<WithVec>(hr));    // count > remaining bytes -> rejected, no amplified alloc
    std::printf("aether vector-decode hardening OK: legit roundtrips, hostile count rejected\n");
}

void testBoolSerialization() {
    struct Flags  { bool a, b, c, d; };            // 4 bytes, would otherwise be memcpy-eligible
    struct NoBool { std::uint8_t a, b, c, d; };    // 4 bytes, stays on the fast path
    static_assert(!aether::canMemcpySerialize<Flags>(), "bool struct must avoid the memcpy path");
    static_assert(aether::canMemcpySerialize<NoBool>(), "bool-free POD keeps the memcpy fast path");
    const Flags f{ true, false, true, false };
    std::uint8_t b[16];
    aether::Writer w{ b, sizeof b, 0, true };
    aether::serialize(w, f);
    aether::Reader r{ b, w.pos, 0 };
    const auto back = aether::deserialize<Flags>(r);
    assert(back && back->a && !back->b && back->c && !back->d);
    std::printf("aether bool-memcpy-exclusion OK: bool struct uses the portable path, round-trips\n");
}

void testFloatDeltaBits() {
    struct F { float v; };
    const F prev{ +0.0f };
    F curr{ -0.0f };
    std::uint8_t db[16];
    aether::Writer dw{ db, sizeof db, 0, true };
    aether::deltaPack(dw, prev, curr);
    aether::Reader dr{ db, dw.pos, 0 };
    const auto back = aether::deltaUnpack(dr, prev);
    assert(back && std::signbit(back->v));   // -0.0 carried through (mask bit set), not dropped
    std::printf("aether delta bit-exact OK: +0.0 -> -0.0 sign flip transmitted\n");
}

void testAeadVector() {
    std::uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = std::uint8_t(0x80 + i);
    const std::uint8_t nonce[12] = { 0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47 };
    const std::uint8_t aad[12]   = { 0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7 };
    const char* ptext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const std::size_t ptLen = std::strlen(ptext);
    const std::uint8_t expectTag[16] = { 0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91 };
    const std::uint8_t expectCt0[4]  = { 0xd3,0x1a,0x8d,0x34 };

    std::vector<std::uint8_t> ct(ptLen);
    std::uint8_t tag[16];
    aether::aeadSeal(key, nonce, aad, sizeof aad, reinterpret_cast<const std::uint8_t*>(ptext), ptLen, ct.data(), tag);
    assert(std::memcmp(tag, expectTag, 16) == 0);
    assert(std::memcmp(ct.data(), expectCt0, 4) == 0);

    auto opened = aether::aeadOpen(key, nonce, aad, sizeof aad, ct.data(), ct.size(), tag);
    assert(opened && opened->size() == ptLen && std::memcmp(opened->data(), ptext, ptLen) == 0);
    std::printf("aether crypto OK: RFC 8439 AEAD vector (tag + ciphertext match), %zu-byte msg\n", ptLen);
}

void testHChaChaVector() {
    std::uint8_t hkey[32];
    for (int i = 0; i < 32; ++i) hkey[i] = std::uint8_t(i);
    const std::uint8_t hin[16] = { 0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x4a, 0x00,0x00,0x00,0x00, 0x31,0x41,0x59,0x27 };
    const std::uint8_t expectSub[32] = {
        0x82,0x41,0x3b,0x42, 0x27,0xb2,0x7b,0xfe, 0xd3,0x0e,0x42,0x50, 0x8a,0x87,0x7d,0x73,
        0xa0,0xf9,0xe4,0xd5, 0x8a,0x74,0xa8,0x53, 0xc1,0x2e,0xc4,0x13, 0x26,0xd3,0xec,0xdc };
    std::uint8_t sub[32];
    aether::detail::hchacha20(hkey, hin, sub);
    assert(std::memcmp(sub, expectSub, 32) == 0);
    std::printf("aether crypto OK: HChaCha20 subkey vector matches\n");
}

void testDirectionalKeys() {
    aether::X25519Key shared{};
    for (int i = 0; i < 32; ++i) shared[static_cast<std::size_t>(i)] = std::uint8_t(i * 5 + 3);
    const auto k1 = aether::deriveDirectionalKeys(shared, 0x1122334455667788ull);
    const auto k2 = aether::deriveDirectionalKeys(shared, 0x1122334455667788ull);
    const auto k3 = aether::deriveDirectionalKeys(shared, 0x99aabbccddeeff00ull);
    assert(k1.clientToServer != k1.serverToClient);                            // directions differ (C1)
    assert(k1.clientToServer == k2.clientToServer);                            // deterministic
    assert(k3.clientToServer != k1.clientToServer && k3.serverToClient != k1.serverToClient);   // salt re-keys (C2)
    std::printf("aether crypto OK: directional KDF (c2s != s2c, fresh salt re-keys)\n");
}

void testPacketEncryption() {
    aether::EncryptionKey key{};
    for (int i = 0; i < 32; ++i) key[i] = std::uint8_t(i * 7 + 1);
    const std::uint8_t payload[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const std::uint8_t aad[3] = { 0xAA, 0xBB, 0xCC };   // stands in for the cleartext packet header
    auto packet = aether::encrypt(key, aether::NonceCounter{ 42 }, 0x12345678u, aad, sizeof aad, payload, sizeof payload);
    auto back = aether::decrypt(key, 0x12345678u, aad, sizeof aad, packet.data(), packet.size());
    assert(back && back->counter.value == 42 && back->plaintext.size() == sizeof payload);
    assert(std::memcmp(back->plaintext.data(), payload, sizeof payload) == 0);
    const std::uint8_t aad2[3] = { 0xAA, 0xBB, 0xCD };   // one AAD bit flipped...
    assert(!aether::decrypt(key, 0x12345678u, aad2, sizeof aad2, packet.data(), packet.size()));   // ...rejected (header authenticated)
    packet[packet.size() - 1] ^= 0x01;   // tamper the tag
    assert(!aether::decrypt(key, 0x12345678u, aad, sizeof aad, packet.data(), packet.size()));
    std::printf("aether crypto OK: packet encrypt/decrypt round-trip + AAD header binding + tamper rejected\n");
}

void testX25519Vectors() {
    const aether::X25519Key scalar = {
        0xa5,0x46,0xe3,0x6b,0xf0,0x52,0x7c,0x9d,0x3b,0x16,0x15,0x4b,0x82,0x46,0x5e,0xdd,
        0x62,0x14,0x4c,0x0a,0xc1,0xfc,0x5a,0x18,0x50,0x6a,0x22,0x44,0xba,0x44,0x9a,0xc4 };
    const aether::X25519Key u = {
        0xe6,0xdb,0x68,0x67,0x58,0x30,0x30,0xdb,0x35,0x94,0xc1,0xa4,0x24,0xb1,0x5f,0x7c,
        0x72,0x66,0x24,0xec,0x26,0xb3,0x35,0x3b,0x10,0xa9,0x03,0xa6,0xd0,0xab,0x1c,0x4c };
    const aether::X25519Key expect = {
        0xc3,0xda,0x55,0x37,0x9d,0xe9,0xc6,0x90,0x8e,0x94,0xea,0x4d,0xf2,0x8d,0x08,0x4f,
        0x32,0xec,0xcf,0x03,0x49,0x1c,0x71,0xf7,0x54,0xb4,0x07,0x55,0x77,0xa2,0x85,0x52 };
    aether::X25519Key out{};
    aether::x25519(out, scalar, u);
    assert(out == expect);

    aether::X25519Key aPriv{}, bPriv{};
    for (int i = 0; i < 32; ++i) {
        aPriv[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(i * 3 + 1);
        bPriv[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(i * 7 + 2);
    }
    aether::X25519Key aPub{}, bPub{}, ss1{}, ss2{};
    aether::x25519Base(aPub, aPriv);
    aether::x25519Base(bPub, bPriv);
    aether::x25519(ss1, aPriv, bPub);
    aether::x25519(ss2, bPriv, aPub);
    assert(ss1 == ss2);
    std::printf("aether x25519 OK: RFC 7748 vector matches + ECDH shared secret agrees\n");
}

void testSystemRandomness() {
    std::array<std::uint8_t, 32> r1{}, r2{};
    aether::secureRandomBytes(r1.data(), r1.size());
    aether::secureRandomBytes(r2.data(), r2.size());
    bool allZero = true;
    for (const auto x : r1) if (x != 0) allZero = false;
    assert(!allZero && r1 != r2);
    std::printf("aether random OK: OS CSPRNG fills + varies\n");
}

void testCongestionAndBatching() {
    aether::CongestionWindow cw = aether::newCongestionWindow(1200);
    const double startCwnd = cw.cwnd;
    aether::cwOnSend(cw, 1200, aether::MonoTime{ 0 });
    assert(cw.bytesInFlight == 1200);
    aether::cwOnAck(cw, 1200);
    assert(cw.bytesInFlight == 0 && cw.cwnd > startCwnd);
    aether::cwOnLoss(cw);
    assert(cw.phase == aether::CongestionPhase::Recovery && cw.cwnd >= aether::minCwndBytes);
    assert(cw.cwnd == cw.ssthresh + 3.0 * 1200);                                       // fast recovery inflates by 3 segments
    aether::cwOnAck(cw, 1200);                                                          // first ack of new data exits recovery
    assert(cw.phase == aether::CongestionPhase::Avoidance && cw.cwnd == cw.ssthresh);   // ...deflating to ssthresh

    const std::vector<aether::Bytes> msgs = { { 1, 2, 3 }, { 4, 5 }, { 6, 7, 8, 9 } };
    aether::Bytes batch;   // hand-frame a coalesced batch ([u8 count][u16 len BE][data]...) and decode it
    batch.push_back(static_cast<std::uint8_t>(msgs.size()));
    for (const auto& m : msgs) {
        batch.push_back(static_cast<std::uint8_t>(m.size() >> 8));
        batch.push_back(static_cast<std::uint8_t>(m.size() & 0xFF));
        batch.insert(batch.end(), m.begin(), m.end());
    }
    const auto un = aether::unbatchMessages(batch);
    assert(un && un->size() == 3 && (*un)[0] == aether::Bytes({ 1, 2, 3 }) && (*un)[2] == aether::Bytes({ 6, 7, 8, 9 }));
    std::printf("aether congestion OK: cwnd ack/loss + unbatch %zu msgs round-trip\n", un->size());
}

void testConfigurationAndQuality() {
    assert(!aether::validateConfig(aether::NetworkConfig{}));
    aether::NetworkConfig bad;
    bad.mtu = aether::minMtu - 1;   // below the smallest MTU any path is required to carry
    assert(aether::validateConfig(bad) == aether::ConfigError::InvalidMtu);
    const auto rejected = aether::openHost(aether::addrLocalhost(0), bad, aether::MonoTime{ 0 });
    assert(!rejected);   // openHost now refuses an invalid config
    assert(aether::assessConnectionQuality(20.0, 0.0)  == aether::ConnectionQuality::Excellent);
    assert(aether::assessConnectionQuality(600.0, 0.0) == aether::ConnectionQuality::Bad);
    std::printf("aether config/stats OK: defaults valid, bad config + quality assessment caught\n");
}

void testConnectionDelivery() {
    const aether::NetworkConfig cfg;
    aether::Connection a = aether::newConnection(cfg, 111, aether::MonoTime{ 0 });
    aether::Connection b = aether::newConnection(cfg, 222, aether::MonoTime{ 0 });
    aether::markConnected(a, aether::MonoTime{ 0 });
    aether::markConnected(b, aether::MonoTime{ 0 });
    assert(aether::isConnected(a) && aether::isConnected(b));

    const aether::Bytes payload = { 0xDE, 0xAD, 0xBE, 0xEF };
    const auto cSendErr = aether::sendMessage(a, aether::ChannelId{ 0 }, payload, aether::MonoTime{ 0 });
    assert(!cSendErr);
    const auto cUpdateErr = aether::updateTick(a, aether::MonoTime{ 1000000 });   // 1ms: flush channel -> queue
    assert(!cUpdateErr);
    const auto outgoing = aether::drainSendQueue(a);
    assert(!outgoing.empty());

    int delivered = 0;
    for (const auto& pkt : outgoing) {
        if (pkt.type != aether::PacketType::Payload || pkt.payload.size() < 3) continue;
        aether::processIncomingAcks(b, pkt.header, aether::MonoTime{ 2000000 });
        aether::recordReceivedPacket(b, pkt.header);
        const auto& w = pkt.payload;
        const auto chan = static_cast<std::uint8_t>(w[0] & 0x07);
        const aether::SequenceNum chSeq{ static_cast<std::uint16_t>((w[1] << 8) | w[2]) };
        const aether::Bytes data(w.begin() + 3, w.end());
        aether::receiveIncomingPayload(b, aether::ChannelId{ chan }, chSeq, data, aether::MonoTime{ 2000000 });
        ++delivered;
    }
    const auto got = aether::receiveMessage(b, aether::ChannelId{ 0 });
    assert(delivered >= 1 && got.size() == 1 && got[0] == payload);
    std::printf("aether connection OK: reliable message a->b across %d payload packet(s)\n", delivered);
}

void testMessageCoalescing() {
    aether::NetworkConfig cfg;
    cfg.channelConfigs = { aether::unreliableChannel() };   // channel 0 unreliable: all messages drain per tick
    aether::Connection a = aether::newConnection(cfg, 111, aether::MonoTime{ 0 });
    aether::Connection b = aether::newConnection(cfg, 222, aether::MonoTime{ 0 });
    aether::markConnected(a, aether::MonoTime{ 0 });
    aether::markConnected(b, aether::MonoTime{ 0 });

    constexpr int N = 6;
    for (int k = 0; k < N; ++k) {
        const aether::Bytes m{ static_cast<std::uint8_t>(k), 0xA0, 0xB0 };
        const auto sendErr = aether::sendMessage(a, aether::ChannelId{ 0 }, m, aether::MonoTime{ 0 });
        assert(!sendErr);
    }
    const auto flushErr = aether::updateTick(a, aether::MonoTime{ 1000000 });   // flush -> coalesce this tick
    assert(!flushErr);
    const auto outgoing = aether::drainSendQueue(a);

    std::size_t batched = 0;
    for (const auto& p : outgoing) if (p.type == aether::PacketType::PayloadBatch) ++batched;
    assert(outgoing.size() < static_cast<std::size_t>(N) && batched >= 1);   // fewer packets, >=1 batch

    const auto deliver = [&](const aether::Bytes& wire) {
        if (wire.size() < 3) return;
        const auto chan = static_cast<std::uint8_t>(wire[0] & 0x07);
        const aether::SequenceNum chSeq{ static_cast<std::uint16_t>((wire[1] << 8) | wire[2]) };
        aether::receiveIncomingPayload(b, aether::ChannelId{ chan }, chSeq,
                                       aether::Bytes(wire.begin() + 3, wire.end()), aether::MonoTime{ 2000000 });
    };
    for (const auto& pkt : outgoing) {
        aether::processIncomingAcks(b, pkt.header, aether::MonoTime{ 2000000 });
        aether::recordReceivedPacket(b, pkt.header);
        if (pkt.type == aether::PacketType::PayloadBatch) {
            const auto wires = aether::unbatchMessages(pkt.payload);
            assert(wires);
            for (const auto& wire : *wires) deliver(wire);
        } else if (pkt.type == aether::PacketType::Payload) {
            deliver(pkt.payload);
        }
    }
    const auto got = aether::receiveMessage(b, aether::ChannelId{ 0 });
    assert(got.size() == static_cast<std::size_t>(N));
    for (const auto& m : got) assert(m.size() == 3 && m[1] == 0xA0 && m[2] == 0xB0);
    std::printf("aether coalescing OK: %d unreliable messages -> %zu packet(s) (%zu batched), all delivered\n",
                N, outgoing.size(), batched);
}

void testClockOffset() {
    aether::ClockSync cs;
    constexpr double trueOffsetMs = 1000.0;   // the remote clock runs 1000ms ahead of ours
    for (int i = 0; i < 20; ++i) {
        const double t0     = static_cast<double>(i) * 100.0;             // local send
        const double rtt    = 40.0 + static_cast<double>(i % 5) * 10.0;  // varying round-trip
        const double t2     = t0 + rtt;                                  // local recv
        const double remote = (t0 + t2) / 2.0 + trueOffsetMs;           // remote clock at the midpoint
        aether::clockSyncObserve(cs, t0, remote, t2);
    }
    assert(cs.hasSample);
    const double err = cs.offsetMs - trueOffsetMs;
    assert(err > -1.0 && err < 1.0);                                     // recovered within 1ms
    const double mapped = aether::localToRemoteMs(cs, 500.0);
    assert(mapped > 1499.0 && mapped < 1501.0);
    std::printf("aether clocksync OK: recovered %.1fms offset from round-trips (best rtt %.1fms)\n",
                cs.offsetMs, cs.bestRttMs);
}

void testReliableDeliveryWithLoss() {
    const aether::NetworkConfig cfg;
    aether::Connection a = aether::newConnection(cfg, 111, aether::MonoTime{ 0 });
    aether::Connection b = aether::newConnection(cfg, 222, aether::MonoTime{ 0 });
    aether::markConnected(a, aether::MonoTime{ 0 });
    aether::markConnected(b, aether::MonoTime{ 0 });

    const aether::Bytes payload = { 0xCA, 0xFE, 0xBA, 0xBE };
    const auto sendErr = aether::sendMessage(a, aether::ChannelId{ 0 }, payload, aether::MonoTime{ 0 });   // channel 0 is reliable
    assert(!sendErr);

    std::uint64_t rng = 1;   // deterministic ~40% loss, so the test is reproducible
    const auto lost = [&] { const auto r = aether::nextRandom(rng); rng = r.state; return aether::randomDouble(r.output) < 0.4; };
    const auto shuttle = [&](aether::Connection& from, aether::Connection& to, aether::MonoTime now) {
        for (const auto& pkt : aether::drainSendQueue(from)) {
            if (lost()) continue;                            // dropped on the wire
            aether::processIncomingAcks(to, pkt.header, now);
            aether::recordReceivedPacket(to, pkt.header);
            if (pkt.type == aether::PacketType::Payload && pkt.payload.size() >= 3) {
                const auto& w = pkt.payload;
                const auto chan = static_cast<std::uint8_t>(w[0] & 0x07);
                const aether::SequenceNum chSeq{ static_cast<std::uint16_t>((w[1] << 8) | w[2]) };
                aether::receiveIncomingPayload(to, aether::ChannelId{ chan }, chSeq,
                                               aether::Bytes(w.begin() + 3, w.end()), now);
            }
        }
    };

    bool got = false;
    for (int tick = 1; tick <= 250 && !got; ++tick) {
        const aether::MonoTime now{ static_cast<std::uint64_t>(tick) * 20000000ull };   // 20ms steps
        aether::updateTick(a, now); shuttle(a, b, now);      // a -> b: data (lossy)
        aether::updateTick(b, now); shuttle(b, a, now);      // b -> a: acks (lossy)
        for (const auto& m : aether::receiveMessage(b, aether::ChannelId{ 0 })) if (m == payload) got = true;
    }
    assert(got);
    std::printf("aether reliability-under-loss OK: reliable message survived ~40%% packet loss via retransmit\n");
}

void testPacketCodecAndPrng() {
    const auto r1 = aether::nextRandom(12345);
    const auto r2 = aether::nextRandom(12345);
    assert(r1.output == r2.output && r1.state == r2.state);
    assert(aether::nextRandom(1).output != aether::nextRandom(2).output);

    const aether::Packet pkt{ aether::PacketHeader{ aether::PacketType::ConnectionChallenge,
                                                    aether::SequenceNum{ 7 }, aether::SequenceNum{ 3 }, 0xABCDu },
                              aether::Bytes{ 9, 8, 7 } };
    const auto bytes = aether::serializePacket(pkt);
    assert(bytes.size() == aether::packetHeaderBytes + 3);
    const auto back = aether::deserializePacket(bytes);
    assert(back && back->header.type == aether::PacketType::ConnectionChallenge && back->payload == aether::Bytes({ 9, 8, 7 }));
    std::printf("aether util/packet OK: deterministic PRNG + packet header/payload round-trip\n");
}

void testCrcAndTokenValidation() {
    const std::uint8_t check[] = { '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    assert(aether::crc32c(check, sizeof check) == 0xE3069283u);

    auto framed = aether::appendCrc32(aether::Bytes{ 10, 20, 30 });
    const auto ok = aether::validateAndStripCrc32(framed);
    assert(ok && *ok == aether::Bytes({ 10, 20, 30 }));
    framed[0] ^= 0xFF;
    assert(!aether::validateAndStripCrc32(framed));

    aether::RateLimiter rl = aether::newRateLimiter(2, aether::MonoTime{ 0 });
    assert(aether::rateLimiterAllow(rl, 42, aether::MonoTime{ 0 }));
    assert(aether::rateLimiterAllow(rl, 42, aether::MonoTime{ 1000000 }));
    assert(!aether::rateLimiterAllow(rl, 42, aether::MonoTime{ 2000000 }));   // 3rd within 1s -> denied

    aether::EncryptionKey tk{};
    for (int i = 0; i < 32; ++i) tk[static_cast<std::size_t>(i)] = std::uint8_t(i * 3 + 7);
    aether::TokenValidator tv = aether::newTokenValidator(100);
    const aether::Bytes sealed = aether::sealConnectToken(tk, aether::ConnectToken{ 7, aether::UnixTime{ 5ull * 1000000000 }, {} });
    assert(sealed.size() == aether::connectTokenNonceBytes + 16u + static_cast<std::size_t>(aether::authTagSize));   // [nonce:12][pt:16][tag:16]
    const aether::Bytes sealedAgain = aether::sealConnectToken(tk, aether::ConnectToken{ 7, aether::UnixTime{ 5ull * 1000000000 }, {} });
    assert(sealedAgain != sealed);                                       // fresh 96-bit random nonce per seal -> no reuse
    const auto v1 = aether::validateConnectToken(tk, tv, sealed, aether::UnixTime{ 1000000 });
    assert(!v1.error && v1.playerId == 7);                                // opens + authenticates
    const auto v2 = aether::validateConnectToken(tk, tv, sealed, aether::UnixTime{ 2000000 });
    assert(v2.error == aether::TokenError::Replayed);                     // same sealed bytes -> replay

    aether::Bytes tampered = sealed; tampered[tampered.size() - 1] ^= 0x01;
    const auto openTampered = aether::openConnectToken(tk, tampered, aether::UnixTime{ 1000000 });
    assert(!openTampered);                                               // tampered tag -> rejected
    aether::EncryptionKey wrongKey{}; wrongKey[0] = 1;
    const auto openWrongKey = aether::openConnectToken(wrongKey, sealed, aether::UnixTime{ 1000000 });
    assert(!openWrongKey);                                               // wrong key -> rejected
    const aether::Bytes shortLived = aether::sealConnectToken(tk, aether::ConnectToken{ 9, aether::UnixTime{ 1000 }, {} });
    const auto openExpired = aether::openConnectToken(tk, shortLived, aether::UnixTime{ 2000 });
    assert(!openExpired);                                                // expired -> rejected
    std::printf("aether security OK: CRC32C vector + corruption detect + rate limit + sealed token (open/replay/tamper/expiry)\n");
}

void testDynamicFields() {
    struct Inventory {
        std::string                name;
        std::vector<std::uint32_t> items;
        std::optional<int>         equipped;
    };
    static_assert(aether::fieldCount<Inventory>() == 3, "Inventory should reflect 3 fields");
    const Inventory inv{ "hero", { 10, 20, 30 }, 7 };
    std::uint8_t dbuf[256];

    aether::Writer rw{ dbuf, sizeof dbuf, 0, true };
    aether::serialize(rw, inv);
    assert(rw.ok);
    aether::Reader rr{ dbuf, rw.pos, 0 };
    const auto rawBack = aether::deserialize<Inventory>(rr);
    assert(rawBack && aether::fieldEqual(*rawBack, inv));

    aether::Writer vw{ dbuf, sizeof dbuf, 0, true };
    aether::pack(vw, inv);
    assert(vw.ok);
    aether::Reader vr{ dbuf, vw.pos, 0 };
    const auto varBack = aether::unpack<Inventory>(vr);
    assert(varBack && aether::fieldEqual(*varBack, inv));

    Inventory moved = inv;
    moved.name = "champion"; moved.items.push_back(40); moved.equipped = std::nullopt;   // all 3 change
    aether::Writer ddw{ dbuf, sizeof dbuf, 0, true };
    aether::deltaPack(ddw, inv, moved);
    assert(ddw.ok);
    aether::Reader ddr{ dbuf, ddw.pos, 0 };
    const auto deltaBack = aether::deltaUnpack(ddr, inv);
    assert(deltaBack && aether::fieldEqual(*deltaBack, moved));
    std::printf("aether dynamic-fields OK: string/vector/optional round-trip through raw + varint + delta\n");
}

void testReplayAndQuantizationEdges() {
    // reliability: a fresh dedup buffer must NOT report seq 65535 as already-seen
    // (the old 0xFFFF sentinel collided with the real sequence 65535 once per wrap).
    aether::ReceivedBuffer rb;
    assert(!aether::rbExists(rb, aether::SequenceNum{ 65535 }));
    aether::rbInsert(rb, aether::SequenceNum{ 65535 });
    assert(aether::rbExists(rb, aether::SequenceNum{ 65535 }));
    assert(!aether::rbExists(rb, aether::SequenceNum{ 0 }));

    // security: re-presenting the SAME sealed token is a replay; a freshly sealed token for the
    // same player (new nonce) is not -- a legit reconnect still works, a captured token cannot.
    aether::EncryptionKey tk2{};
    for (int i = 0; i < 32; ++i) tk2[static_cast<std::size_t>(i)] = std::uint8_t(i * 5 + 1);
    aether::TokenValidator tv = aether::newTokenValidator(64);
    const aether::Bytes s1 = aether::sealConnectToken(tk2, aether::ConnectToken{ 42, aether::UnixTime{ 5ull * 1000000000 }, {} });
    const auto a1 = aether::validateConnectToken(tk2, tv, s1, aether::UnixTime{ 1 });
    assert(!a1.error && a1.playerId == 42);                              // first use OK
    const auto a2 = aether::validateConnectToken(tk2, tv, s1, aether::UnixTime{ 2 });
    assert(a2.error == aether::TokenError::Replayed);                    // same bytes -> replay
    const aether::Bytes s2 = aether::sealConnectToken(tk2, aether::ConnectToken{ 42, aether::UnixTime{ 5ull * 1000000000 }, {} });
    const auto a3 = aether::validateConnectToken(tk2, tv, s2, aether::UnixTime{ 3 });
    assert(!a3.error);                                                   // fresh seal (new nonce) OK

    // wire: Quantized at the full 32-bit width must round-trip a value at Hi (the old code
    // cast an out-of-range float to uint32 there -- UB that silently encoded Hi as Lo).
    aether::Quantized<0.0f, 100.0f, 32> q{ 100.0f };
    std::uint8_t qbuf[8] = {};
    aether::BitWriter qw{ qbuf, sizeof qbuf };
    aether::writeWire(qw, q);
    aether::flushBits(qw);
    assert(qw.ok);
    aether::BitReader qr{ qbuf, sizeof qbuf };
    aether::Quantized<0.0f, 100.0f, 32> q2{ 0.0f };
    aether::readWire(qr, q2);
    assert(qr.ok && q2.value > 99.99f && q2.value <= 100.01f);
}

void testPeerHandshake() {
    const aether::NetworkConfig cfg;
    const aether::Address addrA = aether::addrLocalhost(1111);
    const aether::Address addrB = aether::addrLocalhost(2222);
    const aether::PeerId  idA{ addrA }, idB{ addrB };
    aether::NetPeer A = aether::newPeerState(addrA, cfg, aether::MonoTime{ 0 });
    aether::NetPeer B = aether::newPeerState(addrB, cfg, aether::MonoTime{ 999 });   // distinct RNG seed

    aether::peerConnect(A, idB, aether::MonoTime{ 0 });

    std::vector<aether::IncomingPacket> toA, toB;
    bool          aUp = false, bUp = false;
    std::uint64_t t = 0;
    for (int tick = 0; tick < 12 && !(aUp && bUp); ++tick) {
        t += 1000000;   // 1ms steps
        const auto ra = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        const auto rb = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();
        for (const auto& p : ra.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toB.push_back(aether::IncomingPacket{ idA, *s });
        for (const auto& p : rb.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
        for (const auto& e : ra.events) if (e.kind == aether::PeerEvent::Connected) aUp = true;
        for (const auto& e : rb.events) if (e.kind == aether::PeerEvent::Connected) bUp = true;
    }
    assert(aUp && bUp && aether::peerIsConnected(A, idB) && aether::peerIsConnected(B, idA));

    // X25519: the handshake derived DIRECTIONAL session keys. Each side's send key equals the
    // peer's receive key (so they agree), but a side's own send != recv -- so the two directions
    // never share a (key, nonce). That is the guard against the catastrophic keystream reuse.
    {
        const auto& ca = A.connections.at(idB);
        const auto& cb = B.connections.at(idA);
        assert(ca.sendKey && ca.recvKey && cb.sendKey && cb.recvKey);
        assert(*ca.sendKey == *cb.recvKey && *ca.recvKey == *cb.sendKey);
        assert(*ca.sendKey != *ca.recvKey);
    }
    std::printf("aether x25519-handshake OK: directional keys (send != recv, agree across peers)\n");

    // clock sync: tick past the TimeSync interval a few times so pings/pongs flow and both
    // sides land an offset sample (same test clock here, so the offset is ~0 -- this proves the
    // round-trip exchange + estimator wiring; clocksync.hpp's unit test covers offset recovery).
    for (int sync = 0; sync < 6; ++sync) {
        t += 1100ull * 1000000;   // 1.1s steps: one TimeSyncPing per tick
        const auto rax = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        const auto rbx = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();
        for (const auto& p : rax.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toB.push_back(aether::IncomingPacket{ idA, *s });
        for (const auto& p : rbx.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
    }
    assert(aether::clockSynced(A.connections.at(idB)) && aether::clockSynced(B.connections.at(idA)));
    std::printf("aether timesync OK: offset estimated both ways (A<->B %.2fms over a shared clock)\n",
                aether::clockOffsetMs(A.connections.at(idB)));

    // reconnect: idle past the timeout so both sides drop, then re-establish via the session
    // token -- a fast token-authenticated reconnect (no challenge); the server fires Reconnected.
    const auto token = aether::peerSessionToken(A, idB);
    assert(token);
    const auto origSend = A.connections.at(idB).sendKey;   // the client's pre-drop send key
    assert(origSend);                                      // encrypted before the drop
    t += 11000ull * 1000000;   // > connectionTimeoutMs: both time out this tick
    aether::peerProcess(A, aether::MonoTime{ t }, {});
    aether::peerProcess(B, aether::MonoTime{ t }, {});
    assert(!aether::peerIsConnected(A, idB) && !aether::peerIsConnected(B, idA));

    aether::peerReconnect(A, idB, *token, aether::MonoTime{ t });
    bool reconnected = false;
    for (int rc = 0; rc < 16 && !(reconnected && aether::peerIsConnected(A, idB)); ++rc) {
        t += 1000000;
        const auto ra2 = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        const auto rb2 = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();
        for (const auto& p : ra2.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toB.push_back(aether::IncomingPacket{ idA, *s });
        for (const auto& p : rb2.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
        for (const auto& e : rb2.events) if (e.kind == aether::PeerEvent::Reconnected) reconnected = true;
    }
    assert(reconnected && aether::peerIsConnected(A, idB) && aether::peerIsConnected(B, idA));
    // 0-RTT reconnect stays encrypted AND re-keys: the resumed session derives FRESH directional
    // keys from the cached shared secret + a fresh salt, so it never replays the original keystream.
    {
        const auto& ca = A.connections.at(idB);
        const auto& cb = B.connections.at(idA);
        assert(ca.sendKey && ca.recvKey && cb.sendKey && cb.recvKey);
        assert(*ca.sendKey == *cb.recvKey && *ca.recvKey == *cb.sendKey);   // still agree across peers
        assert(*ca.sendKey != *origSend);                                    // but fresh -- not the pre-drop key
    }
    std::printf("aether reconnect OK: resumed session re-keyed (fresh directional keys, no keystream reuse)\n");

    // peerShutdown drains a Disconnect packet per live connection, so a process that exits
    // immediately still notifies its peers instead of leaving them to time out.
    const auto closeA = aether::peerShutdown(A, aether::MonoTime{ t });
    assert(!closeA.empty());

    std::printf("aether peer OK: full handshake A<->B + graceful shutdown drains Disconnect\n");
}

void testAddressMigration() {
    const aether::NetworkConfig cfg;
    const aether::Address addrA  = aether::addrLocalhost(7001);
    const aether::Address addrB  = aether::addrLocalhost(7002);
    const aether::Address addrA2 = aether::addrLocalhost(7003);   // A's address after a NAT rebind
    const aether::PeerId  idA{ addrA }, idB{ addrB }, idA2{ addrA2 };
    aether::NetPeer A = aether::newPeerState(addrA, cfg, aether::MonoTime{ 0 });
    aether::NetPeer B = aether::newPeerState(addrB, cfg, aether::MonoTime{ 1 });
    aether::peerConnect(A, idB, aether::MonoTime{ 0 });

    std::vector<aether::IncomingPacket> toA, toB;
    std::uint64_t t = 0;
    for (int k = 0; k < 12 && !(aether::peerIsConnected(A, idB) && aether::peerIsConnected(B, idA)); ++k) {
        t += 1000000;
        const auto ra = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        const auto rb = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();
        for (const auto& p : ra.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toB.push_back(aether::IncomingPacket{ idA, *s });
        for (const auto& p : rb.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
    }
    assert(aether::peerIsConnected(A, idB) && aether::peerIsConnected(B, idA));

    // A sends an app message; deliver A's encrypted packets to B, but tagged from the NEW address.
    aether::peerSend(A, idB, aether::ChannelId{ 0 }, aether::Bytes{ 9, 8, 7 }, aether::MonoTime{ t });
    t += 1000000;
    const auto ra = aether::peerProcess(A, aether::MonoTime{ t }, {});
    std::vector<aether::IncomingPacket> fromNew;
    for (const auto& p : ra.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) fromNew.push_back(aether::IncomingPacket{ idA2, *s });

    // Decrypting proves KEY possession, not that the sender receives at the address it claims -- a
    // replayed genuine packet decrypts too. So this authentic packet is delivered on the connection
    // where it already lives, and the new address gets a challenge; nothing moves yet.
    const auto rb = aether::peerProcess(B, aether::MonoTime{ t }, fromNew);
    bool migrated = false, gotMsg = false;
    for (const auto& e : rb.events) {
        if (e.kind == aether::PeerEvent::Migrated)                                      migrated = true;
        if (e.kind == aether::PeerEvent::Message && e.data == aether::Bytes{ 9, 8, 7 }) gotMsg   = true;
    }
    assert(gotMsg);                                   // the payload is authentic, so it is delivered
    assert(!migrated);                                // ...but the path is still unproven
    assert(aether::peerIsConnected(B, idA) && !aether::peerIsConnected(B, idA2));
    assert(B.pathValidations.count(idA2) == 1);       // a challenge is outstanding to the candidate

    // Deliver B's challenge to A (A's view of B is unchanged, so it arrives from idB), and carry A's
    // answer back tagged from the new address. Only that echo completes the move.
    std::vector<aether::IncomingPacket> toA2;
    for (const auto& p : rb.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA2.push_back(aether::IncomingPacket{ idB, *s });
    t += 1000000;
    const auto ra2 = aether::peerProcess(A, aether::MonoTime{ t }, toA2);
    std::vector<aether::IncomingPacket> answer;
    for (const auto& p : ra2.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) answer.push_back(aether::IncomingPacket{ idA2, *s });

    t += 1000000;
    const auto rb2 = aether::peerProcess(B, aether::MonoTime{ t }, answer);
    for (const auto& e : rb2.events) if (e.kind == aether::PeerEvent::Migrated) migrated = true;
    assert(migrated);
    assert(aether::peerIsConnected(B, idA2) && !aether::peerIsConnected(B, idA));   // moved to the new address
    assert(B.pathValidations.empty());                                              // and the probe is retired

    // a spoofed Payload from a stranger (valid header/seq, undecryptable body), past the migration
    // cooldown so the decrypt is the actual gate -- must NOT migrate the connection.
    t += 6000ull * 1000000;   // > migrationCooldownMs
    const aether::PeerId idX{ aether::addrLocalhost(7009) };
    const aether::PacketHeader sh{ aether::PacketType::Payload, aether::connRemoteSeq(B.connections.at(idA2)), aether::SequenceNum{ 0 }, 0 };
    const aether::Bytes spoof = aether::serializePacket(aether::Packet{ sh, aether::Bytes(40, 0x5A) });
    const auto rbSpoof = aether::peerProcess(B, aether::MonoTime{ t }, { aether::IncomingPacket{ idX, spoof } });
    for (const auto& e : rbSpoof.events) assert(e.kind != aether::PeerEvent::Migrated);
    assert(B.pathValidations.count(idX) == 0);   // undecryptable: not even worth a challenge
    assert(!aether::peerIsConnected(B, idX) && aether::peerIsConnected(B, idA2));

    std::printf("aether migration OK: path-validated move; undecryptable spoof refused\n");
}

void testMigrationReplayChallenge() {
    const aether::NetworkConfig cfg;
    const aether::PeerId idA{ aether::addrLocalhost(7020) }, idB{ aether::addrLocalhost(7021) },
                         idEvil{ aether::addrLocalhost(7022) };
    aether::NetPeer A = aether::newPeerState(idA.addr, cfg, aether::MonoTime{ 0 });
    aether::NetPeer B = aether::newPeerState(idB.addr, cfg, aether::MonoTime{ 0 });
    aether::peerConnect(A, idB, aether::MonoTime{ 0 });

    std::vector<aether::IncomingPacket> toA, toB;
    std::uint64_t t = 0;
    for (int k = 0; k < 12 && !(aether::peerIsConnected(A, idB) && aether::peerIsConnected(B, idA)); ++k) {
        t += 1000000;
        const auto ra = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        const auto rb = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();
        for (const auto& p : ra.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toB.push_back(aether::IncomingPacket{ idA, *s });
        for (const auto& p : rb.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
    }
    assert(aether::peerIsConnected(A, idB) && aether::peerIsConnected(B, idA));

    aether::peerSend(A, idB, aether::ChannelId{ 0 }, aether::Bytes{ 4, 4, 4 }, aether::MonoTime{ t });
    t += 1000000;
    const auto raCap = aether::peerProcess(A, aether::MonoTime{ t }, {});
    std::vector<aether::IncomingPacket> replayed;
    for (const auto& p : raCap.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) replayed.push_back(aether::IncomingPacket{ idEvil, *s });
    assert(!replayed.empty());

    t += 1000000;
    const auto rbEvil = aether::peerProcess(B, aether::MonoTime{ t }, replayed);
    for (const auto& e : rbEvil.events) assert(e.kind != aether::PeerEvent::Migrated);
    assert(aether::peerIsConnected(B, idA) && !aether::peerIsConnected(B, idEvil));

    // The attacker is challenged but cannot answer, so the probe expires and the connection never
    // moves. Only B ticks here: the point is that no answer ever arrives.
    for (int k = 0; k < 6; ++k) {
        t += 1000ull * 1000000;
        const auto rbIdle = aether::peerProcess(B, aether::MonoTime{ t }, {});
        for (const auto& e : rbIdle.events) assert(e.kind != aether::PeerEvent::Migrated);
    }
    assert(!aether::peerIsConnected(B, idEvil));
    assert(B.pathValidations.empty());   // the unanswered probe was swept, not left pinned
    std::printf("aether migration OK: a replayed genuine packet cannot hijack the path\n");
}

void testTokenAdmission() {
    aether::EncryptionKey K{};   // the backend<->game-server shared key
    for (int i = 0; i < 32; ++i) K[static_cast<std::size_t>(i)] = std::uint8_t(i * 9 + 5);
    aether::NetworkConfig serverCfg; serverCfg.tokenKey = K;   // server requires a token
    const aether::NetworkConfig clientCfg;                     // client needs no key

    const aether::Address addrS = aether::addrLocalhost(7101);
    const aether::Address addrC = aether::addrLocalhost(7102);
    const aether::PeerId  idS{ addrS }, idC{ addrC };
    aether::NetPeer S = aether::newPeerState(addrS, serverCfg, aether::MonoTime{ 0 });
    aether::NetPeer C = aether::newPeerState(addrC, clientCfg, aether::MonoTime{ 1 });

    // the "backend" mints a token for player 12345, the client presents it
    const aether::Bytes token = aether::sealConnectToken(K, aether::ConnectToken{ 12345, aether::UnixTime{ 3600ull * 1000000000 }, {} });
    aether::peerConnectWithToken(C, idS, token, aether::MonoTime{ 0 });

    aether::TestLink link = aether::newTestLink(C, idC, S, idS);
    std::uint64_t    connectedPlayer = 0;
    const aether::MonoTime t = aether::testLinkRun(link, aether::MonoTime{ 0 }, 1000000, 14,
                                                   [&](const aether::TestLinkStep& s) {
        for (const auto& e : s.bEvents) if (e.kind == aether::PeerEvent::Connected) connectedPlayer = e.playerId;
        return connectedPlayer != 0;
    });
    assert(connectedPlayer == 12345 && aether::peerIsConnected(S, idC));   // server authenticated the player

    // a client with NO token is rejected (server requires one): it never connects.
    const aether::PeerId idX{ aether::addrLocalhost(7103) };
    aether::NetPeer X = aether::newPeerState(aether::addrLocalhost(7103), clientCfg, aether::MonoTime{ 2 });
    aether::peerConnect(X, idS, t);   // no token
    aether::TestLink xlink = aether::newTestLink(X, idX, S, idS);
    bool xUp = false;
    aether::testLinkRun(xlink, t, 1000000, 14, [&](const aether::TestLinkStep& s) {
        xUp = xUp || aether::testHasEvent(s.bEvents, aether::PeerEvent::Connected);
        return xUp;
    });
    assert(!xUp && !aether::peerIsConnected(S, idX));   // no valid token -> never connected
    std::printf("aether auth OK: valid token connects (playerId %llu surfaced), tokenless client rejected\n",
                static_cast<unsigned long long>(connectedPlayer));
}

void testReplicationHelpers() {
    const aether::RadiusInterest ri = aether::newRadiusInterest(10.0f);
    assert(aether::relevant(ri, aether::Position{ 0, 0, 0 }, aether::Position{ 5, 0, 0 }));
    assert(!aether::relevant(ri, aether::Position{ 0, 0, 0 }, aether::Position{ 20, 0, 0 }));

    aether::PriorityAccumulator<int> pa;
    aether::priorityRegister(pa, 1, 10.0f);
    aether::priorityRegister(pa, 2, 1.0f);
    aether::priorityAccumulate(pa, 1.0f);
    const auto sel = aether::priorityDrainTop(pa, 100, [](int) { return 50; });
    assert(sel.size() == 2 && sel[0] == 1);   // higher base priority drains first

    aether::SnapshotBuffer<float> sb = aether::newSnapshotBuffer<float>();
    aether::pushSnapshot(sb, 0.0, 0.0f);
    aether::pushSnapshot(sb, 100.0, 10.0f);
    const auto mid = aether::sampleSnapshot(sb, 150.0);   // target 50ms -> halfway -> 5.0
    assert(mid && *mid > 4.9f && *mid < 5.1f);

    struct Ent { int hp; int x; int y; };
    aether::DeltaTracker<Ent>    tr = aether::newDeltaTracker<Ent>(8);
    aether::BaselineManager<Ent> bm = aether::newBaselineManager<Ent>(8, 5000.0);
    const Ent  s0{ 100, 10, 20 };
    const auto enc0 = aether::deltaEncode(tr, aether::BaselineSeq{ 0 }, s0);
    const auto dec0 = aether::deltaDecode(bm, enc0);
    assert(dec0 && dec0->hp == 100 && dec0->x == 10 && dec0->y == 20);
    aether::pushBaseline(bm, aether::BaselineSeq{ 0 }, *dec0, aether::MonoTime{ 0 });
    aether::deltaOnAck(tr, aether::BaselineSeq{ 0 });
    const Ent  s1{ 100, 11, 20 };
    const auto enc1 = aether::deltaEncode(tr, aether::BaselineSeq{ 1 }, s1);
    assert(enc1.size() < enc0.size());                    // delta beats full snapshot
    const auto dec1 = aether::deltaDecode(bm, enc1);
    assert(dec1 && dec1->hp == 100 && dec1->x == 11 && dec1->y == 20);
    std::printf("aether replication OK: interest + priority + interpolation + delta (full %zu B -> delta %zu B)\n",
                enc0.size(), enc1.size());
}

void testRendezvousCodec() {
    const aether::Address addr = aether::addrV4(0x01020304u, 9999);
    const aether::Bytes enc = aether::serializeAddr(addr);
    const auto back = aether::deserializeAddr(enc.data(), enc.size());
    assert(back && aether::addrEqual(*back, addr));

    const auto room = aether::decodeRegister(aether::encodeRegister(0xABCDEF12u));
    assert(room && *room == 0xABCDEF12u);

    const auto pd = aether::decodePaired(aether::encodePaired(aether::PunchRole::Connect, addr));
    assert(pd && pd->first == aether::PunchRole::Connect && aether::addrEqual(pd->second, addr));
    std::printf("aether rendezvous-proto OK: address + Register/Paired round-trip\n");
}

void testRendezvousPairing() {
    aether::RendezvousServer rv;
    const aether::Address a = aether::addrV4(0x0A000001u, 1111);
    const aether::Address b = aether::addrV4(0x0A000002u, 2222);
    const auto out1 = aether::rendezvousProcess(rv, { { a, aether::encodeRegister(7) } }, aether::MonoTime{ 0 });
    assert(out1.empty());                                  // A waits
    const auto out2 = aether::rendezvousProcess(rv, { { b, aether::encodeRegister(7) } }, aether::MonoTime{ 0 });
    assert(out2.size() == 2);                              // B's arrival pairs them
    const auto pa = aether::decodePaired(out2[0].second);  // -> A: accept, B's address
    const auto pb = aether::decodePaired(out2[1].second);  // -> B: connect, A's address
    assert(aether::addrEqual(out2[0].first, a) && pa && pa->first == aether::PunchRole::Accept  && aether::addrEqual(pa->second, b));
    assert(aether::addrEqual(out2[1].first, b) && pb && pb->first == aether::PunchRole::Connect && aether::addrEqual(pb->second, a));
    std::printf("aether rendezvous OK: two peers paired, roles + addresses correct\n");
}

void testRendezvousRelay() {
    aether::RendezvousServer rv;
    const aether::Address a = aether::addrV4(0x0A000001u, 1111);
    const aether::Address b = aether::addrV4(0x0A000002u, 2222);
    aether::rendezvousProcess(rv, { { a, aether::encodeRegister(7) } }, aether::MonoTime{ 0 });
    aether::rendezvousProcess(rv, { { b, aether::encodeRegister(7) } }, aether::MonoTime{ 0 });   // paired -> session stored
    const aether::Bytes inner = { 0xDE, 0xAD, 0xBE, 0xEF };
    const auto fwd = aether::rendezvousProcess(rv, { { a, aether::encodeRelay(7, inner.data(), inner.size()) } }, aether::MonoTime{ 0 });
    assert(fwd.size() == 1 && aether::addrEqual(fwd[0].first, b) && fwd[0].second == inner);   // A's relay -> B, intact
    const auto back = aether::rendezvousProcess(rv, { { b, aether::encodeRelay(7, inner.data(), inner.size()) } }, aether::MonoTime{ 0 });
    assert(back.size() == 1 && aether::addrEqual(back[0].first, a));                            // B's relay -> A
    const aether::Address c = aether::addrV4(0x0A000099u, 9999);                                 // not a session member
    const auto none = aether::rendezvousProcess(rv, { { c, aether::encodeRelay(7, inner.data(), inner.size()) } }, aether::MonoTime{ 0 });
    assert(none.empty());                                                                       // not an open reflector
    std::printf("aether relay OK: rendezvous forwards a relayed packet to the paired peer; rejects non-members\n");
}

void testRendezvousExpiry() {
    aether::RendezvousServer rv;
    const aether::Address a = aether::addrV4(0x0A000001u, 1111);
    const aether::Address b = aether::addrV4(0x0A000002u, 2222);
    const auto r0 = aether::rendezvousProcess(rv, { { a, aether::encodeRegister(9) } }, aether::MonoTime{ 0 });
    assert(r0.empty() && rv.waiting.size() == 1);   // A waits
    const auto r1 = aether::rendezvousProcess(rv, {}, aether::MonoTime{ 400ull * 1000000000 });   // > TTL -> sweep
    assert(r1.empty() && rv.waiting.empty());        // A's stale wait was dropped
    const auto r2 = aether::rendezvousProcess(rv, { { b, aether::encodeRegister(9) } }, aether::MonoTime{ 400ull * 1000000000 });
    assert(r2.empty() && rv.waiting.size() == 1);   // B is a fresh waiter, not paired with the expired A
    std::printf("aether rendezvous-ttl OK: a stale waiter is swept after the TTL\n");
}

void testUdpHandshake() {
    const aether::NetworkConfig cfg;
    auto hA = aether::openHost(aether::addrLocalhost(0), cfg, aether::MonoTime{ 0 });
    auto hB = aether::openHost(aether::addrLocalhost(0), cfg, aether::MonoTime{ 999 });
    assert(hA && hB);
    const aether::Address addrB = aether::localAddr(hB->socket);
    aether::hostConnect(*hA, addrB, aether::MonoTime{ 0 });

    bool          aUp = false, bUp = false;
    std::uint64_t t = 0;
    for (int tick = 0; tick < 300 && !(aUp && bUp); ++tick) {
        t += 1000000;
        for (const auto& e : aether::hostTick(*hA, {}, aether::MonoTime{ t })) if (e.kind == aether::PeerEvent::Connected) aUp = true;
        for (const auto& e : aether::hostTick(*hB, {}, aether::MonoTime{ t })) if (e.kind == aether::PeerEvent::Connected) bUp = true;
        std::this_thread::yield();   // give the OS a slice to actually deliver the loopback packets; a tight spin can starve it
    }
    assert(aUp && bUp);
    aether::closeHost(*hA);
    aether::closeHost(*hB);
    std::printf("aether net OK: two real UDP hosts handshook over localhost\n");
}

void testUdpRendezvousPunch() {
    const aether::NetworkConfig cfg2;
    auto rv = aether::openUdp(aether::addrLocalhost(0));
    auto hA = aether::openHost(aether::addrLocalhost(0), cfg2, aether::MonoTime{ 0 });
    auto hB = aether::openHost(aether::addrLocalhost(0), cfg2, aether::MonoTime{ 777 });
    assert(rv && hA && hB);
    const aether::Address rvAddr = aether::localAddr(*rv);
    aether::RendezvousServer server;
    aether::hostJoinRoom(*hA, rvAddr, 42, aether::MonoTime{ 0 });
    aether::hostJoinRoom(*hB, rvAddr, 42, aether::MonoTime{ 777 });

    bool aUp = false, bUp = false;
    std::uint64_t t = 0;
    for (int tick = 0; tick < 200 && !(aUp && bUp); ++tick) {
        t += 1000000;
        aether::rendezvousTick(server, *rv, aether::MonoTime{ t });
        for (const auto& e : aether::hostTick(*hA, {}, aether::MonoTime{ t })) if (e.kind == aether::PeerEvent::Connected) aUp = true;
        for (const auto& e : aether::hostTick(*hB, {}, aether::MonoTime{ t })) if (e.kind == aether::PeerEvent::Connected) bUp = true;
        std::this_thread::yield();
    }
    assert(aUp && bUp);
    aether::closeHost(*hA); aether::closeHost(*hB); aether::closeSocket(*rv);
    std::printf("aether nat-punch OK: rendezvous paired two hosts, handshake completed over the punched path\n");
}

void testRendezvousRegisterRetry() {
    const aether::NetworkConfig rcfg;
    auto rv2 = aether::openUdp(aether::addrLocalhost(0));
    auto h   = aether::openHost(aether::addrLocalhost(0), rcfg, aether::MonoTime{ 0 });
    assert(rv2 && h);
    const aether::Address rv2Addr = aether::localAddr(*rv2);
    aether::hostJoinRoom(*h, rv2Addr, 7, aether::MonoTime{ 0 });   // Register #1
    std::uint64_t tt = 0;
    for (int k = 0; k < 4; ++k) { tt += 1100ull * 1000000; (void) aether::hostTick(*h, {}, aether::MonoTime{ tt }); std::this_thread::yield(); }  // each > registerRetryMs
    // Drain the rendezvous socket, polling until the retries are actually delivered over loopback
    // (a non-blocking recv returns -1 while datagrams are still in flight). Bounded, so a genuinely
    // broken retry path fails rather than hangs -- this replaces a single drain that raced delivery.
    int registers = 0;
    std::uint8_t rb[600];
    for (int attempt = 0; attempt < 2000 && registers < 2; ++attempt) {
        aether::Address from{};
        const int n = aether::recvFrom(*rv2, std::span<std::uint8_t>(rb, sizeof rb), from);
        if (n > 0) { if (aether::decodeRegister(aether::Bytes(rb, rb + n))) ++registers; }
        else       { std::this_thread::yield(); }
    }
    assert(registers >= 2);   // re-sent, not sent once
    aether::closeHost(*h);
    aether::closeSocket(*rv2);
    std::printf("aether register-resend OK: a stranded join retries Register (%d datagrams)\n", registers);
}

void testUdpRelayHandshake() {
    const aether::NetworkConfig rcfg;
    auto rv = aether::openUdp(aether::addrLocalhost(0));
    auto hA = aether::openHost(aether::addrLocalhost(0), rcfg, aether::MonoTime{ 0 });
    auto hB = aether::openHost(aether::addrLocalhost(0), rcfg, aether::MonoTime{ 5 });
    assert(rv && hA && hB);
    hA->punchTimeoutMs = 0.0;   // skip the direct punch -> relay immediately
    hB->punchTimeoutMs = 0.0;
    const aether::Address rvAddr = aether::localAddr(*rv);
    aether::RendezvousServer server;
    aether::hostJoinRoom(*hA, rvAddr, 55, aether::MonoTime{ 0 });
    aether::hostJoinRoom(*hB, rvAddr, 55, aether::MonoTime{ 0 });

    bool aUp = false, bUp = false;
    std::uint64_t t = 0;
    for (int tick = 0; tick < 300 && !(aUp && bUp); ++tick) {
        t += 1000000;
        aether::rendezvousTick(server, *rv, aether::MonoTime{ t });
        for (const auto& e : aether::hostTick(*hA, {}, aether::MonoTime{ t })) if (e.kind == aether::PeerEvent::Connected) aUp = true;
        for (const auto& e : aether::hostTick(*hB, {}, aether::MonoTime{ t })) if (e.kind == aether::PeerEvent::Connected) bUp = true;
        std::this_thread::yield();
    }
    assert(aUp && bUp && hA->relaying && hB->relaying);   // connected, and over the relay path
    aether::closeHost(*hA); aether::closeHost(*hB); aether::closeSocket(*rv);
    std::printf("aether relay-e2e OK: two hosts handshook through the rendezvous relay (punch skipped)\n");
}

void testStringLengthOverflow() {
    struct StrBox { std::string s; };
    const aether::Bytes evil = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };   // LEB128 for 0xFFFFFFFFFFFFFFFF
    aether::Reader r{ evil.data(), evil.size(), 0 };
    const auto out = aether::unpack<StrBox>(r);
    assert(!out);   // nullopt, and -- the point -- no length_error / over-read
    std::printf("aether hostile-string-length OK: oversized varint length rejected, no crash\n");
}

void testReceiveMessageSize() {
    aether::ChannelConfig cfg;
    cfg.deliveryMode   = aether::DeliveryMode::Unreliable;
    cfg.maxMessageSize = 16;
    aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);
    aether::onMessageReceived(ch, aether::SequenceNum{ 0 }, aether::Bytes(64, 0xAB), aether::MonoTime{ 0 });   // 64 > 16
    assert(aether::channelReceive(ch).empty() && ch.totalDropped == 1);
    aether::onMessageReceived(ch, aether::SequenceNum{ 1 }, aether::Bytes(8, 0xCD), aether::MonoTime{ 0 });    // 8 <= 16
    assert(aether::channelReceive(ch).size() == 1);
    std::printf("aether channel-recv-cap OK: oversized message dropped, in-bound delivered\n");
}

void testChannelCapacityValidation() {
    aether::NetworkConfig c;
    c.defaultChannelConfig.messageBufferSize = 0;   // would make every reliable send BufferFull forever
    assert(validateConfig(c) == aether::ConfigError::InvalidChannelConfig);
    aether::NetworkConfig c2;
    c2.channelConfigs.push_back(aether::ChannelConfig{ .maxMessageSize = 0 });   // dead channel
    assert(validateConfig(c2) == aether::ConfigError::InvalidChannelConfig);
    aether::NetworkConfig c3;
    c3.defaultChannelConfig.maxMessageSize = 400000;   // beyond maxFragmentCount fragments at the default MTU -> rejected at setup, not dropped at send
    assert(validateConfig(c3) == aether::ConfigError::MessageTooLargeToFragment);
    // ...and the fragment ceiling is the ONLY size limit: a message far bigger than one send-rate
    // bucket validates fine, because fragment pacing spreads its emission across ticks (the old
    // whole-message admission rejected this as MessageExceedsSendBudget).
    aether::NetworkConfig c4;
    c4.defaultChannelConfig.maxMessageSize = static_cast<int>(aether::maxFragmentableMessage(c4));   // ~295KB >> one bucket
    assert(!validateConfig(c4));
    assert(!validateConfig(aether::NetworkConfig{}));   // defaults remain valid
    std::printf("aether channel-config-validation OK: non-positive caps + unfragmentable maxMessageSize rejected; budget no longer caps size\n");
}

void testOrderedGapFailureAcrossWrap() {
    aether::ChannelConfig cfg;
    cfg.deliveryMode         = aether::DeliveryMode::ReliableOrdered;
    cfg.orderedBufferTimeout = 100.0;
    aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);
    ch.orderedExpected = aether::SequenceNum{ 0xFFFD };
    aether::onMessageReceived(ch, aether::SequenceNum{ 0xFFFE }, aether::Bytes{ 1 }, aether::MonoTime{ 0 });   // before the wrap
    aether::onMessageReceived(ch, aether::SequenceNum{ 0x0001 }, aether::Bytes{ 2 }, aether::MonoTime{ 0 });   // after the wrap (logically newest)
    aether::channelUpdate(ch, aether::MonoTime{ 200'000'000 });   // 200ms exceeds the configured gap deadline
    assert(ch.orderedExpected.value == 0xFFFD);
    assert(ch.failure == aether::ChannelFailure::OrderedGapTimeout);
    assert(aether::channelReceive(ch).empty());
    std::printf("aether ordered timeout OK: explicit failure preserves the missing sequence across wrap\n");
}

void testFragmentDeliveryWithLoss() {
    aether::NetworkConfig cfg;
    cfg.defaultChannelConfig.maxMessageSize = 16384;   // allow (and force fragmentation of) a >MTU message
    const aether::Address addrA = aether::addrLocalhost(3333), addrB = aether::addrLocalhost(4444);
    const aether::PeerId  idA{ addrA }, idB{ addrB };
    aether::NetPeer A = aether::newPeerState(addrA, cfg, aether::MonoTime{ 0 });
    aether::NetPeer B = aether::newPeerState(addrB, cfg, aether::MonoTime{ 7 });

    std::vector<aether::IncomingPacket> toA, toB;
    std::uint64_t t = 0;
    aether::peerConnect(A, idB, aether::MonoTime{ t });
    bool aUp = false, bUp = false;
    for (int tick = 0; tick < 16 && !(aUp && bUp); ++tick) {   // clean handshake first
        t += 1000000;
        const auto ra = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        const auto rb = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();
        for (const auto& p : ra.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toB.push_back(aether::IncomingPacket{ idA, *s });
        for (const auto& p : rb.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
        for (const auto& e : ra.events) if (e.kind == aether::PeerEvent::Connected) aUp = true;
        for (const auto& e : rb.events) if (e.kind == aether::PeerEvent::Connected) bUp = true;
    }
    assert(aUp && bUp);

    aether::Bytes big(5000);   // ~5 fragments at a 1200 MTU
    for (std::size_t k = 0; k < big.size(); ++k) big[k] = static_cast<std::uint8_t>((k * 31 + 7) & 0xFF);
    assert(!aether::peerSend(A, idB, aether::ChannelId{ 0 }, big, aether::MonoTime{ t }));   // accepted; will fragment

    aether::Bytes received;
    int drop = 0, fragmentsSent = 0;
    for (int tick = 0; tick < 400 && received.empty(); ++tick) {
        t += 1000000;
        const auto ra = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        auto       rb = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();   // non-const: we move the received message out of its event
        for (const auto& p : ra.outgoing) {
            assert(static_cast<int>(p.data.size()) <= cfg.mtu);   // no oversized datagram -> it really fragmented
            auto s = aether::validateAndStripCrc32(p.data);
            if (!s) continue;
            // The payload is encrypted, but the header type is not: at a 1200 MTU each ~1156-byte
            // fragment fills its own datagram, so payload-carrying datagrams count fragment sends.
            const auto pkt = aether::deserializePacket(*s);
            if (pkt && (pkt->header.type == aether::PacketType::Payload
                     || pkt->header.type == aether::PacketType::PayloadBatch)) ++fragmentsSent;
            if (drop++ % 3 != 0) toB.push_back(aether::IncomingPacket{ idA, *s });   // drop ~1/3 of A->B
        }
        for (const auto& p : rb.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
        for (auto& e : rb.events) if (e.kind == aether::PeerEvent::Message) received = std::move(e.data);
    }
    assert(received == big);   // exact reassembly under loss
    // With ~1/3 of fragments lost, 5 fragments cost 7 datagrams: the 5 originals plus the 2 that were
    // dropped. Resending the whole message per retransmit round costs 10 here (measured), and the gap
    // widens with the fragment count -- so this bound fails on a regression back to full resends rather
    // than quietly costing bandwidth.
    assert(fragmentsSent < 10);
    std::printf("aether fragmentation-e2e OK: %zu-byte reliable message fragmented + reassembled under "
                "~33%% loss, %d fragment wires sent for 5 fragments\n", big.size(), fragmentsSent);
}

void testCongestionWindowWithLoss() {
    aether::NetworkConfig cfg;
    cfg.useCwndCongestion = true;
    cfg.channelConfigs.push_back(aether::reliableOrderedChannel());
    cfg.channelConfigs.push_back(aether::unreliableChannel());   // never acked -- must not be charged
    cfg.maxChannels = 2;
    assert(!aether::validateConfig(cfg));

    const aether::Address addrA = aether::addrLocalhost(7301), addrB = aether::addrLocalhost(7302);
    const aether::PeerId  idA{ addrA }, idB{ addrB };
    aether::NetPeer A = aether::newPeerState(addrA, cfg, aether::MonoTime{ 0 });
    aether::NetPeer B = aether::newPeerState(addrB, cfg, aether::MonoTime{ 0 });
    aether::peerConnect(A, idB, aether::MonoTime{ 0 });

    std::vector<aether::IncomingPacket> toA, toB;
    std::uint64_t t = 0;
    int  sent = 0, delivered = 0, drop = 0;
    constexpr int totalMessages = 60;
    for (int tick = 0; tick < 4000 && delivered < totalMessages; ++tick) {
        t += 1000000;   // 1ms
        if (sent < totalMessages && aether::peerIsConnected(A, idB)) {
            const aether::Bytes payload(700, static_cast<std::uint8_t>(sent));
            if (!aether::peerSend(A, idB, aether::ChannelId{ 0 }, payload, aether::MonoTime{ t })) ++sent;
            aether::peerSend(A, idB, aether::ChannelId{ 1 }, aether::Bytes(200, 0x5A), aether::MonoTime{ t });   // unreliable filler
        }
        const auto ra = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        auto       rb = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();
        for (const auto& p : ra.outgoing)
            if (auto s = aether::validateAndStripCrc32(p.data)) if (drop++ % 4 != 0) toB.push_back(aether::IncomingPacket{ idA, *s });   // ~25% loss A->B
        for (const auto& p : rb.outgoing)
            if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
        for (const auto& e : rb.events)
            if (e.kind == aether::PeerEvent::Message && e.channel == aether::ChannelId{ 0 }) ++delivered;
    }
    assert(sent == totalMessages);
    assert(delivered == totalMessages);   // every reliable message arrived: the window never wedged shut

    // Quiet drain: no new sends, no loss. Once every outstanding packet has resolved, the window
    // must be exactly empty -- any byte that was charged and never credited shows up here.
    for (int tick = 0; tick < 400; ++tick) {
        t += 1000000;
        const auto ra = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        const auto rb = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();
        for (const auto& p : ra.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toB.push_back(aether::IncomingPacket{ idA, *s });
        for (const auto& p : rb.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
    }
    const auto& sender = A.connections.at(idB);
    assert(sender.cwnd.has_value());
    assert(sender.cwnd->bytesInFlight == 0);   // every charged byte was credited back exactly once
    std::printf("aether cwnd-e2e OK: %d/%d reliable messages under ~25%% loss, window drained to 0 in-flight\n",
                delivered, totalMessages);
}

void testReceiveBufferLimit() {
    aether::ChannelConfig cfg;
    cfg.deliveryMode         = aether::DeliveryMode::Unreliable;
    cfg.maxReceiveBufferSize = 4;
    aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);
    for (int i = 0; i < 10; ++i)
        aether::onMessageReceived(ch, aether::SequenceNum{ static_cast<std::uint16_t>(i) }, aether::Bytes{ 0x01 }, aether::MonoTime{ 0 });
    assert(static_cast<int>(ch.receiveBuffer.size()) == 4 && ch.totalDropped == 6);   // bounded at the cap; the excess 6 shed + counted
    std::printf("aether receive-cap OK: undrained buffer bounded at the cap, excess counted as dropped\n");
}

void testResumeProof() {
    const aether::NetworkConfig cfg;
    const aether::Address addrA = aether::addrLocalhost(5555), addrB = aether::addrLocalhost(6666), addrF = aether::addrLocalhost(7777);
    const aether::PeerId  idA{ addrA }, idB{ addrB }, idF{ addrF };
    aether::NetPeer A = aether::newPeerState(addrA, cfg, aether::MonoTime{ 0 });
    aether::NetPeer B = aether::newPeerState(addrB, cfg, aether::MonoTime{ 3 });

    std::vector<aether::IncomingPacket> toA, toB;
    std::uint64_t t = 0;
    aether::peerConnect(A, idB, aether::MonoTime{ t });
    bool aUp = false, bUp = false;
    for (int tick = 0; tick < 16 && !(aUp && bUp); ++tick) {
        t += 1000000;
        const auto ra = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        const auto rb = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();
        for (const auto& p : ra.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toB.push_back(aether::IncomingPacket{ idA, *s });
        for (const auto& p : rb.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
        for (const auto& e : ra.events) if (e.kind == aether::PeerEvent::Connected) aUp = true;
        for (const auto& e : rb.events) if (e.kind == aether::PeerEvent::Connected) bUp = true;
    }
    assert(aUp && bUp);
    const auto token = aether::peerSessionToken(A, idB);
    assert(token);

    t += 11000ull * 1000000;   // both time out -> server caches the resumable (token -> master)
    aether::peerProcess(A, aether::MonoTime{ t }, {});
    aether::peerProcess(B, aether::MonoTime{ t }, {});
    assert(B.resumableTokens.count(*token) == 1);

    // forger replays the (observed) token with a bogus MAC -- it never held the master
    std::array<std::uint8_t, 16> badMac{};   // all-zero: not a valid tag
    const aether::Bytes forged = aether::serializePacket(aether::Packet{
        aether::PacketHeader{ aether::PacketType::ConnectionRequest, aether::SequenceNum{ 0 }, aether::SequenceNum{ 0 }, 0 },
        aether::encodeConnectionRequest({}, aether::encodeResume(*token, 0x1234u, badMac)) });
    t += 1000000;
    const auto rf = aether::peerProcess(B, aether::MonoTime{ t }, { aether::IncomingPacket{ idF, forged } });
    for (const auto& e : rf.events) assert(e.kind != aether::PeerEvent::Reconnected);
    assert(!aether::peerIsConnected(B, idF));          // forger got a fresh-handshake pending at most, never the session
    assert(B.resumableTokens.count(*token) == 1);      // NOT burned -> the real client can still resume

    aether::peerReconnect(A, idB, *token, aether::MonoTime{ t });   // legit client holds the master
    bool reconnected = false;
    for (int rc = 0; rc < 16 && !(reconnected && aether::peerIsConnected(A, idB)); ++rc) {
        t += 1000000;
        const auto ra = aether::peerProcess(A, aether::MonoTime{ t }, toA); toA.clear();
        const auto rb = aether::peerProcess(B, aether::MonoTime{ t }, toB); toB.clear();
        for (const auto& p : ra.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toB.push_back(aether::IncomingPacket{ idA, *s });
        for (const auto& p : rb.outgoing) if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
        for (const auto& e : rb.events) if (e.kind == aether::PeerEvent::Reconnected) reconnected = true;
    }
    assert(reconnected && aether::peerIsConnected(A, idB));
    std::printf("aether resume-mac OK: forged reconnect rejected (token not burned), real client still resumes\n");
}

void testHalfOpenCapacity() {
    aether::NetworkConfig cfg;
    cfg.maxPending = 3;
    cfg.maxClients = 64;                                          // deliberately != maxPending, to prove which one caps pending
    aether::NetPeer S = aether::newPeerState(aether::addrAny(7200), cfg, aether::MonoTime{ 0 });
    const auto rawRequest = [](const aether::Bytes& payload) {
        return aether::serializePacket(aether::Packet{
            aether::PacketHeader{ aether::PacketType::ConnectionRequest, aether::SequenceNum{ 0 }, aether::SequenceNum{ 0 }, 0 }, payload });
    };
    for (int i = 0; i < 10; ++i) {                                // 10 distinct sources, each walking the retry-cookie exchange
        const aether::PeerId from{ aether::addrV4(0x0B000000u + static_cast<std::uint32_t>(i), 5000) };
        // uncookied first: earns a cookie and commits nothing
        const auto r = aether::peerProcess(S, aether::MonoTime{ 1000000 },
            { aether::IncomingPacket{ from, rawRequest(aether::encodeConnectionRequest({}, {})) } });
        assert(r.outgoing.size() == 1);
        const auto stripped = aether::validateAndStripCrc32(r.outgoing[0].data);
        assert(stripped);
        const auto retry = aether::deserializePacket(*stripped);
        assert(retry && retry->header.type == aether::PacketType::ConnectionRetry);
        // ...then echo it, which is what actually opens a pending
        aether::peerProcess(S, aether::MonoTime{ 1000000 },
            { aether::IncomingPacket{ from, rawRequest(aether::encodeConnectionRequest(retry->payload, {})) } });
    }
    assert(static_cast<int>(S.pending.size()) == cfg.maxPending);   // capped at maxPending (3), not maxClients (64)
    std::printf("aether maxPending OK: half-open table capped at %d (distinct from maxClients)\n", cfg.maxPending);
}

void testRendezvousCapacity() {
    aether::RendezvousServer rv;
    rv.maxRooms = 4;
    for (int i = 0; i < 32; ++i) {                                // 32 distinct rooms from 32 distinct sources -> all wait, none pair
        const aether::Address src = aether::addrV4(0x0C000000u + static_cast<std::uint32_t>(i), 6000);
        aether::rendezvousProcess(rv, { { src, aether::encodeRegister(2000ull + static_cast<std::uint64_t>(i)) } }, aether::MonoTime{ 0 });
    }
    assert(static_cast<int>(rv.waiting.size()) <= rv.maxRooms);     // bounded, not unbounded growth
    std::printf("aether rendezvous cap OK: waiting table held at <= %d under a 32-room flood\n", rv.maxRooms);
}

void testMigrationRateLimit() {
    aether::NetworkConfig cfg;
    cfg.rateLimitPerSecond = 5;
    aether::NetPeer S = aether::newPeerState(aether::addrAny(7300), cfg, aether::MonoTime{ 0 });
    const aether::PeerId from{ aether::addrV4(0x0D000001u, 7000) };
    std::vector<aether::IncomingPacket> flood;
    for (int i = 0; i < 20; ++i) {
        const aether::Bytes p = aether::serializePacket(aether::Packet{
            aether::PacketHeader{ aether::PacketType::Payload, aether::SequenceNum{ static_cast<std::uint16_t>(i) }, aether::SequenceNum{ 0 }, 0 },
            aether::Bytes(30, 0x5A) });
        flood.push_back(aether::IncomingPacket{ from, p });
    }
    aether::peerProcess(S, aether::MonoTime{ 1000000 }, flood);
    assert(S.rateLimitDrops > 0 && !aether::peerIsConnected(S, from));   // flood shed past the per-source limit; nothing connected
    std::printf("aether migration rate-limit OK: %llu spoofed attempts shed, no trial-decrypt storm\n",
                static_cast<unsigned long long>(S.rateLimitDrops));
}

void testSelectiveFragmentRetransmission() {
    aether::NetworkConfig cfg;                      // default 1200 MTU -> ~1156-byte chunks
    aether::ChannelConfig cc = aether::reliableOrderedChannel();
    cc.maxMessageSize = 16384;
    cfg.defaultChannelConfig = cc;
    assert(!aether::validateConfig(cfg));

    aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cc);
    const auto sr = aether::channelSend(ch, aether::Bytes(5000, 0xAB), aether::MonoTime{ 0 });
    assert(sr.error == aether::ChannelError::None);

    // First send: nothing is acked and the channel has not recorded a fragment count yet, so every
    // fragment is rendered, each tagged with its own index.
    const aether::ChannelMessage* peek = aether::peekOutgoingMessage(ch);
    assert(peek);
    const aether::MessageWires first = aether::buildMessageWires(cfg, aether::ChannelId{ 0 }, *peek);
    assert(first.ok && first.fragmentCount > 1);
    assert(first.wires.size() == first.fragmentCount);
    for (std::size_t i = 0; i < first.wires.size(); ++i) assert(first.wires[i].fragIndex == i);

    aether::commitOutgoingMessage(ch, sr.seq, aether::MonoTime{ 0 });
    ch.sendBuffer.at(sr.seq).fragmentCount = first.fragmentCount;

    // Every fragment lands except index 2.
    constexpr std::uint8_t missing = 2;
    for (std::uint8_t i = 0; i < first.fragmentCount; ++i)
        if (i != missing) aether::acknowledgeMessage(ch, sr.seq, i);
    const aether::ChannelMessage& stored = ch.sendBuffer.at(sr.seq);
    assert(!stored.acked);                                  // one piece short of complete
    assert(!aether::fragmentAcked(stored, missing) && aether::fragmentAcked(stored, 0));

    // The retransmit render carries exactly the missing fragment -- and still reports the message's
    // TOTAL fragment count, which is what the channel needs to know when it is finally whole.
    const aether::MessageWires again = aether::buildMessageWires(cfg, aether::ChannelId{ 0 }, stored);
    assert(again.ok && again.wires.size() == 1);
    assert(again.wires[0].fragIndex == missing);
    assert(again.fragmentCount == first.fragmentCount);
    assert(again.wires[0].data == first.wires[missing].data);   // byte-identical to the piece that was lost

    // Acking the last one completes it, and there is then nothing left to resend.
    aether::acknowledgeMessage(ch, sr.seq, missing);
    assert(ch.sendBuffer.at(sr.seq).acked);
    const aether::MessageWires complete = aether::buildMessageWires(cfg, aether::ChannelId{ 0 }, ch.sendBuffer.at(sr.seq));
    assert(complete.wires.empty());
    std::printf("aether selective-retransmit OK: %u-fragment message resends 1 wire, not %u\n",
                static_cast<unsigned>(first.fragmentCount), static_cast<unsigned>(first.fragmentCount));
}

void testFragmentPacing() {
    aether::NetworkConfig cfg;
    cfg.sendRate      = 5.0;    // bucket: 6KB at base rate...
    cfg.maxPacketRate = 10.0;   // ...12KB at the AIMD peak
    aether::ChannelConfig cc = aether::reliableOrderedChannel();
    cc.maxMessageSize        = 30000;   // ~27 fragments, ~30KB of wire: more than TWO peak buckets
    cfg.defaultChannelConfig = cc;
    assert(!aether::validateConfig(cfg));

    aether::Connection conn = aether::newConnection(cfg, 1, aether::MonoTime{ 0 });
    aether::markConnected(conn, aether::MonoTime{ 0 });
    const auto sendErr = aether::sendMessage(conn, aether::ChannelId{ 0 }, aether::Bytes(30000, 0x7E), aether::MonoTime{ 0 });
    assert(!sendErr);

    aether::updateConnectedPure(conn, aether::MonoTime{ 1000000 });   // first tick: the bucket seeds full (6KB) -> ~5 fragments
    aether::Channel& ch = conn.channels[0];
    const aether::ChannelMessage& msg = ch.sendBuffer.begin()->second;
    assert(msg.fragmentCount > 1);                    // total recorded up front: an early ack must see it
    assert(msg.sentFragments > 0);                    // some fragments went out...
    assert(msg.sentFragments < msg.fragmentCount);    // ...but not all: the message exceeds the bucket
    assert(msg.retryCount == 0);                      // not committed until fully emitted
    const std::uint8_t afterFirst = msg.sentFragments;

    aether::updateConnectedPure(conn, aether::MonoTime{ 1000001 });   // no time passed -> no budget earned -> no progress
    assert(msg.sentFragments == afterFirst);

    // Budget accrues with time; the message finishes over later ticks and only then commits, with
    // the RTO clock starting at completion. Count what was actually emitted: exactly one wire per
    // fragment, no re-sends and no gaps.
    std::size_t   payloadPackets = 0;
    std::uint64_t t              = 1000001;
    for (const auto& pkt : aether::drainSendQueue(conn))
        if (pkt.type == aether::PacketType::Payload || pkt.type == aether::PacketType::PayloadBatch) ++payloadPackets;
    for (int tick = 0; tick < 100 && msg.retryCount == 0; ++tick) {
        t += 500000000;   // 500ms: at 5 pkts/s each tick earns ~2.5 fragments of budget
        aether::updateConnectedPure(conn, aether::MonoTime{ t });
        for (const auto& pkt : aether::drainSendQueue(conn))
            if (pkt.type == aether::PacketType::Payload || pkt.type == aether::PacketType::PayloadBatch) ++payloadPackets;
    }
    assert(msg.retryCount == 1);                         // fully emitted + committed
    assert(msg.sentFragments == msg.fragmentCount);
    assert(msg.sendTime.ns == t);                        // RTO runs from emission completion, not channelSend
    assert(payloadPackets == msg.fragmentCount);         // every fragment exactly once (each fills its own datagram)
    std::printf("aether fragment-pacing OK: %u-fragment message emitted over ticks (%u after one bucket), one wire each\n",
                static_cast<unsigned>(msg.fragmentCount), static_cast<unsigned>(afterFirst));
}

void testPacedMessageDelivery() {
    aether::NetworkConfig cfg;
    cfg.sendRate      = 20.0;   // 24KB bucket
    cfg.maxPacketRate = 40.0;
    aether::ChannelConfig cc = aether::reliableOrderedChannel();
    cc.maxMessageSize        = 60000;   // ~52 fragments, ~2.5 buckets
    cfg.defaultChannelConfig = cc;
    assert(!aether::validateConfig(cfg));

    const aether::Address addrA = aether::addrLocalhost(8811), addrB = aether::addrLocalhost(8812);
    const aether::PeerId  idA{ addrA }, idB{ addrB };
    aether::NetPeer A = aether::newPeerState(addrA, cfg, aether::MonoTime{ 0 });
    aether::NetPeer B = aether::newPeerState(addrB, cfg, aether::MonoTime{ 0 });
    aether::peerConnect(A, idB, aether::MonoTime{ 0 });

    aether::TestLink link = aether::newTestLink(A, idA, B, idB);
    aether::MonoTime t    = aether::testLinkConnect(link, aether::MonoTime{ 0 }, 1000000, 40);
    assert(aether::peerIsConnected(A, idB));

    aether::Bytes big(60000);
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<std::uint8_t>(i * 31u);
    const auto err = aether::peerSend(A, idB, aether::ChannelId{ 0 }, big, t);
    assert(!err);

    aether::Bytes received;
    aether::testLinkRun(link, t, 10000000 /*10ms*/, 600, [&](aether::TestLinkStep step) {
        for (aether::PeerEvent& e : step.bEvents)
            if (e.kind == aether::PeerEvent::Message) received = std::move(e.data);
        return !received.empty();
    });
    assert(received == big);   // reassembled exactly, from an emission spread over many ticks
    std::printf("aether pacing-e2e OK: %zu-byte message (>2 send buckets) delivered whole\n", big.size());
}

void testAdaptiveDeltaMask() {
    struct Wide {
        std::uint8_t f00, f01, f02, f03, f04, f05, f06, f07, f08, f09;
        std::uint8_t f10, f11, f12, f13, f14, f15, f16, f17, f18, f19;
    };
    static_assert(aether::fieldCount<Wide>() == 20);
    std::uint8_t buf[64];
    const Wide base{};
    const auto deltaBytes = [&](const Wide& to) {
        aether::Writer w{ buf, sizeof buf, 0, true };
        aether::deltaPack(w, base, to);
        aether::Reader r{ buf, w.pos, 0 };
        const auto back = aether::deltaUnpack(r, base);
        assert(back && std::memcmp(&*back, &to, sizeof(Wide)) == 0);   // every form reconstructs exactly
        return w.pos;
    };
    Wide w1 = base; w1.f07 = 9;
    Wide w2 = w1;   w2.f19 = 5;
    Wide w3 = w2;   w3.f00 = 1;
    Wide all{};
    std::uint8_t* ab = reinterpret_cast<std::uint8_t*>(&all);
    for (std::size_t k = 0; k < sizeof(Wide); ++k) ab[k] = static_cast<std::uint8_t>(k + 1);
    assert(deltaBytes(base) == 1);   // nothing changed: one mode byte, not a 3-byte zero bitmap
    assert(deltaBytes(w1)   == 3);   // 1 change:  mode + index + value   (bitmap would be 4+)
    assert(deltaBytes(w2)   == 5);   // 2 changes: mode + 2 idx + 2 values
    assert(deltaBytes(w3)   == 7);   // 3 changes == bitmap bytes: mode + 3-byte bitmap + 3 values
    assert(deltaBytes(all)  == 24);  // everything: mode + bitmap + 20 values

    // Hostile wire forms: each is decodable-looking but non-canonical or malformed -> nullopt.
    const auto rejects = [&](std::initializer_list<std::uint8_t> bytes) {
        const aether::Bytes hostile(bytes);
        aether::Reader r{ hostile.data(), hostile.size(), 0 };
        return !aether::deltaUnpack(r, base).has_value();
    };
    assert(rejects({ 0x03, 0x01, 0x02, 0x03, 0x09, 0x09, 0x09 }));   // sparse count == bitmap bytes: always sent as bitmap
    assert(rejects({ 0x02, 0x05, 0x03, 0x09, 0x09 }));               // indices not ascending
    assert(rejects({ 0x02, 0x05, 0x05, 0x09, 0x09 }));               // duplicate index
    assert(rejects({ 0x01, 0x14, 0x09 }));                           // index 20 out of range (fields 0..19)
    assert(rejects({ 0x01 }));                                       // truncated: promised index missing
    assert(rejects({ 0xFF, 0x03, 0x00, 0x00, 0x09, 0x09 }));         // bitmap with 2 bits: always sent sparse
    assert(rejects({ 0xFF, 0xFF, 0xFF, 0xFF }));                     // bitmap padding bits set (fields stop at 19)
    std::printf("aether adaptive-mask OK: sparse 1/20 costs 3 bytes (was 4), canonical-form rejection holds\n");
}

void testAssemblyIdleExpiry() {
    aether::FragmentAssembler a = aether::newFragmentAssembler(100.0, 1 << 20, 16);
    std::uint8_t frag[aether::fragmentHeaderSize + 8]{};
    const auto feed = [&](std::uint8_t idx, std::uint64_t atMs) {
        aether::writeFragmentHeader(frag, aether::FragmentHeader{ aether::MessageId{ 9 }, idx, 3 });
        return aether::processFragment(a, frag, sizeof frag, aether::MonoTime{ atMs * 1000000 });
    };
    assert(!feed(0, 0));
    assert(!feed(1, 80));                  // 80ms gap: inside the idle window
    const auto done = feed(2, 160);        // total age 160ms > the 100ms timeout -- but never idle
    assert(done && done->size() == 24);    // completes; total-age expiry would have dropped it at 100ms

    assert(!feed(0, 1000));                // a fresh assembly...
    assert(!feed(1, 1300));                // ...that went 300ms with nothing new: expired, this re-opens it
    assert(a.buffers.at(aether::MessageId{ 9 }).fragments.size() == 1);   // only the re-opening fragment held
    std::printf("aether fragment-idle-expiry OK: advancing assembly outlives the timeout, stalled one expires\n");
}

void testOrderedBufferBackpressure() {
    aether::NetworkConfig cfg;
    cfg.defaultChannelConfig                      = aether::reliableOrderedChannel();
    cfg.defaultChannelConfig.maxOrderedBufferSize = 4;       // small, so the overrun is reached at once
    cfg.defaultChannelConfig.orderedBufferTimeout = 1.0e9;   // never: the give-up flush must not mask it
    assert(!aether::validateConfig(cfg));

    const aether::Address addrA = aether::addrLocalhost(8801), addrB = aether::addrLocalhost(8802);
    const aether::PeerId  idA{ addrA }, idB{ addrB };
    aether::NetPeer A = aether::newPeerState(addrA, cfg, aether::MonoTime{ 0 });
    aether::NetPeer B = aether::newPeerState(addrB, cfg, aether::MonoTime{ 0 });
    aether::peerConnect(A, idB, aether::MonoTime{ 0 });

    aether::TestLink link = aether::newTestLink(A, idA, B, idB);
    aether::MonoTime t    = aether::testLinkConnect(link, aether::MonoTime{ 0 }, 1000000, 40);
    assert(aether::peerIsConnected(A, idB) && aether::peerIsConnected(B, idA));

    constexpr int total = 30;
    int  sent = 0, delivered = 0;
    bool droppedFirst = false;
    std::vector<aether::IncomingPacket> toA, toB;
    for (int tick = 0; tick < 3000 && delivered < total; ++tick) {
        t = aether::MonoTime{ t.ns + 1000000 };
        while (sent < total) {                                   // fill the pipeline as fast as it accepts
            const aether::Bytes payload{ static_cast<std::uint8_t>(sent) };
            if (aether::peerSend(A, idB, aether::ChannelId{ 0 }, payload, t)) break;   // BufferFull: next tick
            ++sent;
        }
        const auto ra = aether::peerProcess(A, t, toA); toA.clear();
        const auto rb = aether::peerProcess(B, t, toB); toB.clear();
        for (const auto& p : ra.outgoing) {
            auto s = aether::validateAndStripCrc32(p.data);
            if (!s) continue;
            const auto pkt = aether::deserializePacket(*s);
            const bool isPayload = pkt && (pkt->header.type == aether::PacketType::Payload
                                        || pkt->header.type == aether::PacketType::PayloadBatch);
            if (isPayload && !droppedFirst) { droppedFirst = true; continue; }   // the one and only loss
            toB.push_back(aether::IncomingPacket{ idA, *s });
        }
        for (const auto& p : rb.outgoing)
            if (auto s = aether::validateAndStripCrc32(p.data)) toA.push_back(aether::IncomingPacket{ idB, *s });
        for (const auto& e : rb.events)
            if (e.kind == aether::PeerEvent::Message) ++delivered;
    }
    assert(sent == total);
    assert(delivered == total);   // was 20 of 30: the overrun silently ate a run of messages
    const auto& chB = B.connections.at(idA).channels[0];
    assert(chB.totalRefused > 0);    // the overrun really happened...
    assert(chB.totalDropped == 0);   // ...and cost nothing: refusals are backpressure, not loss
    std::printf("aether reliable-overrun OK: %d/%d delivered through a reorder-buffer overrun "
                "(%llu refusals, %llu duplicates, 0 dropped)\n", delivered, total,
                static_cast<unsigned long long>(chB.totalRefused),
                static_cast<unsigned long long>(chB.totalDuplicate));
}

void testDisconnectReason() {
    const aether::NetworkConfig cfg;
    const aether::Address addrS = aether::addrLocalhost(7501), addrC = aether::addrLocalhost(7502);
    const aether::PeerId  idS{ addrS }, idC{ addrC };
    aether::NetPeer S = aether::newPeerState(addrS, cfg, aether::MonoTime{ 0 });
    aether::NetPeer C = aether::newPeerState(addrC, cfg, aether::MonoTime{ 0 });
    aether::peerConnect(C, idS, aether::MonoTime{ 0 });

    aether::TestLink link = aether::newTestLink(C, idC, S, idS);
    aether::MonoTime t    = aether::testLinkConnect(link, aether::MonoTime{ 0 }, 1000000, 24);
    assert(aether::peerIsConnected(S, idC) && aether::peerIsConnected(C, idS));

    aether::peerDisconnect(S, idC, t, aether::DisconnectReason::Kicked);
    aether::DisconnectReason seen = aether::DisconnectReason::Requested;
    bool dropped = false;
    aether::testLinkRun(link, t, 1000000, 8, [&](const aether::TestLinkStep& s) {
        for (const auto& e : s.aEvents)
            if (e.kind == aether::PeerEvent::Disconnected) { seen = e.reason; dropped = true; }
        return dropped;
    });
    assert(dropped && seen == aether::DisconnectReason::Kicked);   // the client learns it was kicked
    std::printf("aether disconnect-reason OK: a kick arrives as Kicked, not a generic close\n");
}

void testBandwidthDecay() {
    const aether::NetworkConfig cfg;
    aether::Connection conn = aether::newConnection(cfg, 1, aether::MonoTime{ 0 });
    aether::markConnected(conn, aether::MonoTime{ 0 });

    aether::recordBytesSent(conn, 6000, aether::MonoTime{ 0 });
    aether::recordBytesReceived(conn, 3000, aether::MonoTime{ 0 });
    aether::updateTick(conn, aether::MonoTime{ 1000000 });                  // 1ms later: inside the window
    assert(conn.stats.bandwidthUp > 0.0 && conn.stats.bandwidthDown > 0.0);

    // Idle well past the 1s window. Sends nothing, so nothing prunes the window on record.
    aether::updateTick(conn, aether::MonoTime{ 3000ull * 1000000 });
    assert(conn.stats.bandwidthUp == 0.0 && conn.stats.bandwidthDown == 0.0);
    std::printf("aether bandwidth-decay OK: an idle connection reports 0 B/s, not its last burst\n");
}

void testDatagramFraming() {
    aether::EncryptionKey key{};
    for (int i = 0; i < 32; ++i) key[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(i * 11 + 3);
    constexpr std::uint32_t protocolId = 0xFEEDBEEFu;
    const aether::PacketHeader header{ aether::PacketType::PayloadBatch, aether::SequenceNum{ 4242 },
                                       aether::SequenceNum{ 4200 }, 0x0F0F0F0Fu };
    const aether::NonceCounter counter{ 99 };
    const aether::Bytes payload = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    // cleartext: header || payload || crc
    const aether::Bytes clearRef   = aether::appendCrc32(aether::serializePacket(aether::Packet{ header, payload }));
    const aether::Bytes clearBuilt = aether::frameCleartextDatagram(header, payload);
    assert(clearBuilt == clearRef);

    // keyed: header || counter || ciphertext || tag || crc
    const aether::Bytes serialized = aether::serializePacket(aether::Packet{ header, payload });
    aether::Bytes combined(serialized.begin(), serialized.begin() + static_cast<std::ptrdiff_t>(aether::packetHeaderBytes));
    const aether::Bytes enc = aether::encrypt(key, counter, protocolId,
                                              serialized.data(), aether::packetHeaderBytes,
                                              serialized.data() + aether::packetHeaderBytes,
                                              serialized.size() - aether::packetHeaderBytes);
    combined.insert(combined.end(), enc.begin(), enc.end());
    const aether::Bytes sealedRef   = aether::appendCrc32(combined);
    const aether::Bytes sealedBuilt = aether::sealDatagram(key, counter, protocolId, header, payload);
    assert(sealedBuilt == sealedRef);

    // ...and it round-trips through the real receive path: CRC, header, then decrypt under the header
    // as AAD, which is the check that the AAD really covers the bytes that were written.
    const auto stripped = aether::validateAndStripCrc32(sealedBuilt);
    assert(stripped);
    aether::Reader rr{ stripped->data(), stripped->size(), 0 };
    const auto gotHeader = aether::readHeader(rr);
    assert(gotHeader && gotHeader->sequence == header.sequence && gotHeader->ack == header.ack
           && gotHeader->ackBits == header.ackBits && gotHeader->type == header.type);
    const auto opened = aether::decrypt(key, protocolId, stripped->data(), aether::packetHeaderBytes,
                                        stripped->data() + aether::packetHeaderBytes,
                                        stripped->size() - aether::packetHeaderBytes);
    assert(opened && opened->plaintext == payload && opened->counter.value == counter.value);
    std::printf("aether datagram-framing OK: one-allocation build is byte-identical to the composed form\n");
}

void testAllocationFreePrimitives() {
    aether::EncryptionKey key{};
    for (int i = 0; i < 32; ++i) key[i] = static_cast<std::uint8_t>(i * 7 + 1);
    const std::uint8_t   aad[9] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const aether::Bytes  pt     = { 10, 20, 30, 40, 50 };
    const aether::Bytes  enc    = aether::encrypt(key, aether::NonceCounter{ 123 }, 0xABCDu, aad, sizeof aad, pt.data(), pt.size());

    const auto ref = aether::decrypt(key, 0xABCDu, aad, sizeof aad, enc.data(), enc.size());   // owning reference
    assert(ref && ref->plaintext == pt && ref->counter.value == 123);

    std::vector<std::uint8_t> out(enc.size());                                                 // decryptInto must match
    const auto info = aether::decryptInto(key, 0xABCDu, aad, sizeof aad, enc.data(), enc.size(), out.data());
    assert(info && info->length == pt.size() && info->counter.value == 123);
    assert(aether::Bytes(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(info->length)) == pt);

    aether::Bytes bad = enc; bad.back() ^= 0xFFu;                                               // tampered tag -> rejected, out untouched
    assert(!aether::decryptInto(key, 0xABCDu, aad, sizeof aad, bad.data(), bad.size(), out.data()));

    const aether::Bytes framed = aether::appendCrc32(aether::Bytes{ 9, 8, 7, 6, 5 });           // crc32StrippedLen must match validateAndStripCrc32
    const auto slen = aether::crc32StrippedLen(framed.data(), framed.size());
    assert(slen && *slen == 5);
    aether::Bytes corrupt = framed; corrupt[0] ^= 0xFFu;
    assert(!aether::crc32StrippedLen(corrupt.data(), corrupt.size()));
    std::printf("aether zero-copy primitives OK: decryptInto + crc32StrippedLen match the owning forms\n");
}

struct TestCase { const char* name; void (*run)(); };

} // namespace

int main() {
    const TestCase cases[] = {
        {"Foundation", testFoundation},
        {"PacketHeader", testPacketHeader},
        {"NestedSerialization", testNestedSerialization},
        {"MemcpyWireLayout", testMemcpyWireLayout},
        {"UdpLoopback", testUdpLoopback},
        {"PacketAcknowledgements", testPacketAcknowledgements},
        {"LossAccounting", testLossAccounting},
        {"ReliableSendPipelining", testReliableSendPipelining},
        {"RetransmitCommit", testRetransmitCommit},
        {"AckWindowBoundary", testAckWindowBoundary},
        {"NonceReplayWindow", testNonceReplayWindow},
        {"SendBackpressure", testSendBackpressure},
        {"AssemblyCountLimit", testAssemblyCountLimit},
        {"AssemblyByteLimit", testAssemblyByteLimit},
        {"MonotonicTimeSaturation", testMonotonicTimeSaturation},
        {"ConfigurationValidation", testConfigurationValidation},
        {"OversizedMessageFailure", testOversizedMessageFailure},
        {"ConfigurationPropagation", testConfigurationPropagation},
        {"FragmentRoundtrip", testFragmentRoundtrip},
        {"OrderedReceive", testOrderedReceive},
        {"BitSerialization", testBitSerialization},
        {"FieldDeltas", testFieldDeltas},
        {"VectorDecodeBounds", testVectorDecodeBounds},
        {"BoolSerialization", testBoolSerialization},
        {"FloatDeltaBits", testFloatDeltaBits},
        {"AeadVector", testAeadVector},
        {"HChaChaVector", testHChaChaVector},
        {"DirectionalKeys", testDirectionalKeys},
        {"PacketEncryption", testPacketEncryption},
        {"X25519Vectors", testX25519Vectors},
        {"SystemRandomness", testSystemRandomness},
        {"CongestionAndBatching", testCongestionAndBatching},
        {"ConfigurationAndQuality", testConfigurationAndQuality},
        {"ConnectionDelivery", testConnectionDelivery},
        {"MessageCoalescing", testMessageCoalescing},
        {"ClockOffset", testClockOffset},
        {"ReliableDeliveryWithLoss", testReliableDeliveryWithLoss},
        {"PacketCodecAndPrng", testPacketCodecAndPrng},
        {"CrcAndTokenValidation", testCrcAndTokenValidation},
        {"DynamicFields", testDynamicFields},
        {"ReplayAndQuantizationEdges", testReplayAndQuantizationEdges},
        {"PeerHandshake", testPeerHandshake},
        {"AddressMigration", testAddressMigration},
        {"MigrationReplayChallenge", testMigrationReplayChallenge},
        {"TokenAdmission", testTokenAdmission},
        {"ReplicationHelpers", testReplicationHelpers},
        {"RendezvousCodec", testRendezvousCodec},
        {"RendezvousPairing", testRendezvousPairing},
        {"RendezvousRelay", testRendezvousRelay},
        {"RendezvousExpiry", testRendezvousExpiry},
        {"UdpHandshake", testUdpHandshake},
        {"UdpRendezvousPunch", testUdpRendezvousPunch},
        {"RendezvousRegisterRetry", testRendezvousRegisterRetry},
        {"UdpRelayHandshake", testUdpRelayHandshake},
        {"StringLengthOverflow", testStringLengthOverflow},
        {"ReceiveMessageSize", testReceiveMessageSize},
        {"ChannelCapacityValidation", testChannelCapacityValidation},
        {"OrderedGapFailureAcrossWrap", testOrderedGapFailureAcrossWrap},
        {"FragmentDeliveryWithLoss", testFragmentDeliveryWithLoss},
        {"CongestionWindowWithLoss", testCongestionWindowWithLoss},
        {"ReceiveBufferLimit", testReceiveBufferLimit},
        {"ResumeProof", testResumeProof},
        {"HalfOpenCapacity", testHalfOpenCapacity},
        {"RendezvousCapacity", testRendezvousCapacity},
        {"MigrationRateLimit", testMigrationRateLimit},
        {"SelectiveFragmentRetransmission", testSelectiveFragmentRetransmission},
        {"FragmentPacing", testFragmentPacing},
        {"PacedMessageDelivery", testPacedMessageDelivery},
        {"AdaptiveDeltaMask", testAdaptiveDeltaMask},
        {"AssemblyIdleExpiry", testAssemblyIdleExpiry},
        {"OrderedBufferBackpressure", testOrderedBufferBackpressure},
        {"DisconnectReason", testDisconnectReason},
        {"BandwidthDecay", testBandwidthDecay},
        {"DatagramFraming", testDatagramFraming},
        {"AllocationFreePrimitives", testAllocationFreePrimitives},
    };
    for (const auto& test : cases) {
        std::printf("Running %s\n", test.name);
        std::fflush(stdout);
        test.run();
    }
    return 0;
}
