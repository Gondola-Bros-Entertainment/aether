// Foundation smoke test: round-trip a struct through the little-endian cursor (free
// functions, data-first), and check sequence-number wraparound. No allocation.
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
#include "aether/types.hpp"
#include "aether/util.hpp"
#include "aether/x25519.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>

struct PlayerState {
    float               x{}, y{};
    std::uint8_t        health{};
    aether::SequenceNum seq{};
};

struct Vec3   { float x, y, z; };
struct Entity { Vec3 pos; std::uint32_t id; std::uint8_t hp; aether::ChannelId ch; };

int main() {
    const PlayerState in{ 1.5f, -2.25f, 200, aether::SequenceNum{65535} };

    std::uint8_t buf[64];
    aether::Writer w{ buf, sizeof buf, 0, true };
    write(w, in.x);
    write(w, in.y);
    write(w, in.health);
    write(w, in.seq.value);
    assert(w.ok);

    aether::Reader r{ buf, w.pos, 0 };
    const auto x = aether::read<float>(r);
    const auto y = aether::read<float>(r);
    const auto h = aether::read<std::uint8_t>(r);
    const auto s = aether::read<std::uint16_t>(r);
    assert(x && y && h && s);
    const PlayerState out{ *x, *y, *h, aether::SequenceNum{*s} };

    assert(out.x == in.x && out.y == in.y && out.health == in.health && out.seq == in.seq);

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
                static_cast<double>(out.x), static_cast<double>(out.y),
                static_cast<unsigned>(out.health), static_cast<unsigned>(out.seq.value), w.pos);

    // packet header: the bit-packed 9-byte header round-trips byte-exact
    {
        const aether::PacketHeader h{ aether::PacketType::Payload, aether::SequenceNum{40000},
                                      aether::SequenceNum{39999}, 0xDEADBEEFu };
        std::uint8_t pbuf[16];
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

    // generic serialization: a nested aggregate round-trips with zero boilerplate
    {
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

    // memcpy fast-path: for a trivially-copyable, no-padding struct on a little-endian target,
    // serialize() is one memcpy -- its wire must be byte-identical to the portable per-field path
    // so a big-endian peer on that path still interoperates.
    {
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

    // socket: bind a UDP socket on localhost, send a datagram to itself, receive it
    {
        auto sock = aether::openUdp(aether::addrLocalhost(0));   // ephemeral port
        assert(sock);
        const aether::Address self = aether::localAddr(*sock);
        const std::uint8_t msg[] = { 0xAB, 0xCD, 0xEF };
        const int sent = aether::sendTo(*sock, msg, self);
        assert(sent == 3);

        std::uint8_t rbuf[16];
        aether::Address from{};
        int got = 0;
        for (int i = 0; i < 10000 && got == 0; ++i) got = aether::recvFrom(*sock, rbuf, from);
        assert(got == 3 && rbuf[0] == 0xAB && rbuf[1] == 0xCD && rbuf[2] == 0xEF);
        std::printf("aether socket loopback OK: sent %d, recv %d on 127.0.0.1:%u\n",
                    sent, got, aether::addrPort(self));
        aether::closeSocket(*sock);
    }

    // reliability: send 3, peer acks all 3, verify acked + in-flight drops + RTT ~50ms
    {
        aether::ReliableEndpoint ep{};
        const aether::ChannelId ch{ 0 };
        for (int i = 0; i < 3; ++i) {
            const auto s = aether::nextSequence(ep);
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

    // fragment: split a 2500-byte message into MTU-sized pieces and reassemble it
    {
        aether::Bytes msg(2500);
        for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<std::uint8_t>(i * 31 + 7);
        const auto fr = aether::fragmentMessage(aether::MessageId{ 42 }, msg.data(), msg.size(), 1024);
        assert(!fr.tooMany && fr.fragments.size() == 3);

        aether::FragmentAssembler assembler = aether::newFragmentAssembler(5000.0, 1 << 20);
        std::optional<aether::Bytes> done;
        for (const auto& f : fr.fragments) {
            auto out = aether::processFragment(assembler, f.data(), f.size(), aether::MonoTime{ 0 });
            if (out) done = out;
        }
        assert(done && *done == msg);
        std::printf("aether fragment OK: 2500 bytes -> %zu fragments -> reassembled exact\n", fr.fragments.size());
    }

    // channel: reliable-ordered delivers in order even when packets arrive out of order
    {
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        const aether::Bytes m0{ 1 }, m1{ 2 }, m2{ 3 };
        aether::onMessageReceived(ch, aether::SequenceNum{ 0 }, m0, aether::MonoTime{ 0 });
        aether::onMessageReceived(ch, aether::SequenceNum{ 2 }, m2, aether::MonoTime{ 0 });   // arrives early
        aether::onMessageReceived(ch, aether::SequenceNum{ 1 }, m1, aether::MonoTime{ 0 });   // fills the gap
        const auto got = aether::channelReceive(ch);
        assert(got.size() == 3 && got[0] == m0 && got[1] == m1 && got[2] == m2);
        const auto acks = aether::takePendingAcks(ch);
        assert(acks.size() == 3);
        std::printf("aether channel OK: out-of-order [0,2,1] -> in-order [0,1,2], %zu acks\n", acks.size());
    }

    // bit-packed reflective serialize: the wire contract lives in the field types, so the
    // same logical packet that costs 14 bytes byte-aligned packs into 5, round-tripping exact.
    {
        struct Move {
            aether::Ranged<int, 0, 1023>       x;        // 10 bits
            aether::Ranged<int, 0, 1023>       y;        // 10 bits
            aether::Quantized<-1.0f, 1.0f, 12> aimYaw;   // 12 bits
            aether::Ranged<int, 0, 7>          button;   //  3 bits
            bool                               firing{};   //  1 bit
        };
        const Move in{ 512, 1000, 0.5f, 5, true };       // 36 bits -> 5 bytes

        std::uint8_t bb[16];
        aether::BitWriter bw{ bb, sizeof bb };
        const std::size_t packed = aether::packBits(bw, in);
        assert(bw.ok);

        aether::BitReader br{ bb, packed };
        const auto out = aether::unpackBits<Move>(br);
        assert(out);
        assert(out->x == 512 && out->y == 1000 && out->button == 5 && out->firing);
        const float dy = static_cast<float>(out->aimYaw) - static_cast<float>(in.aimYaw);
        assert(dy > -0.001f && dy < 0.001f);

        // same logical packet on the byte-aligned generic path, for comparison
        struct MovePlain { std::uint32_t x, y; float aimYaw; std::uint8_t button, firing; };
        std::uint8_t pb[32];
        aether::Writer pw{ pb, sizeof pb, 0, true };
        aether::serialize(pw, MovePlain{ 512, 1000, 0.5f, 5, 1 });
        std::printf("aether bitpack OK: bit-packed %zu bytes vs byte-path %zu bytes, round-trip exact\n",
                    packed, pw.pos);
    }

    // magic path: define a plain struct, get automatic delta snapshots -- zero annotations.
    // Only the field that changed since the last snapshot goes on the wire.
    {
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

    // crypto: RFC 8439 section 2.8.2 AEAD vector -- proves ChaCha20 + Poly1305 + construction.
    {
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
    // crypto: our packet encrypt/decrypt round-trips and rejects tampering.
    {
        aether::EncryptionKey key{};
        for (int i = 0; i < 32; ++i) key[i] = std::uint8_t(i * 7 + 1);
        const std::uint8_t payload[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        auto packet = aether::encrypt(key, aether::NonceCounter{ 42 }, 0x12345678u, payload, sizeof payload);
        auto back = aether::decrypt(key, 0x12345678u, packet.data(), packet.size());
        assert(back && back->counter.value == 42 && back->plaintext.size() == sizeof payload);
        assert(std::memcmp(back->plaintext.data(), payload, sizeof payload) == 0);
        packet[packet.size() - 1] ^= 0x01;   // tamper the tag
        assert(!aether::decrypt(key, 0x12345678u, packet.data(), packet.size()));
        std::printf("aether crypto OK: packet encrypt/decrypt round-trip + tamper rejected\n");
    }
    // X25519: RFC 7748 section 5.2 vector proves the field arithmetic + Montgomery ladder, then an
    // ECDH round-trip proves both sides derive the same shared secret.
    {
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
    // secure randomness: the OS CSPRNG fills the buffer and varies between calls (a sanity check,
    // not a proof of randomness quality -- that lives in the OS).
    {
        std::array<std::uint8_t, 32> r1{}, r2{};
        aether::secureRandomBytes(r1.data(), r1.size());
        aether::secureRandomBytes(r2.data(), r2.size());
        bool allZero = true;
        for (const auto x : r1) if (x != 0) allZero = false;
        assert(!allZero && r1 != r2);
        std::printf("aether random OK: OS CSPRNG fills + varies\n");
    }
    // congestion: window grows on ack in slow start, halves on loss; batching round-trips.
    {
        aether::CongestionWindow cw = aether::newCongestionWindow(1200);
        const double startCwnd = cw.cwnd;
        aether::cwOnSend(cw, 1200, aether::MonoTime{ 0 });
        assert(cw.bytesInFlight == 1200);
        aether::cwOnAck(cw, 1200);
        assert(cw.bytesInFlight == 0 && cw.cwnd > startCwnd);
        aether::cwOnLoss(cw);
        assert(cw.phase == aether::CongestionPhase::Recovery && cw.cwnd >= aether::minCwndBytes);

        const std::vector<aether::Bytes> msgs = { { 1, 2, 3 }, { 4, 5 }, { 6, 7, 8, 9 } };
        const auto batches = aether::batchMessages(msgs, 1200);
        assert(batches.size() == 1);
        const auto un = aether::unbatchMessages(batches[0]);
        assert(un && un->size() == 3 && (*un)[0] == aether::Bytes({ 1, 2, 3 }) && (*un)[2] == aether::Bytes({ 6, 7, 8, 9 }));
        std::printf("aether congestion OK: cwnd ack/loss + batch/unbatch %zu msgs round-trip\n", un->size());
    }
    // config + stats: defaults validate, a bad override is caught, quality assessment works.
    {
        assert(!aether::validateConfig(aether::NetworkConfig{}));
        aether::NetworkConfig bad;
        bad.fragmentThreshold = bad.mtu + 1;
        assert(aether::validateConfig(bad) == aether::ConfigError::FragmentThresholdExceedsMtu);
        assert(aether::assessConnectionQuality(20.0, 0.0)  == aether::ConnectionQuality::Excellent);
        assert(aether::assessConnectionQuality(600.0, 0.0) == aether::ConnectionQuality::Bad);
        std::printf("aether config/stats OK: defaults valid, bad config + quality assessment caught\n");
    }

    // connection: two endpoints (handshake skipped via markConnected) exchange a reliable
    // message end-to-end through the channel + reliability + send-queue pipeline.
    {
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
            aether::processIncomingHeader(b, pkt.header, aether::MonoTime{ 2000000 });
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

    // coalescing: several messages sent in one tick ride a single PayloadBatch packet, and the
    // receiver unbatches all of them -- fewer datagrams + auth tags, identical delivery.
    {
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
            aether::processIncomingHeader(b, pkt.header, aether::MonoTime{ 2000000 });
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

    // clock sync: recover a known clock offset from timestamped round-trips (Cristian's algorithm).
    {
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

    // reliable delivery under packet loss: a reliable message must reach b even when ~40% of
    // packets are dropped, by riding the ack + retransmit machinery. This is the test that makes
    // "tested" mean something on a lossy link, not just a clean localhost handshake.
    {
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
                aether::processIncomingHeader(to, pkt.header, now);
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

    // util + full packet codec: PRNG is deterministic; a whole packet round-trips.
    {
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

    // security: CRC32C matches the known vector + detects corruption; rate limit + token replay.
    {
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

        aether::TokenValidator tv = aether::newTokenValidator(5000.0, 100);
        const aether::ConnectToken tok = aether::newConnectToken(7, 5000.0, {}, aether::MonoTime{ 0 });
        const auto v1 = aether::validateToken(tv, tok, aether::MonoTime{ 1000000 });
        assert(!v1.error && v1.clientId == 7);
        const auto v2 = aether::validateToken(tv, tok, aether::MonoTime{ 2000000 });   // replay
        assert(v2.error == aether::TokenError::Replayed);
        std::printf("aether security OK: CRC32C vector + corruption detect + rate limit + token replay\n");
    }

    // dynamic fields: a struct with std::string / std::vector / std::optional round-trips through
    // the raw, varint, and delta paths (the serializer's new variable-length support).
    {
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

    // audit-fix verification: each correctness bug from the audit, pinned by a test.
    {
        // reliability: a fresh dedup buffer must NOT report seq 65535 as already-seen
        // (the old 0xFFFF sentinel collided with the real sequence 65535 once per wrap).
        aether::ReceivedBuffer rb;
        assert(!aether::rbExists(rb, aether::SequenceNum{ 65535 }));
        aether::rbInsert(rb, aether::SequenceNum{ 65535 });
        assert(aether::rbExists(rb, aether::SequenceNum{ 65535 }));
        assert(!aether::rbExists(rb, aether::SequenceNum{ 0 }));

        // security: a reconnect with a fresh token (same clientId, new createTime) is NOT a
        // replay; resending the exact same token is. (Old code keyed on clientId alone.)
        aether::TokenValidator tv = aether::newTokenValidator(10000.0, 64);
        const aether::ConnectToken t1 = aether::newConnectToken(42, 5000.0, {}, aether::MonoTime{ 0 });
        assert(!aether::validateToken(tv, t1, aether::MonoTime{ 1 }).error);
        assert(aether::validateToken(tv, t1, aether::MonoTime{ 2 }).error == aether::TokenError::Replayed);
        const aether::ConnectToken t2 = aether::newConnectToken(42, 5000.0, {}, aether::MonoTime{ 3 });
        assert(!aether::validateToken(tv, t2, aether::MonoTime{ 4 }).error);

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

    // peer: a full handshake (request -> challenge -> response -> accepted) over a simulated
    // link. Each side's CRC-framed output is validated + stripped, exactly like the IO layer.
    {
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

        // X25519: the handshake negotiated a session key on both sides, and they agree (ECDH) --
        // encrypted by default, no pre-shared key.
        assert(A.connections.at(idB).encryptionKey && B.connections.at(idA).encryptionKey);
        assert(*A.connections.at(idB).encryptionKey == *B.connections.at(idA).encryptionKey);
        std::printf("aether x25519-handshake OK: session key negotiated + agrees on both sides\n");

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
        const auto origKey = B.connections.at(idA).encryptionKey;   // the X25519 session key, pre-drop
        assert(origKey);                                            // encrypted before the drop
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
        // 0-RTT: the reconnect restored the negotiated key on both sides -- not a plaintext downgrade.
        assert(B.connections.at(idA).encryptionKey == origKey && A.connections.at(idB).encryptionKey == origKey);
        std::printf("aether reconnect OK: timed-out session re-established via token (0-RTT, encryption restored), server fired Reconnected\n");

        // peerShutdown drains a Disconnect packet per live connection, so a process that exits
        // immediately still notifies its peers instead of leaving them to time out.
        const auto closeA = aether::peerShutdown(A, aether::MonoTime{ t });
        assert(!closeA.empty());

        std::printf("aether peer OK: full handshake A<->B + graceful shutdown drains Disconnect\n");
    }

    // replication: interest filtering, priority budgeting, interpolation, and delta snapshots.
    {
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
        const auto enc0 = aether::deltaEncode(tr, 0, s0);
        const auto dec0 = aether::deltaDecode(bm, enc0);
        assert(dec0 && dec0->hp == 100 && dec0->x == 10 && dec0->y == 20);
        aether::pushBaseline(bm, 0, *dec0, aether::MonoTime{ 0 });
        aether::deltaOnAck(tr, 0);
        const Ent  s1{ 100, 11, 20 };
        const auto enc1 = aether::deltaEncode(tr, 1, s1);
        assert(enc1.size() < enc0.size());                    // delta beats full snapshot
        const auto dec1 = aether::deltaDecode(bm, enc1);
        assert(dec1 && dec1->hp == 100 && dec1->x == 11 && dec1->y == 20);
        std::printf("aether replication OK: interest + priority + interpolation + delta (full %zu B -> delta %zu B)\n",
                    enc0.size(), enc1.size());
    }

    // NAT rendezvous protocol: addresses + Register/Paired messages round-trip on the wire.
    {
        const aether::Address addr = aether::addrV4(0x01020304u, 9999);
        const aether::Bytes enc = aether::encodeAddr(addr);
        const auto back = aether::decodeAddr(enc.data(), enc.size());
        assert(back && aether::addrEqual(*back, addr));

        const auto room = aether::decodeRegister(aether::encodeRegister(0xABCDEF12u));
        assert(room && *room == 0xABCDEF12u);

        const auto pd = aether::decodePaired(aether::encodePaired(aether::PunchRole::Connect, addr));
        assert(pd && pd->first == aether::PunchRole::Connect && aether::addrEqual(pd->second, addr));
        std::printf("aether rendezvous-proto OK: address + Register/Paired round-trip\n");
    }

    // NAT rendezvous server: two peers registering for the same room get paired with correct roles.
    {
        aether::RendezvousServer rv;
        const aether::Address a = aether::addrV4(0x0A000001u, 1111);
        const aether::Address b = aether::addrV4(0x0A000002u, 2222);
        const auto out1 = aether::rendezvousProcess(rv, { { a, aether::encodeRegister(7) } });
        assert(out1.empty());                                  // A waits
        const auto out2 = aether::rendezvousProcess(rv, { { b, aether::encodeRegister(7) } });
        assert(out2.size() == 2);                              // B's arrival pairs them
        const auto pa = aether::decodePaired(out2[0].second);  // -> A: accept, B's address
        const auto pb = aether::decodePaired(out2[1].second);  // -> B: connect, A's address
        assert(aether::addrEqual(out2[0].first, a) && pa && pa->first == aether::PunchRole::Accept  && aether::addrEqual(pa->second, b));
        assert(aether::addrEqual(out2[1].first, b) && pb && pb->first == aether::PunchRole::Connect && aether::addrEqual(pb->second, a));
        std::printf("aether rendezvous OK: two peers paired, roles + addresses correct\n");
    }

    // net: two real UDP hosts on localhost complete a full handshake over actual sockets.
    {
        const aether::NetworkConfig cfg;
        auto hA = aether::openHost(aether::addrLocalhost(0), cfg, aether::MonoTime{ 0 });
        auto hB = aether::openHost(aether::addrLocalhost(0), cfg, aether::MonoTime{ 999 });
        assert(hA && hB);
        const aether::Address addrB = aether::localAddr(hB->socket);
        aether::hostConnect(*hA, addrB, aether::MonoTime{ 0 });

        bool          aUp = false, bUp = false;
        std::uint64_t t = 0;
        for (int tick = 0; tick < 100 && !(aUp && bUp); ++tick) {
            t += 1000000;
            for (const auto& e : aether::hostTick(*hA, {}, aether::MonoTime{ t })) if (e.kind == aether::PeerEvent::Connected) aUp = true;
            for (const auto& e : aether::hostTick(*hB, {}, aether::MonoTime{ t })) if (e.kind == aether::PeerEvent::Connected) bUp = true;
        }
        assert(aUp && bUp);
        aether::closeHost(*hA);
        aether::closeHost(*hB);
        std::printf("aether net OK: two real UDP hosts handshook over localhost\n");
    }

    // NAT punch-through flow: a rendezvous pairs two real hosts; the Connect peer connects, the
    // Accept peer hole-punches, and the handshake completes. Localhost stands in for the opened path
    // (real NAT traversal needs real networks); this proves the rendezvous -> pair -> connect -> handshake flow.
    {
        const aether::NetworkConfig cfg2;
        auto rv = aether::openUdp(aether::addrLocalhost(0));
        auto hA = aether::openHost(aether::addrLocalhost(0), cfg2, aether::MonoTime{ 0 });
        auto hB = aether::openHost(aether::addrLocalhost(0), cfg2, aether::MonoTime{ 777 });
        assert(rv && hA && hB);
        const aether::Address rvAddr = aether::localAddr(*rv);
        aether::RendezvousServer server;
        aether::hostJoinRoom(*hA, rvAddr, 42);
        aether::hostJoinRoom(*hB, rvAddr, 42);

        bool aUp = false, bUp = false;
        std::uint64_t t = 0;
        for (int tick = 0; tick < 200 && !(aUp && bUp); ++tick) {
            t += 1000000;
            aether::rendezvousTick(server, *rv);
            for (const auto& e : aether::hostTick(*hA, {}, aether::MonoTime{ t })) if (e.kind == aether::PeerEvent::Connected) aUp = true;
            for (const auto& e : aether::hostTick(*hB, {}, aether::MonoTime{ t })) if (e.kind == aether::PeerEvent::Connected) bUp = true;
        }
        assert(aUp && bUp);
        aether::closeHost(*hA); aether::closeHost(*hB); aether::closeSocket(*rv);
        std::printf("aether nat-punch OK: rendezvous paired two hosts, handshake completed over the punched path\n");
    }

    return 0;
}
