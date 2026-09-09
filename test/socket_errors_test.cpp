#include "check.hpp"
#include <aether/peer.hpp>
#include <array>
#include <limits>

int main() {
    using namespace aether;
    using aether::test::require;
    const auto destination = addrLocalhost(19001);
    require(addressValid(destination));
    require(addressValid(addrAny6(0)));
    Address invalid;
    invalid.len = std::numeric_limits<std::uint32_t>::max();
    require(!addressValid(invalid));
    require(!openUdp(invalid));
    require(serializeAddr(invalid).empty());
    require(addrPort(invalid) == 0);
    require(addrEqual(invalid, invalid));
    require(!(PeerId{invalid} < PeerId{invalid}));

    auto socket = openUdp(addrLocalhost(0));
    require(socket);
    std::array<std::uint8_t, 16> buffer{};
    Address from;
    require(recvFrom(*socket, buffer, from) == -1);
    require(socket->lastReceiveError.code == SocketErrorCode::WouldBlock);
    require(socket->receiveErrors == 0);
    require(sendTo(*socket, buffer, invalid) == -1);
    require(socket->lastSendError.code == SocketErrorCode::InvalidAddress);
    require(socket->sendErrors == 1 && socket->packetsSent == 0);
    const Bytes oversized(maxUdpPayloadSize + 1);
    require(sendTo(*socket, oversized, destination) == -1);
    require(socket->lastSendError.code == SocketErrorCode::MessageTooLarge);
    require(socket->sendErrors == 2 && socket->packetsSent == 0);
    require(sendTo(*socket, buffer, localAddr(*socket)) == static_cast<int>(buffer.size()));
    require(socket->lastSendError.code == SocketErrorCode::None);
    require(socket->packetsSent == 1 && socket->bytesSent == buffer.size());
    closeSocket(*socket);
    require(sendTo(*socket, buffer, destination) == -1);
    require(socket->lastSendError.code == SocketErrorCode::Closed);
    require(recvFrom(*socket, buffer, from) == -1);
    require(socket->lastReceiveError.code == SocketErrorCode::Closed);
    require(socket->receiveErrors == 1);
}
