// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A toy server, which listens on a specified address for QUIC traffic and
// handles incoming responses.
//
// Note that this server is intended to verify correctness of the client and is
// in no way expected to be performant.

#ifndef QUICHE_QUIC_TOOLS_QUIC_SERVER_H_
#define QUICHE_QUIC_TOOLS_QUIC_SERVER_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/connection_id_generator.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/deterministic_connection_id_generator.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/quic_server_io_harness.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_udp_socket.h"
#include "quiche/quic/core/quic_version_manager.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/core/socket_factory.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quic_simple_server_backend.h"
#include "quiche/quic/tools/quic_spdy_server_base.h"

namespace quic {

namespace test {
class QuicServerPeer;
}  // namespace test

class QuicDispatcher;
class QuicPacketReader;

class QuicServer : public QuicSpdyServerBase {
 public:
  // `quic_simple_server_backend` must outlive the created QuicServer.
  QuicServer(std::unique_ptr<ProofSource> proof_source,
             QuicSimpleServerBackend* quic_simple_server_backend);
  QuicServer(std::unique_ptr<ProofSource> proof_source,
             QuicSimpleServerBackend* quic_simple_server_backend,
             const ParsedQuicVersionVector& supported_versions);
  QuicServer(std::unique_ptr<ProofSource> proof_source,
             const QuicConfig& config,
             const QuicCryptoServerConfig::ConfigOptions& crypto_config_options,
             const ParsedQuicVersionVector& supported_versions,
             QuicSimpleServerBackend* quic_simple_server_backend,
             uint8_t expected_server_connection_id_length);
  QuicServer(const QuicServer&) = delete;
  QuicServer& operator=(const QuicServer&) = delete;

  ~QuicServer() override;

  // Start listening on the specified address.
  bool CreateUDPSocketAndListen(const QuicSocketAddress& address) override;
  // Handles all events. Does not return.
  void HandleEventsForever() override;

  // Wait up to 50ms, and handle any events which occur.
  void WaitForEvents();

  // Server deletion is imminent.  Start cleaning up any pending sessions.
  virtual void Shutdown();

  void SetChloMultiplier(size_t multiplier) {
    crypto_config_.set_chlo_multiplier(multiplier);
  }

  void SetPreSharedKey(absl::string_view key) {
    crypto_config_.set_pre_shared_key(key);
  }

  bool overflow_supported() const { return io_->overflow_supported(); }

  QuicPacketCount packets_dropped() { return io_->packets_dropped(); }

  int port() { return io_->local_address().port(); }

  QuicEventLoop* event_loop() { return event_loop_.get(); }

  void set_max_sessions_to_create_per_socket_event(size_t value) {
    io_->set_max_sessions_to_create_per_socket_event(value);
  }

 protected:
  virtual QuicPacketWriter* CreateWriter(int fd);

  virtual QuicDispatcher* CreateQuicDispatcher();

  virtual std::unique_ptr<QuicEventLoop> CreateEventLoop();

  const QuicConfig& config() const { return config_; }
  const QuicCryptoServerConfig& crypto_config() const { return crypto_config_; }

  QuicDispatcher* dispatcher() { return dispatcher_.get(); }

  QuicVersionManager* version_manager() { return &version_manager_; }

  QuicSimpleServerBackend* server_backend() {
    return quic_simple_server_backend_;
  }

  void set_silent_close(bool value) { silent_close_ = value; }

  uint8_t expected_server_connection_id_length() {
    return expected_server_connection_id_length_;
  }

  ConnectionIdGeneratorInterface& connection_id_generator() {
    return connection_id_generator_;
  }

 private:
  friend class quic::test::QuicServerPeer;

  // Initialize the internal state of the server.
  void Initialize();

  // Schedules alarms and notifies the server of the I/O events.
  std::unique_ptr<QuicEventLoop> event_loop_;
  // Used by some backends to create additional sockets, e.g. for upstream
  // destination connections for proxying.
  std::unique_ptr<SocketFactory> socket_factory_;
  // Accepts data from the framer and demuxes clients to sessions.
  std::unique_ptr<QuicDispatcher> dispatcher_;

  // If true, do not call Shutdown on the dispatcher.  Connections will close
  // without sending a final connection close.
  bool silent_close_;

  // config_ contains non-crypto parameters that are negotiated in the crypto
  // handshake.
  QuicConfig config_;
  // crypto_config_ contains crypto parameters for the handshake.
  QuicCryptoServerConfig crypto_config_;
  // crypto_config_options_ contains crypto parameters for the handshake.
  QuicCryptoServerConfig::ConfigOptions crypto_config_options_;

  // Used to generate current supported versions.
  QuicVersionManager version_manager_;

  QuicSimpleServerBackend* quic_simple_server_backend_;  // unowned.

  // Connection ID length expected to be read on incoming IETF short headers.
  uint8_t expected_server_connection_id_length_;

  DeterministicConnectionIdGenerator connection_id_generator_;

  SocketFd fd_ = kInvalidSocketFd;
  std::unique_ptr<QuicServerIoHarness> io_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUIC_SERVER_H_
