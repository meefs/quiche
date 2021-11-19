// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_CRYPTO_QUIC_CLIENT_SESSION_CACHE_H_
#define QUICHE_QUIC_CORE_CRYPTO_QUIC_CLIENT_SESSION_CACHE_H_

#include <memory>

#include "quic/core/crypto/quic_crypto_client_config.h"
#include "quic/core/quic_lru_cache.h"
#include "quic/core/quic_server_id.h"

namespace quic {

// QuicClientSessionCache maps from QuicServerId to information used to resume
// TLS sessions for that server.
class QUIC_EXPORT_PRIVATE QuicClientSessionCache : public SessionCache {
 public:
  QuicClientSessionCache();
  explicit QuicClientSessionCache(size_t max_entries);
  ~QuicClientSessionCache() override;

  void Insert(const QuicServerId& server_id,
              bssl::UniquePtr<SSL_SESSION> session,
              const TransportParameters& params,
              const ApplicationState* application_state) override;

  std::unique_ptr<QuicResumptionState> Lookup(const QuicServerId& server_id,
                                              QuicWallTime now,
                                              const SSL_CTX* ctx) override;

  void ClearEarlyData(const QuicServerId& server_id) override;

  void RemoveExpiredEntries(QuicWallTime now) override;

  void Clear() override;

  size_t size() const { return cache_.Size(); }

 private:
  struct QUIC_EXPORT_PRIVATE Entry {
    Entry();
    Entry(Entry&&);
    ~Entry();

    // Adds a new |session| onto sessions, dropping the oldest one if two are
    // already stored.
    void PushSession(bssl::UniquePtr<SSL_SESSION> session);

    // Retrieves the latest session from the entry, meanwhile removing it.
    bssl::UniquePtr<SSL_SESSION> PopSession();

    SSL_SESSION* PeekSession();

    bssl::UniquePtr<SSL_SESSION> sessions[2];
    std::unique_ptr<TransportParameters> params;
    std::unique_ptr<ApplicationState> application_state;
  };

  // Creates a new entry and insert into |cache_|.
  void CreateAndInsertEntry(const QuicServerId& server_id,
                            bssl::UniquePtr<SSL_SESSION> session,
                            const TransportParameters& params,
                            const ApplicationState* application_state);

  QuicLRUCache<QuicServerId, Entry, QuicServerIdHash> cache_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_CRYPTO_QUIC_CLIENT_SESSION_CACHE_H_
