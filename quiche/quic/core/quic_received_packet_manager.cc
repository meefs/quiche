// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_received_packet_manager.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <utility>

#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection_stats.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

namespace {

// The maximum number of packets to ack immediately after a missing packet for
// fast retransmission to kick in at the sender.  This limit is created to
// reduce the number of acks sent that have no benefit for fast retransmission.
// Set to the number of nacks needed for fast retransmit plus one for protection
// against an ack loss
const size_t kMaxPacketsAfterNewMissing = 4;

// One eighth RTT delay when doing ack decimation.
const float kShortAckDecimationDelay = 0.125;
}  // namespace

QuicReceivedPacketManager::QuicReceivedPacketManager()
    : QuicReceivedPacketManager(nullptr) {}

QuicReceivedPacketManager::QuicReceivedPacketManager(QuicConnectionStats* stats)
    : ack_frame_updated_(false),
      max_ack_ranges_(0),
      time_largest_observed_(QuicTime::Zero()),
      save_timestamps_(false),
      save_timestamps_for_in_order_packets_(false),
      stats_(stats),
      num_retransmittable_packets_received_since_last_ack_sent_(0),
      min_received_before_ack_decimation_(kMinReceivedBeforeAckDecimation),
      ack_decimation_delay_(GetQuicFlag(quic_ack_decimation_delay)),
      unlimited_ack_decimation_(false),
      one_immediate_ack_(false),
      local_max_ack_delay_(
          QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs())),
      ack_timeout_(QuicTime::Zero()),
      time_of_previous_received_packet_(QuicTime::Zero()),
      was_last_packet_missing_(false) {}

QuicReceivedPacketManager::~QuicReceivedPacketManager() {}

void QuicReceivedPacketManager::SetFromConfig(const QuicConfig& config,
                                              Perspective perspective) {
  if (config.HasClientSentConnectionOption(kAKD3, perspective)) {
    ack_decimation_delay_ = kShortAckDecimationDelay;
  }
  if (config.HasClientSentConnectionOption(kAKDU, perspective)) {
    unlimited_ack_decimation_ = true;
  }
  if (config.HasClientSentConnectionOption(k1ACK, perspective)) {
    one_immediate_ack_ = true;
  }
}

void QuicReceivedPacketManager::RecordPacketReceived(
    const QuicPacketHeader& header, QuicTime receipt_time,
    const QuicEcnCodepoint ecn) {
  const QuicPacketNumber packet_number = header.packet_number;
  QUICHE_DCHECK(IsAwaitingPacket(packet_number))
      << " packet_number:" << packet_number;
  was_last_packet_missing_ = IsMissing(packet_number);
  if (!ack_frame_updated_) {
    ack_frame_.received_packet_times.clear();
  }
  ack_frame_updated_ = true;
  ack_now_ = false;

  // Whether |packet_number| is received out of order.
  bool packet_reordered = false;
  if (LargestAcked(ack_frame_).IsInitialized() &&
      LargestAcked(ack_frame_) > packet_number) {
    // Record how out of order stats.
    packet_reordered = true;
    ++stats_->packets_reordered;
    stats_->max_sequence_reordering =
        std::max(stats_->max_sequence_reordering,
                 LargestAcked(ack_frame_) - packet_number);
    int64_t reordering_time_us =
        (receipt_time - time_largest_observed_).ToMicroseconds();
    stats_->max_time_reordering_us =
        std::max(stats_->max_time_reordering_us, reordering_time_us);
  }
  if (!LargestAcked(ack_frame_).IsInitialized() ||
      packet_number > LargestAcked(ack_frame_)) {
    ack_frame_.largest_acked = packet_number;
    time_largest_observed_ = receipt_time;
  }
  ack_frame_.packets.Add(packet_number);
  MaybeTrimAckRanges();

  if (save_timestamps_) {
    // The timestamp format only handles packets in time order.
    if (save_timestamps_for_in_order_packets_ && packet_reordered) {
      QUIC_DLOG(WARNING) << "Not saving receive timestamp for packet "
                         << packet_number;
    } else if (!ack_frame_.received_packet_times.empty() &&
               ack_frame_.received_packet_times.back().second > receipt_time) {
      QUIC_LOG(WARNING)
          << "Receive time went backwards from: "
          << ack_frame_.received_packet_times.back().second.ToDebuggingValue()
          << " to " << receipt_time.ToDebuggingValue();
    } else {
      ack_frame_.received_packet_times.push_back(
          std::make_pair(packet_number, receipt_time));
    }
  }

  if (ecn == ECN_CE && !last_packet_was_ce_marked_) {
    changed_to_ce_marked_ = true;
  }
  last_packet_was_ce_marked_ = ecn == ECN_CE;
  if (ecn != ECN_NOT_ECT) {
    if (!ack_frame_.ecn_counters.has_value()) {
      ack_frame_.ecn_counters = QuicEcnCounts();
    }
    switch (ecn) {
      case ECN_NOT_ECT:
        QUICHE_NOTREACHED();
        break;  // It's impossible to get here, but the compiler complains.
      case ECN_ECT0:
        ack_frame_.ecn_counters->ect0++;
        break;
      case ECN_ECT1:
        ack_frame_.ecn_counters->ect1++;
        break;
      case ECN_CE:
        ack_frame_.ecn_counters->ce++;
        break;
    }
  }

  if (least_received_packet_number_.IsInitialized()) {
    least_received_packet_number_ =
        std::min(least_received_packet_number_, packet_number);
  } else {
    least_received_packet_number_ = packet_number;
  }
}

void QuicReceivedPacketManager::MaybeTrimAckRanges() {
  while (max_ack_ranges_ > 0 &&
         ack_frame_.packets.NumIntervals() > max_ack_ranges_) {
    ack_frame_.packets.RemoveSmallestInterval();
  }
}

bool QuicReceivedPacketManager::IsMissing(QuicPacketNumber packet_number) {
  return LargestAcked(ack_frame_).IsInitialized() &&
         packet_number < LargestAcked(ack_frame_) &&
         !ack_frame_.packets.Contains(packet_number);
}

bool QuicReceivedPacketManager::IsAwaitingPacket(
    QuicPacketNumber packet_number) const {
  return quic::IsAwaitingPacket(ack_frame_, packet_number,
                                peer_least_packet_awaiting_ack_);
}

const QuicFrame QuicReceivedPacketManager::GetUpdatedAckFrame(
    QuicTime approximate_now) {
  if (time_largest_observed_ == QuicTime::Zero()) {
    // We have received no packets.
    ack_frame_.ack_delay_time = QuicTime::Delta::Infinite();
  } else {
    // Ensure the delta is zero if approximate now is "in the past".
    ack_frame_.ack_delay_time = approximate_now < time_largest_observed_
                                    ? QuicTime::Delta::Zero()
                                    : approximate_now - time_largest_observed_;
  }

  const size_t initial_ack_ranges = ack_frame_.packets.NumIntervals();
  uint64_t num_iterations = 0;
  while (max_ack_ranges_ > 0 &&
         ack_frame_.packets.NumIntervals() > max_ack_ranges_) {
    num_iterations++;
    QUIC_BUG_IF(quic_rpm_too_many_ack_ranges, (num_iterations % 100000) == 0)
        << "Too many ack ranges to remove, possibly a dead loop. "
           "initial_ack_ranges:"
        << initial_ack_ranges << " max_ack_ranges:" << max_ack_ranges_
        << ", current_ack_ranges:" << ack_frame_.packets.NumIntervals()
        << " num_iterations:" << num_iterations;
    ack_frame_.packets.RemoveSmallestInterval();
  }
  // Clear all packet times if any are too far from largest observed.
  // It's expected this is extremely rare.
  for (auto it = ack_frame_.received_packet_times.begin();
       it != ack_frame_.received_packet_times.end();) {
    if (LargestAcked(ack_frame_) - it->first >=
        std::numeric_limits<uint8_t>::max()) {
      it = ack_frame_.received_packet_times.erase(it);
    } else {
      ++it;
    }
  }

#if QUIC_FRAME_DEBUG
  QuicFrame frame = QuicFrame(&ack_frame_);
  frame.delete_forbidden = true;
  return frame;
#else   // QUIC_FRAME_DEBUG
  return QuicFrame(&ack_frame_);
#endif  // QUIC_FRAME_DEBUG
}

void QuicReceivedPacketManager::DontWaitForPacketsBefore(
    QuicPacketNumber least_unacked) {
  if (!least_unacked.IsInitialized()) {
    return;
  }
  // ValidateAck() should fail if peer_least_packet_awaiting_ack shrinks.
  QUICHE_DCHECK(!peer_least_packet_awaiting_ack_.IsInitialized() ||
                peer_least_packet_awaiting_ack_ <= least_unacked);
  if (!peer_least_packet_awaiting_ack_.IsInitialized() ||
      least_unacked > peer_least_packet_awaiting_ack_) {
    peer_least_packet_awaiting_ack_ = least_unacked;
    bool packets_updated = ack_frame_.packets.RemoveUpTo(least_unacked);
    if (packets_updated) {
      // Ack frame gets updated because packets set is updated because of stop
      // waiting frame.
      ack_frame_updated_ = true;
    }
  }
  QUICHE_DCHECK(ack_frame_.packets.Empty() ||
                !peer_least_packet_awaiting_ack_.IsInitialized() ||
                ack_frame_.packets.Min() >= peer_least_packet_awaiting_ack_);
}

QuicTime::Delta QuicReceivedPacketManager::GetMaxAckDelay(
    QuicPacketNumber last_received_packet_number,
    const RttStats& rtt_stats) const {
  if (AckFrequencyFrameReceived() ||
      last_received_packet_number < PeerFirstSendingPacketNumber() +
                                        min_received_before_ack_decimation_) {
    return local_max_ack_delay_;
  }

  // Wait for the minimum of the ack decimation delay or the delayed ack time
  // before sending an ack.
  QuicTime::Delta ack_delay = std::min(
      local_max_ack_delay_, rtt_stats.min_rtt() * ack_decimation_delay_);
  return std::max(ack_delay, kAlarmGranularity);
}

void QuicReceivedPacketManager::MaybeUpdateAckFrequency(
    QuicPacketNumber last_received_packet_number) {
  if (AckFrequencyFrameReceived()) {
    // Skip Ack Decimation below after receiving an AckFrequencyFrame from the
    // other end point.
    return;
  }
  if (last_received_packet_number <
      PeerFirstSendingPacketNumber() + min_received_before_ack_decimation_) {
    return;
  }
  ack_frequency_ = unlimited_ack_decimation_
                       ? std::numeric_limits<size_t>::max()
                       : kMaxRetransmittablePacketsBeforeAck;
}

void QuicReceivedPacketManager::MaybeUpdateAckTimeout(
    bool should_last_packet_instigate_acks,
    QuicPacketNumber last_received_packet_number,
    QuicTime last_packet_receipt_time, QuicTime now,
    const RttStats* rtt_stats) {
  if (!ack_frame_updated_) {
    // ACK frame has not been updated, nothing to do.
    return;
  }

  if (ack_now_) {
    // An IMMEDIATE_ACK frame arrived. Send an ack immediately.
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_receive_ack_frequency, 2, 2);
    ack_timeout_ = now;
    return;
  }

  // Limiting this to reordering_threshold_ > 0 is not compliant with
  // draft-ietf-quic-ack-frequency-11, but there is an issue to add this
  // behavior.
  if (reordering_threshold_ > 0 && was_last_packet_missing_ &&
      last_sent_largest_acked_.IsInitialized() &&
      last_received_packet_number < last_sent_largest_acked_) {
    // Ack immediately if an ACK frame was sent with a larger largest acked than
    // the newly received packet number.
    ack_timeout_ = now;
    return;
  }

  if (changed_to_ce_marked_) {
    ack_timeout_ = now;
    changed_to_ce_marked_ = false;
    return;
  }

  if (!should_last_packet_instigate_acks) {
    return;
  }

  ++num_retransmittable_packets_received_since_last_ack_sent_;

  MaybeUpdateAckFrequency(last_received_packet_number);
  if (num_retransmittable_packets_received_since_last_ack_sent_ >=
      ack_frequency_) {
    ack_timeout_ = now;
    return;
  }

  if (reordering_threshold_ == 1) {
    // Default behavior, not updated by ACK_FREQUENCY.
    if (HasNewMissingPackets()) {
      ack_timeout_ = now;
      return;
    }
  } else {
    if (ack_frame_.packets.NumIntervals() == max_ack_ranges_ &&
        (!last_sent_largest_acked_.IsInitialized() ||
         last_sent_largest_acked_ < ack_frame_.packets.begin()->max() - 1)) {
      // If the lowest ACK range has not yet been reported, and might be trimmed
      // on the next packet arrival, send an ACK.
      ack_timeout_ = now;
      return;
    }
    if (ReorderingExceedsThreshold()) {
      ack_timeout_ = now;
      return;
    }
  }

  const QuicTime updated_ack_time = std::max(
      now, std::min(last_packet_receipt_time, now) +
               GetMaxAckDelay(last_received_packet_number, *rtt_stats));
  if (!ack_timeout_.IsInitialized() || ack_timeout_ > updated_ack_time) {
    ack_timeout_ = updated_ack_time;
  }
}

void QuicReceivedPacketManager::ResetAckStates() {
  ack_frame_updated_ = false;
  ack_timeout_ = QuicTime::Zero();
  num_retransmittable_packets_received_since_last_ack_sent_ = 0;
  last_sent_largest_acked_ = LargestAcked(ack_frame_);
}

bool QuicReceivedPacketManager::HasMissingPackets() const {
  if (ack_frame_.packets.Empty()) {
    return false;
  }
  if (ack_frame_.packets.NumIntervals() > 1) {
    return true;
  }
  return peer_least_packet_awaiting_ack_.IsInitialized() &&
         ack_frame_.packets.Min() > peer_least_packet_awaiting_ack_;
}

bool QuicReceivedPacketManager::HasNewMissingPackets() const {
  if (one_immediate_ack_) {
    return HasMissingPackets() && ack_frame_.packets.LastIntervalLength() == 1;
  }
  return HasMissingPackets() &&
         ack_frame_.packets.LastIntervalLength() <= kMaxPacketsAfterNewMissing;
}

bool QuicReceivedPacketManager::ReorderingExceedsThreshold() const {
  if (reordering_threshold_ <= 1) {  // flag is not enabled, or there is no
                                     // threshold.
    return false;
  }
  if (!HasMissingPackets() ||
      GetLargestObserved() < QuicPacketNumber(reordering_threshold_)) {
    return false;
  }
  // Find the next missing packet.
  QuicPacketNumber smallest_unreported_missing;
  if (last_sent_largest_acked_.IsInitialized() &&
      last_sent_largest_acked_ >= QuicPacketNumber(reordering_threshold_)) {
    smallest_unreported_missing =
        last_sent_largest_acked_ - reordering_threshold_ + 1;
  }
  // All ACK ranges before peer_least_packet_awaiting_ack_ have already been
  // deleted, so this is the lowest packet number that has receive state.
  if (peer_least_packet_awaiting_ack_.IsInitialized() &&
      (!smallest_unreported_missing.IsInitialized() ||
       smallest_unreported_missing < peer_least_packet_awaiting_ack_)) {
    smallest_unreported_missing = peer_least_packet_awaiting_ack_;
    if (!least_unacked_plus_1_) {
      ++smallest_unreported_missing;
    }
  }
  if (smallest_unreported_missing.IsInitialized()) {
    auto it = ack_frame_.packets.LowerBound(smallest_unreported_missing);
    if (it == ack_frame_.packets.end()) {
      QUIC_BUG(quic_bug_764939479)
          << "Checking reordering with improper ACK state";
      return false;
    }
    if (it->Contains(smallest_unreported_missing)) {
      smallest_unreported_missing = it->max();
    }
  } else {
    // No ACK has been sent. Since HasMissingPackets() is true, there must be at
    // least two ranges. Per RFC9000, ignore the range from zero to the first
    // observed packet. Smallest_unreported_missing is therefore the max of the
    // first range.
    QUICHE_DCHECK(ack_frame_.packets.NumIntervals() > 1);
    smallest_unreported_missing = ack_frame_.packets.begin()->max();
  }
  return smallest_unreported_missing <=
         (GetLargestObserved() - reordering_threshold_);
}

bool QuicReceivedPacketManager::ack_frame_updated() const {
  return ack_frame_updated_;
}

QuicPacketNumber QuicReceivedPacketManager::GetLargestObserved() const {
  return LargestAcked(ack_frame_);
}

QuicPacketNumber QuicReceivedPacketManager::PeerFirstSendingPacketNumber()
    const {
  if (!least_received_packet_number_.IsInitialized()) {
    QUIC_BUG(quic_bug_10849_1) << "No packets have been received yet";
    return QuicPacketNumber(1);
  }
  return least_received_packet_number_;
}

bool QuicReceivedPacketManager::IsAckFrameEmpty() const {
  return ack_frame_.packets.Empty();
}

void QuicReceivedPacketManager::OnAckFrequencyFrame(
    const QuicAckFrequencyFrame& frame) {
  if (frame.sequence_number < next_ack_frequency_frame_sequence_number_) {
    // Ignore old ACK_FREQUENCY frames.
    return;
  }
  next_ack_frequency_frame_sequence_number_ = frame.sequence_number + 1;
  ack_frequency_ = frame.ack_eliciting_threshold + 1;
  local_max_ack_delay_ = frame.requested_max_ack_delay;
  reordering_threshold_ = frame.reordering_threshold;
}

}  // namespace quic
