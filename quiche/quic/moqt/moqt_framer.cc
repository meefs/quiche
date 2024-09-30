// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_framer.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <type_traits>
#include <utility>

#include "absl/container/inlined_vector.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_data_writer.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/common/wire_serialization.h"

namespace moqt {

namespace {

using ::quiche::QuicheBuffer;
using ::quiche::WireBytes;
using ::quiche::WireOptional;
using ::quiche::WireSpan;
using ::quiche::WireStringWithVarInt62Length;
using ::quiche::WireUint8;
using ::quiche::WireVarInt62;

// Encoding for string parameters as described in
// https://moq-wg.github.io/moq-transport/draft-ietf-moq-transport.html#name-parameters
struct StringParameter {
  template <typename Enum>
  StringParameter(Enum type, absl::string_view data)
      : type(static_cast<uint64_t>(type)), data(data) {
    static_assert(std::is_enum_v<Enum>);
  }

  uint64_t type;
  absl::string_view data;
};
class WireStringParameter {
 public:
  using DataType = StringParameter;

  explicit WireStringParameter(const StringParameter& parameter)
      : parameter_(parameter) {}
  size_t GetLengthOnWire() {
    return quiche::ComputeLengthOnWire(
        WireVarInt62(parameter_.type),
        WireStringWithVarInt62Length(parameter_.data));
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    return quiche::SerializeIntoWriter(
        writer, WireVarInt62(parameter_.type),
        WireStringWithVarInt62Length(parameter_.data));
  }

 private:
  const StringParameter& parameter_;
};

// Encoding for integer parameters as described in
// https://moq-wg.github.io/moq-transport/draft-ietf-moq-transport.html#name-parameters
struct IntParameter {
  template <typename Enum, typename Param>
  IntParameter(Enum type, Param value)
      : type(static_cast<uint64_t>(type)), value(static_cast<uint64_t>(value)) {
    static_assert(std::is_enum_v<Enum>);
    static_assert(std::is_enum_v<Param> || std::is_unsigned_v<Param>);
  }

  uint64_t type;
  uint64_t value;
};
class WireIntParameter {
 public:
  using DataType = IntParameter;

  explicit WireIntParameter(const IntParameter& parameter)
      : parameter_(parameter) {}
  size_t GetLengthOnWire() {
    return quiche::ComputeLengthOnWire(
        WireVarInt62(parameter_.type),
        WireVarInt62(NeededVarIntLen(parameter_.value)),
        WireVarInt62(parameter_.value));
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    return quiche::SerializeIntoWriter(
        writer, WireVarInt62(parameter_.type),
        WireVarInt62(NeededVarIntLen(parameter_.value)),
        WireVarInt62(parameter_.value));
  }

 private:
  size_t NeededVarIntLen(const uint64_t value) {
    return static_cast<size_t>(quic::QuicDataWriter::GetVarInt62Len(value));
  }

  const IntParameter& parameter_;
};

class WireSubscribeParameterList {
 public:
  explicit WireSubscribeParameterList(const MoqtSubscribeParameters& list)
      : list_(list) {}

  size_t GetLengthOnWire() {
    uint64_t num_params = 0;
    size_t length = 0;
    if (list_.authorization_info.has_value()) {
      ++num_params;
      length +=
          WireStringParameter(
              StringParameter(MoqtTrackRequestParameter::kAuthorizationInfo,
                              *list_.authorization_info))
              .GetLengthOnWire();
    }
    if (list_.delivery_timeout.has_value()) {
      ++num_params;
      length += WireIntParameter(
                    IntParameter(MoqtTrackRequestParameter::kDeliveryTimeout,
                                 static_cast<uint64_t>(
                                     list_.delivery_timeout->ToMilliseconds())))
                    .GetLengthOnWire();
    }
    if (list_.max_cache_duration.has_value()) {
      ++num_params;
      length +=
          WireIntParameter(
              IntParameter(MoqtTrackRequestParameter::kMaxCacheDuration,
                           static_cast<uint64_t>(
                               list_.max_cache_duration->ToMilliseconds())))
              .GetLengthOnWire();
    }
    if (list_.object_ack_window.has_value()) {
      ++num_params;
      length +=
          WireIntParameter(
              IntParameter(MoqtTrackRequestParameter::kOackWindowSize,
                           static_cast<uint64_t>(
                               list_.object_ack_window->ToMicroseconds())))
              .GetLengthOnWire();
    }
    length += WireVarInt62(num_params).GetLengthOnWire();
    return length;
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    uint64_t num_params = (list_.authorization_info.has_value() ? 1 : 0) +
                          (list_.delivery_timeout.has_value() ? 1 : 0) +
                          (list_.max_cache_duration.has_value() ? 1 : 0) +
                          (list_.object_ack_window.has_value() ? 1 : 0);
    if (!writer.WriteVarInt62(num_params)) {
      return absl::InternalError("Failed to serialize the length prefix");
    }
    if (list_.authorization_info.has_value() &&
        WireStringParameter(
            StringParameter(MoqtTrackRequestParameter::kAuthorizationInfo,
                            *list_.authorization_info))
                .SerializeIntoWriter(writer) != absl::OkStatus()) {
      return absl::InternalError("Failed to serialize the authorization info");
    }
    if (list_.delivery_timeout.has_value() &&
        WireIntParameter(
            IntParameter(MoqtTrackRequestParameter::kDeliveryTimeout,
                         static_cast<uint64_t>(
                             list_.delivery_timeout->ToMilliseconds())))
                .SerializeIntoWriter(writer) != absl::OkStatus()) {
      return absl::InternalError("Failed to serialize the delivery timeout");
    }
    if (list_.max_cache_duration.has_value() &&
        WireIntParameter(
            IntParameter(MoqtTrackRequestParameter::kMaxCacheDuration,
                         static_cast<uint64_t>(
                             list_.max_cache_duration->ToMilliseconds())))
                .SerializeIntoWriter(writer) != absl::OkStatus()) {
      return absl::InternalError("Failed to serialize the max cache duration");
    }
    if (list_.object_ack_window.has_value() &&
        WireIntParameter(
            IntParameter(MoqtTrackRequestParameter::kOackWindowSize,
                         static_cast<uint64_t>(
                             list_.object_ack_window->ToMicroseconds())))
                .SerializeIntoWriter(writer) != absl::OkStatus()) {
      return absl::InternalError("Failed to serialize the oack window size");
    }
    return absl::OkStatus();
  }

 private:
  const MoqtSubscribeParameters& list_;
};

class WireFullTrackName {
 public:
  using DataType = FullTrackName;

  // If |includes_name| is true, the last element in the tuple is the track
  // name and is therefore not counted in the prefix of the namespace tuple.
  WireFullTrackName(const FullTrackName& name, bool includes_name)
      : name_(name), includes_name_(includes_name) {}

  size_t GetLengthOnWire() {
    const auto tuple = name_.tuple();
    size_t num_elements = includes_name_ ? (tuple.size() - 1) : tuple.size();
    size_t length = WireVarInt62(num_elements).GetLengthOnWire();
    for (const auto& element : tuple) {
      length += WireStringWithVarInt62Length(element).GetLengthOnWire();
    }
    return length;
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    const auto tuple = name_.tuple();
    size_t num_elements = includes_name_ ? (tuple.size() - 1) : tuple.size();
    if (!writer.WriteVarInt62(num_elements)) {
      return absl::InternalError("Failed to serialize the length prefix");
    }
    for (const auto& element : tuple) {
      if (WireStringWithVarInt62Length(element).SerializeIntoWriter(writer) !=
          absl::OkStatus()) {
        return absl::InternalError("Failed to serialize the element");
      }
    }
    return absl::OkStatus();
  }

 private:
  const FullTrackName& name_;
  const bool includes_name_;
};

// Serializes data into buffer using the default allocator.  Invokes QUICHE_BUG
// on failure.
template <typename... Ts>
QuicheBuffer Serialize(Ts... data) {
  absl::StatusOr<QuicheBuffer> buffer = quiche::SerializeIntoBuffer(
      quiche::SimpleBufferAllocator::Get(), data...);
  if (!buffer.ok()) {
    QUICHE_BUG(moqt_failed_serialization)
        << "Failed to serialize MoQT frame: " << buffer.status();
    return QuicheBuffer();
  }
  return *std::move(buffer);
}

WireUint8 WireDeliveryOrder(std::optional<MoqtDeliveryOrder> delivery_order) {
  if (!delivery_order.has_value()) {
    return WireUint8(0x00);
  }
  switch (*delivery_order) {
    case MoqtDeliveryOrder::kAscending:
      return WireUint8(0x01);
    case MoqtDeliveryOrder::kDescending:
      return WireUint8(0x02);
  }
  QUICHE_NOTREACHED();
  return WireUint8(0xff);
}

uint64_t SignedVarintSerializedForm(int64_t value) {
  if (value < 0) {
    return ((-value) << 1) | 0x01;
  }
  return value << 1;
}

}  // namespace

quiche::QuicheBuffer MoqtFramer::SerializeObjectHeader(
    const MoqtObject& message, bool is_first_in_stream) {
  if (!ValidateObjectMetadata(message)) {
    QUIC_BUG(quic_bug_serialize_object_header_01)
        << "Object metadata is invalid";
    return quiche::QuicheBuffer();
  }
  if (message.forwarding_preference == MoqtForwardingPreference::kDatagram) {
    QUIC_BUG(quic_bug_serialize_object_header_02)
        << "Datagrams use SerializeObjectDatagram()";
    return quiche::QuicheBuffer();
  }
  if (!is_first_in_stream) {
    switch (message.forwarding_preference) {
      case MoqtForwardingPreference::kTrack:
        return (message.payload_length == 0)
                   ? Serialize(WireVarInt62(message.group_id),
                               WireVarInt62(message.object_id),
                               WireVarInt62(message.payload_length),
                               WireVarInt62(message.object_status))
                   : Serialize(WireVarInt62(message.group_id),
                               WireVarInt62(message.object_id),
                               WireVarInt62(message.payload_length));
      case MoqtForwardingPreference::kSubgroup:
        return (message.payload_length == 0)
                   ? Serialize(WireVarInt62(message.object_id),
                               WireVarInt62(message.payload_length),
                               WireVarInt62(static_cast<uint64_t>(
                                   message.object_status)))
                   : Serialize(WireVarInt62(message.object_id),
                               WireVarInt62(message.payload_length));
      default:
        QUICHE_NOTREACHED();
        return quiche::QuicheBuffer();
    }
  }
  MoqtDataStreamType message_type =
      GetMessageTypeForForwardingPreference(message.forwarding_preference);
  switch (message.forwarding_preference) {
    case MoqtForwardingPreference::kTrack:
      return (message.payload_length == 0)
                 ? Serialize(WireVarInt62(message_type),
                             WireVarInt62(message.subscribe_id),
                             WireVarInt62(message.track_alias),
                             WireUint8(message.publisher_priority),
                             WireVarInt62(message.group_id),
                             WireVarInt62(message.object_id),
                             WireVarInt62(message.payload_length),
                             WireVarInt62(message.object_status))
                 : Serialize(WireVarInt62(message_type),
                             WireVarInt62(message.subscribe_id),
                             WireVarInt62(message.track_alias),
                             WireUint8(message.publisher_priority),
                             WireVarInt62(message.group_id),
                             WireVarInt62(message.object_id),
                             WireVarInt62(message.payload_length));
    case MoqtForwardingPreference::kSubgroup:
      return (message.payload_length == 0)
                 ? Serialize(WireVarInt62(message_type),
                             WireVarInt62(message.subscribe_id),
                             WireVarInt62(message.track_alias),
                             WireVarInt62(message.group_id),
                             WireVarInt62(*message.subgroup_id),
                             WireUint8(message.publisher_priority),
                             WireVarInt62(message.object_id),
                             WireVarInt62(message.payload_length),
                             WireVarInt62(message.object_status))
                 : Serialize(WireVarInt62(message_type),
                             WireVarInt62(message.subscribe_id),
                             WireVarInt62(message.track_alias),
                             WireVarInt62(message.group_id),
                             WireVarInt62(*message.subgroup_id),
                             WireUint8(message.publisher_priority),
                             WireVarInt62(message.object_id),
                             WireVarInt62(message.payload_length));
    case MoqtForwardingPreference::kDatagram:
      QUICHE_NOTREACHED();
      return quiche::QuicheBuffer();
  }
}

quiche::QuicheBuffer MoqtFramer::SerializeObjectDatagram(
    const MoqtObject& message, absl::string_view payload) {
  if (!ValidateObjectMetadata(message)) {
    QUIC_BUG(quic_bug_serialize_object_datagram_01)
        << "Object metadata is invalid";
    return quiche::QuicheBuffer();
  }
  if (message.forwarding_preference != MoqtForwardingPreference::kDatagram) {
    QUIC_BUG(quic_bug_serialize_object_datagram_02)
        << "Only datagrams use SerializeObjectDatagram()";
    return quiche::QuicheBuffer();
  }
  if (message.payload_length != payload.length()) {
    QUIC_BUG(quic_bug_serialize_object_datagram_03)
        << "Payload length does not match payload";
    return quiche::QuicheBuffer();
  }
  if (message.payload_length == 0) {
    return Serialize(
        WireVarInt62(MoqtDataStreamType::kObjectDatagram),
        WireVarInt62(message.subscribe_id), WireVarInt62(message.track_alias),
        WireVarInt62(message.group_id), WireVarInt62(message.object_id),
        WireUint8(message.publisher_priority),
        WireVarInt62(message.payload_length),
        WireVarInt62(message.object_status));
  }
  return Serialize(
      WireVarInt62(MoqtDataStreamType::kObjectDatagram),
      WireVarInt62(message.subscribe_id), WireVarInt62(message.track_alias),
      WireVarInt62(message.group_id), WireVarInt62(message.object_id),
      WireUint8(message.publisher_priority),
      WireVarInt62(message.payload_length), WireBytes(payload));
}

quiche::QuicheBuffer MoqtFramer::SerializeClientSetup(
    const MoqtClientSetup& message) {
  absl::InlinedVector<IntParameter, 1> int_parameters;
  absl::InlinedVector<StringParameter, 1> string_parameters;
  if (message.role.has_value()) {
    int_parameters.push_back(
        IntParameter(MoqtSetupParameter::kRole, *message.role));
  }
  if (message.max_subscribe_id.has_value()) {
    int_parameters.push_back(IntParameter(MoqtSetupParameter::kMaxSubscribeId,
                                          *message.max_subscribe_id));
  }
  if (message.supports_object_ack) {
    int_parameters.push_back(
        IntParameter(MoqtSetupParameter::kSupportObjectAcks, 1u));
  }
  if (!using_webtrans_ && message.path.has_value()) {
    string_parameters.push_back(
        StringParameter(MoqtSetupParameter::kPath, *message.path));
  }
  return Serialize(
      WireVarInt62(MoqtMessageType::kClientSetup),
      WireVarInt62(message.supported_versions.size()),
      WireSpan<WireVarInt62, MoqtVersion>(message.supported_versions),
      WireVarInt62(string_parameters.size() + int_parameters.size()),
      WireSpan<WireIntParameter>(int_parameters),
      WireSpan<WireStringParameter>(string_parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeServerSetup(
    const MoqtServerSetup& message) {
  absl::InlinedVector<IntParameter, 1> int_parameters;
  if (message.role.has_value()) {
    int_parameters.push_back(
        IntParameter(MoqtSetupParameter::kRole, *message.role));
  }
  if (message.max_subscribe_id.has_value()) {
    int_parameters.push_back(IntParameter(MoqtSetupParameter::kMaxSubscribeId,
                                          *message.max_subscribe_id));
  }
  if (message.supports_object_ack) {
    int_parameters.push_back(
        IntParameter(MoqtSetupParameter::kSupportObjectAcks, 1u));
  }
  return Serialize(WireVarInt62(MoqtMessageType::kServerSetup),
                   WireVarInt62(message.selected_version),
                   WireVarInt62(int_parameters.size()),
                   WireSpan<WireIntParameter>(int_parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribe(
    const MoqtSubscribe& message) {
  MoqtFilterType filter_type = GetFilterType(message);
  if (filter_type == MoqtFilterType::kNone) {
    QUICHE_BUG(MoqtFramer_invalid_subscribe) << "Invalid object range";
    return quiche::QuicheBuffer();
  }
  switch (filter_type) {
    case MoqtFilterType::kLatestGroup:
    case MoqtFilterType::kLatestObject:
      return Serialize(
          WireVarInt62(MoqtMessageType::kSubscribe),
          WireVarInt62(message.subscribe_id), WireVarInt62(message.track_alias),
          WireFullTrackName(message.full_track_name, true),
          WireUint8(message.subscriber_priority),
          WireDeliveryOrder(message.group_order), WireVarInt62(filter_type),
          WireSubscribeParameterList(message.parameters));
    case MoqtFilterType::kAbsoluteStart:
      return Serialize(
          WireVarInt62(MoqtMessageType::kSubscribe),
          WireVarInt62(message.subscribe_id), WireVarInt62(message.track_alias),
          WireFullTrackName(message.full_track_name, true),
          WireUint8(message.subscriber_priority),
          WireDeliveryOrder(message.group_order), WireVarInt62(filter_type),
          WireVarInt62(*message.start_group),
          WireVarInt62(*message.start_object),
          WireSubscribeParameterList(message.parameters));
    case MoqtFilterType::kAbsoluteRange:
      return Serialize(
          WireVarInt62(MoqtMessageType::kSubscribe),
          WireVarInt62(message.subscribe_id), WireVarInt62(message.track_alias),
          WireFullTrackName(message.full_track_name, true),
          WireUint8(message.subscriber_priority),
          WireDeliveryOrder(message.group_order), WireVarInt62(filter_type),
          WireVarInt62(*message.start_group),
          WireVarInt62(*message.start_object), WireVarInt62(*message.end_group),
          WireVarInt62(message.end_object.has_value() ? *message.end_object + 1
                                                      : 0),
          WireSubscribeParameterList(message.parameters));
    default:
      QUICHE_BUG(MoqtFramer_end_group_missing) << "Subscribe framing error.";
      return quiche::QuicheBuffer();
  }
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeOk(
    const MoqtSubscribeOk& message) {
  if (message.parameters.authorization_info.has_value()) {
    QUICHE_BUG(MoqtFramer_invalid_subscribe_ok)
        << "SUBSCRIBE_OK with delivery timeout";
  }
  if (message.largest_id.has_value()) {
    return Serialize(WireVarInt62(MoqtMessageType::kSubscribeOk),
                     WireVarInt62(message.subscribe_id),
                     WireVarInt62(message.expires.ToMilliseconds()),
                     WireDeliveryOrder(message.group_order), WireUint8(1),
                     WireVarInt62(message.largest_id->group),
                     WireVarInt62(message.largest_id->object),
                     WireSubscribeParameterList(message.parameters));
  }
  return Serialize(WireVarInt62(MoqtMessageType::kSubscribeOk),
                   WireVarInt62(message.subscribe_id),
                   WireVarInt62(message.expires.ToMilliseconds()),
                   WireDeliveryOrder(message.group_order), WireUint8(0),
                   WireSubscribeParameterList(message.parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeError(
    const MoqtSubscribeError& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kSubscribeError),
                   WireVarInt62(message.subscribe_id),
                   WireVarInt62(message.error_code),
                   WireStringWithVarInt62Length(message.reason_phrase),
                   WireVarInt62(message.track_alias));
}

quiche::QuicheBuffer MoqtFramer::SerializeUnsubscribe(
    const MoqtUnsubscribe& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kUnsubscribe),
                   WireVarInt62(message.subscribe_id));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeDone(
    const MoqtSubscribeDone& message) {
  if (message.final_id.has_value()) {
    return Serialize(WireVarInt62(MoqtMessageType::kSubscribeDone),
                     WireVarInt62(message.subscribe_id),
                     WireVarInt62(message.status_code),
                     WireStringWithVarInt62Length(message.reason_phrase),
                     WireUint8(1), WireVarInt62(message.final_id->group),
                     WireVarInt62(message.final_id->object));
  }
  return Serialize(
      WireVarInt62(MoqtMessageType::kSubscribeDone),
      WireVarInt62(message.subscribe_id), WireVarInt62(message.status_code),
      WireStringWithVarInt62Length(message.reason_phrase), WireUint8(0));
}

quiche::QuicheBuffer MoqtFramer::SerializeSubscribeUpdate(
    const MoqtSubscribeUpdate& message) {
  if (message.parameters.authorization_info.has_value()) {
    QUICHE_BUG(MoqtFramer_invalid_subscribe_update)
        << "SUBSCRIBE_UPDATE with authorization info";
  }
  uint64_t end_group =
      message.end_group.has_value() ? *message.end_group + 1 : 0;
  uint64_t end_object =
      message.end_object.has_value() ? *message.end_object + 1 : 0;
  if (end_group == 0 && end_object != 0) {
    QUICHE_BUG(MoqtFramer_invalid_subscribe_update) << "Invalid object range";
    return quiche::QuicheBuffer();
  }
  return Serialize(
      WireVarInt62(MoqtMessageType::kSubscribeUpdate),
      WireVarInt62(message.subscribe_id), WireVarInt62(message.start_group),
      WireVarInt62(message.start_object), WireVarInt62(end_group),
      WireVarInt62(end_object), WireUint8(message.subscriber_priority),
      WireSubscribeParameterList(message.parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeAnnounce(
    const MoqtAnnounce& message) {
  if (message.parameters.delivery_timeout.has_value()) {
    QUICHE_BUG(MoqtFramer_invalid_announce) << "ANNOUNCE with delivery timeout";
  }
  return Serialize(
      WireVarInt62(static_cast<uint64_t>(MoqtMessageType::kAnnounce)),
      WireFullTrackName(message.track_namespace, false),
      WireSubscribeParameterList(message.parameters));
}

quiche::QuicheBuffer MoqtFramer::SerializeAnnounceOk(
    const MoqtAnnounceOk& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kAnnounceOk),
                   WireFullTrackName(message.track_namespace, false));
}

quiche::QuicheBuffer MoqtFramer::SerializeAnnounceError(
    const MoqtAnnounceError& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kAnnounceError),
                   WireFullTrackName(message.track_namespace, false),
                   WireVarInt62(message.error_code),
                   WireStringWithVarInt62Length(message.reason_phrase));
}

quiche::QuicheBuffer MoqtFramer::SerializeAnnounceCancel(
    const MoqtAnnounceCancel& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kAnnounceCancel),
                   WireFullTrackName(message.track_namespace, false),
                   WireVarInt62(message.error_code),
                   WireStringWithVarInt62Length(message.reason_phrase));
}

quiche::QuicheBuffer MoqtFramer::SerializeTrackStatusRequest(
    const MoqtTrackStatusRequest& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kTrackStatusRequest),
                   WireFullTrackName(message.full_track_name, true));
}

quiche::QuicheBuffer MoqtFramer::SerializeUnannounce(
    const MoqtUnannounce& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kUnannounce),
                   WireFullTrackName(message.track_namespace, false));
}

quiche::QuicheBuffer MoqtFramer::SerializeTrackStatus(
    const MoqtTrackStatus& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kTrackStatus),
                   WireFullTrackName(message.full_track_name, true),
                   WireVarInt62(message.status_code),
                   WireVarInt62(message.last_group),
                   WireVarInt62(message.last_object));
}

quiche::QuicheBuffer MoqtFramer::SerializeGoAway(const MoqtGoAway& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kGoAway),
                   WireStringWithVarInt62Length(message.new_session_uri));
}

quiche::QuicheBuffer MoqtFramer::SerializeMaxSubscribeId(
    const MoqtMaxSubscribeId& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kMaxSubscribeId),
                   WireVarInt62(message.max_subscribe_id));
}

quiche::QuicheBuffer MoqtFramer::SerializeObjectAck(
    const MoqtObjectAck& message) {
  return Serialize(WireVarInt62(MoqtMessageType::kObjectAck),
                   WireVarInt62(message.subscribe_id),
                   WireVarInt62(message.group_id),
                   WireVarInt62(message.object_id),
                   WireVarInt62(SignedVarintSerializedForm(
                       message.delta_from_deadline.ToMicroseconds())));
}

// static
bool MoqtFramer::ValidateObjectMetadata(const MoqtObject& object) {
  if (object.object_status != MoqtObjectStatus::kNormal &&
      object.payload_length > 0) {
    return false;
  }
  if ((object.forwarding_preference == MoqtForwardingPreference::kSubgroup) !=
      object.subgroup_id.has_value()) {
    return false;
  }
  return true;
}

}  // namespace moqt
