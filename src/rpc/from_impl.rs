/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2023 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::collections::HashMap;
use tinyjson::JsonValue::{self, Number as JsonNum, Object as JsonObj, String as JsonStr};

use crate::net;

// helper functions
fn json_map<const N: usize>(vals: [(&str, JsonValue); N]) -> JsonValue {
    JsonObj(HashMap::from(vals.map(|(k, v)| (k.to_string(), v))))
}
fn json_str(val: &str) -> JsonValue {
    JsonStr(val.to_string())
}

#[cfg(feature = "net")]
impl From<net::channel::ChannelInfo> for JsonValue {
    fn from(info: net::channel::ChannelInfo) -> JsonValue {
        json_map([("addr", JsonStr(info.addr.to_string())), ("id", JsonNum(info.id.into()))])
    }
}

#[cfg(feature = "net")]
impl From<net::dnet::MessageInfo> for JsonValue {
    fn from(info: net::dnet::MessageInfo) -> JsonValue {
        json_map([
            ("chan", info.chan.into()),
            ("cmd", JsonStr(info.cmd)),
            ("time", JsonStr(info.time.0.to_string())),
        ])
    }
}

#[cfg(feature = "net")]
impl From<net::dnet::OutboundConnecting> for JsonValue {
    fn from(info: net::dnet::OutboundConnecting) -> JsonValue {
        json_map([("slot", JsonNum(info.slot.into())), ("addr", JsonStr(info.addr.to_string()))])
    }
}

#[cfg(feature = "net")]
impl From<net::dnet::OutboundConnected> for JsonValue {
    fn from(info: net::dnet::OutboundConnected) -> JsonValue {
        json_map([
            ("slot", JsonNum(info.slot.into())),
            ("addr", JsonStr(info.addr.to_string())),
            ("channel_id", JsonNum(info.channel_id.into())),
        ])
    }
}

#[cfg(feature = "net")]
impl From<net::dnet::OutboundDisconnected> for JsonValue {
    fn from(info: net::dnet::OutboundDisconnected) -> JsonValue {
        json_map([("slot", JsonNum(info.slot.into())), ("err", JsonStr(info.err))])
    }
}

#[cfg(feature = "net")]
impl From<net::dnet::DnetEvent> for JsonValue {
    fn from(event: net::dnet::DnetEvent) -> JsonValue {
        match event {
            net::dnet::DnetEvent::SendMessage(info) => {
                json_map([("event", json_str("send")), ("info", info.into())])
            }
            net::dnet::DnetEvent::RecvMessage(info) => {
                json_map([("event", json_str("recv")), ("info", info.into())])
            }
            net::dnet::DnetEvent::OutboundConnecting(info) => {
                json_map([("event", json_str("outbound_connecting")), ("info", info.into())])
            }
            net::dnet::DnetEvent::OutboundConnected(info) => {
                json_map([("event", json_str("outbound_connected")), ("info", info.into())])
            }
            net::dnet::DnetEvent::OutboundDisconnected(info) => {
                json_map([("event", json_str("outbound_disconnected")), ("info", info.into())])
            }
        }
    }
}
