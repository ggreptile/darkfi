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

use std::collections::HashSet;

use async_std::sync::Arc;
use async_trait::async_trait;
use darkfi::{
    dht2::net_hashmap::{NetHashMapInsert, NetHashMapRemove},
    net::{
        self, ChannelPtr, MessageSubscription, P2pPtr, ProtocolBase, ProtocolBasePtr,
        ProtocolJobsManager, ProtocolJobsManagerPtr,
    },
    Result,
};
use darkfi_serial::{SerialDecodable, SerialEncodable};
use log::debug;
use smol::Executor;

use super::DhtdPtr;

pub struct ProtocolDht {
    jobsman: ProtocolJobsManagerPtr,
    channel: ChannelPtr,
    p2p: P2pPtr,
    state: DhtdPtr,
    insert_sub: MessageSubscription<NetHashMapInsert<blake3::Hash, Vec<blake3::Hash>>>,
    remove_sub: MessageSubscription<NetHashMapRemove<blake3::Hash>>,
    chunk_request_sub: MessageSubscription<ChunkRequest>,
    chunk_reply_sub: MessageSubscription<ChunkReply>,
}

#[derive(Debug, Clone, SerialEncodable, SerialDecodable)]
pub struct ChunkRequest {
    pub hash: blake3::Hash,
}

impl net::Message for ChunkRequest {
    fn name() -> &'static str {
        "dhtchunkrequest"
    }
}

#[derive(Debug, Clone, SerialEncodable, SerialDecodable)]
pub struct ChunkReply {
    pub hash: blake3::Hash,
    pub data: Vec<u8>,
}

impl net::Message for ChunkReply {
    fn name() -> &'static str {
        "dhtchunkreply"
    }
}

impl ProtocolDht {
    pub async fn init(channel: ChannelPtr, p2p: P2pPtr, state: DhtdPtr) -> Result<ProtocolBasePtr> {
        let msg_subsystem = channel.get_message_subsystem();
        msg_subsystem.add_dispatch::<NetHashMapInsert<blake3::Hash, Vec<blake3::Hash>>>().await;
        msg_subsystem.add_dispatch::<NetHashMapRemove<blake3::Hash>>().await;
        msg_subsystem.add_dispatch::<ChunkRequest>().await;
        msg_subsystem.add_dispatch::<ChunkReply>().await;

        let insert_sub = channel.subscribe_msg().await?;
        let remove_sub = channel.subscribe_msg().await?;
        let chunk_request_sub = channel.subscribe_msg().await?;
        let chunk_reply_sub = channel.subscribe_msg().await?;

        Ok(Arc::new(Self {
            jobsman: ProtocolJobsManager::new("DHTProto", channel.clone()),
            channel,
            p2p,
            state,
            insert_sub,
            remove_sub,
            chunk_request_sub,
            chunk_reply_sub,
        }))
    }

    async fn handle_insert(self: Arc<Self>) -> Result<()> {
        debug!("ProtocolDht::handle_insert START");
        loop {
            let Ok(msg) = self.insert_sub.receive().await else {
                continue
            };

            let mut state = self.state.write().await;

            if !state.routing_table.contains_key(&msg.k) {
                state.routing_table.insert(msg.k, HashSet::new());
            }

            let hashset = state.routing_table.get_mut(&msg.k).unwrap();
            hashset.insert(self.channel.address());
        }
    }

    async fn handle_remove(self: Arc<Self>) -> Result<()> {
        debug!("ProtocolDht::handle_remove START");
        loop {
            let Ok(msg) = self.remove_sub.receive().await else {
                continue
            };

            let mut state = self.state.write().await;

            if !state.routing_table.contains_key(&msg.k) {
                continue
            }

            let hashset = state.routing_table.get_mut(&msg.k).unwrap();
            hashset.remove(&self.channel.address());
        }
    }

    async fn handle_chunk_request(self: Arc<Self>) -> Result<()> {
        debug!("ProtocolDht::handle_chunk_request START");
        loop {
            let Ok(msg) = self.chunk_request_sub.receive().await else {
                continue
            };

            println!("{:?}", msg);
        }
    }

    async fn handle_chunk_reply(self: Arc<Self>) -> Result<()> {
        debug!("ProtocolDht::handle_chunk_reply START");
        loop {
            let Ok(msg) = self.chunk_reply_sub.receive().await else {
                continue
            };

            println!("{:?}", msg);
        }
    }
}

#[async_trait]
impl ProtocolBase for ProtocolDht {
    async fn start(self: Arc<Self>, ex: Arc<Executor<'_>>) -> Result<()> {
        debug!("ProtocolDht::start()");
        self.jobsman.clone().start(ex.clone());
        self.jobsman.clone().spawn(self.clone().handle_insert(), ex.clone()).await;
        self.jobsman.clone().spawn(self.clone().handle_remove(), ex.clone()).await;
        self.jobsman.clone().spawn(self.clone().handle_chunk_request(), ex.clone()).await;
        self.jobsman.clone().spawn(self.clone().handle_chunk_reply(), ex.clone()).await;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ProtoDHT"
    }
}