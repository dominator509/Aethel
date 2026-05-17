#![forbid(unsafe_code)]

use std::collections::HashMap;

pub type PeerId = Vec<u8>;
pub const K_BUCKET_SIZE: usize = 20;

/// A bucket holds a list of known peers.
#[derive(Debug, Clone)]
pub struct Bucket {
    pub peers: Vec<PeerId>,
}

impl Default for Bucket {
    fn default() -> Self {
        Self::new()
    }
}

impl Bucket {
    pub fn new() -> Self {
        Self { peers: Vec::new() }
    }
}

/// A basic Distributed Hash Table routing table for peer discovery.
/// (In a full implementation, this uses Kademlia's XOR metric).
pub struct RoutingTable {
    pub local_id: PeerId,
    pub buckets: HashMap<usize, Bucket>,
}

impl RoutingTable {
    pub fn new(local_id: PeerId) -> Self {
        Self {
            local_id,
            buckets: HashMap::new(),
        }
    }

    /// Determines the "distance" between two peer IDs
    fn distance(&self, a: &[u8], b: &[u8]) -> usize {
        let mut dist = 0;
        let len = std::cmp::min(a.len(), b.len());
        for i in 0..len {
            dist += (a[i] ^ b[i]) as usize;
        }
        dist
    }

    /// Adds a peer to the routing table based on distance
    pub fn add_peer(&mut self, peer: PeerId) {
        let dist = self.distance(&self.local_id, &peer);
        // Simple bucketing based on raw distance
        let bucket_idx = dist % 256;

        let bucket = self.buckets.entry(bucket_idx).or_default();
        if !bucket.peers.contains(&peer) {
            // Anti-Eclipse Attack: Enforce maximum bucket size
            if bucket.peers.len() < K_BUCKET_SIZE {
                bucket.peers.push(peer);
            }
        }
    }

    /// Finds the closest peers to a target ID
    pub fn find_closest_peers(&self, target: &[u8], max_count: usize) -> Vec<PeerId> {
        let dist = self.distance(&self.local_id, target);
        let bucket_idx = dist % 256;

        if let Some(bucket) = self.buckets.get(&bucket_idx) {
            let mut result = bucket.peers.clone();
            result.truncate(max_count);
            result
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_routing() {
        let local = b"node_a".to_vec();
        let peer1 = b"node_b".to_vec();
        let peer2 = b"node_c".to_vec();

        let mut dht = RoutingTable::new(local);
        dht.add_peer(peer1.clone());
        dht.add_peer(peer2.clone());

        // Should be able to find peer1 as the closest node to itself
        let closest = dht.find_closest_peers(&peer1, 10);
        assert!(closest.contains(&peer1));
    }
}

    #[test]
    fn test_internal_exception_k_bucket_size_exhaustion() {
        let local = b"node_a".to_vec();
        let mut dht = RoutingTable::new(local);

        // Fill bucket 0 to capacity
        for i in 0..K_BUCKET_SIZE {
            // By XOR math, a peer with the same first byte will map to distance 0 for the first byte
            let mut peer = b"node_a".to_vec();
            peer.push(i as u8); // make it unique
            dht.add_peer(peer);
        }

        // Ensure bucket is at capacity
        assert_eq!(dht.buckets.get(&0).unwrap().peers.len(), K_BUCKET_SIZE);

        // Attempt to add one more
        let mut overflow_peer = b"node_a".to_vec();
        overflow_peer.push(255);
        dht.add_peer(overflow_peer.clone());

        // Verify bucket size has not exceeded K_BUCKET_SIZE
        assert_eq!(dht.buckets.get(&0).unwrap().peers.len(), K_BUCKET_SIZE);
        assert!(!dht.buckets.get(&0).unwrap().peers.contains(&overflow_peer));
    }
