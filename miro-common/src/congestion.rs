use std::{cmp::max, time::Duration};

use s2n_quic::provider::congestion_controller::{
    self, CongestionController, Publisher, RandomGenerator, RttEstimator, Timestamp
};


const MAX_BURST_PACKETS: u64 = 10;
const MAX_BURST_PACING_DELAY_MULTIPLIER: u64 = 4;
/// 2ms
const MIN_PACING_DEALY: u64 = 2_000_000;

const PACING_RATE_UNIT: u64 = 1_000_000_000;

const CONGESTION_WINDOW_MULTIPLIER: u64 = 2;

const PKT_INFO_SLOT_COUNT: usize = 5;

const MIN_SAMPLE_COUNT: u64 = 50;

const MIN_ACK_RATE: f64 = 0.8;

#[derive(Debug, Clone)]
pub(crate) struct Pacer {
    mtu: u64,
    budget_at_last_sent: u64,
    last_sent: Option<Timestamp>,
    bandwidth: u64,
}

impl Pacer {
    pub fn new(mtu: u64, bandwidth: u64) -> Self {
        Self {
            mtu,
            budget_at_last_sent: 0,
            last_sent: None,
            bandwidth,
        }
    }

    pub fn sent_packet(&mut self, now: Timestamp, size: u64) {
        let budget = self.budget(now);
        if size > budget {
            self.budget_at_last_sent = 0;
        } else {
            self.budget_at_last_sent = budget - size;
        }
        self.last_sent = Some(now);
    }

    fn budget(&self, now: Timestamp) -> u64 {
        if let Some(timestamp) = self.last_sent {
            // budget := p.budgetAtLastSent + (p.getBandwidth()*congestion.ByteCount(now.Sub(p.lastSentTime).Nanoseconds()))/1e9
            let elapsed = now.saturating_duration_since(timestamp);
            let budget = self.budget_at_last_sent
                + (self.bandwidth * elapsed.as_nanos() as u64) / PACING_RATE_UNIT;
            budget.min(self.mtu)
        } else {
            self.max_burst_size()
        }
    }

    fn max_burst_size(&self) -> u64 {
        max(
            MAX_BURST_PACING_DELAY_MULTIPLIER * MIN_PACING_DEALY * self.bandwidth
                / PACING_RATE_UNIT,
            MAX_BURST_PACKETS * self.mtu,
        )
    }
    pub fn earliest_departure_time(&self) -> Option<Timestamp> {
        if self.budget_at_last_sent >= self.mtu {
            return None;
        }
        let diff = (self.mtu - self.budget_at_last_sent) * PACING_RATE_UNIT;
        let mut d = diff / self.bandwidth;
        if diff % self.bandwidth != 0 {
            d += 1;
        }
        Some(
            self.last_sent
                .clone()
                .unwrap_or_else(|| unsafe {
                    Timestamp::from_duration(std::time::Duration::from_secs(0))
                })
                .checked_add(Duration::from_nanos(d as u64))
                .unwrap_or_else(|| unsafe { Timestamp::from_duration(std::time::Duration::MAX) }),
        )
    }

    pub fn on_mtu_update(&mut self, mtu: u64) {
        self.mtu = mtu;
    }

    pub fn on_bandwidth_update(&mut self, bandwidth: u64) {
        self.bandwidth = bandwidth;
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AckInfo {
    pub time_sent: Timestamp,
    pub ack_count: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct LostInfo {
    pub time_sent: Timestamp,
    pub lost_count: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct Brutal {
    pacer: Pacer,
    mtu: u64,
    window: u64,
    bytes_in_flight: u32,
    bps: u64,
    ack_rate: f64,
    ack_info: [AckInfo; PKT_INFO_SLOT_COUNT],
    lost_info: [LostInfo; PKT_INFO_SLOT_COUNT],
}

impl Brutal {
    fn update_ack_rate(&mut self, now: Timestamp) {
        let min_time = now
            .checked_sub(Duration::from_secs(PKT_INFO_SLOT_COUNT as u64))
            .unwrap_or_else(|| unsafe { Timestamp::from_duration(Duration::from_secs(0)) });
        let mut ack_count = 0;
        for info in self.ack_info.iter() {
            if info.time_sent < min_time {
                continue;
            }
            ack_count += info.ack_count;
        }
        let mut lost_count = 0;
        for info in self.lost_info.iter() {
            if info.time_sent < min_time {
                continue;
            }
            lost_count += info.lost_count;
        }
        if ack_count + lost_count < self.min_sample_bytes() {
            self.ack_rate = 1.0;
            self.update_bandwidth();
            return;
        }
        let mut rate = (ack_count as f64) / (ack_count as f64 + lost_count as f64);
        if rate < MIN_ACK_RATE {
            rate = MIN_ACK_RATE;
        }
        self.ack_rate = rate;
        self.update_bandwidth();
    }

    fn update_bandwidth(&mut self) {
        self.pacer
            .on_bandwidth_update(self.bps / self.ack_rate as u64)
    }

    fn min_sample_bytes(&self) -> u64 {
        self.mtu / 3 * MIN_SAMPLE_COUNT
    }
}

impl CongestionController for Brutal {
    type PacketInfo = ();

    fn congestion_window(&self) -> u32 {
        self.window as u32
    }

    fn bytes_in_flight(&self) -> u32 {
        self.bytes_in_flight
    }

    fn is_congestion_limited(&self) -> bool {
        self.congestion_window() < self.bytes_in_flight
    }

    fn requires_fast_retransmission(&self) -> bool {
        false
    }

    fn on_packet_sent<Pub: Publisher>(
        &mut self,
        time_sent: Timestamp,
        sent_bytes: usize,
        _app_limited: Option<bool>,
        _rtt_estimator: &RttEstimator,
        _publisher: &mut Pub,
    ) -> Self::PacketInfo {
        self.pacer.sent_packet(time_sent, sent_bytes as u64);
        self.bytes_in_flight += sent_bytes as u32;
    }

    fn on_rtt_update<Pub: Publisher>(
        &mut self,
        _time_sent: Timestamp,
        _now: Timestamp,
        rtt_estimator: &RttEstimator,
        _publisher: &mut Pub,
    ) {
        let rtt = rtt_estimator.smoothed_rtt();
        let mut window_size =
            self.bps * rtt.as_secs() * CONGESTION_WINDOW_MULTIPLIER / self.ack_rate as u64;
        if window_size < self.mtu {
            window_size = self.mtu;
        }
        self.window = window_size;
    }

    fn on_ack<Pub: Publisher>(
        &mut self,
        _newest_acked_time_sent: Timestamp,
        bytes_acknowledged: usize,
        _newest_acked_packet_info: Self::PacketInfo,
        _rtt_estimator: &RttEstimator,
        _random_generator: &mut dyn RandomGenerator,
        ack_receive_time: Timestamp,
        _publisher: &mut Pub,
    ) {
        let seconds = unsafe { ack_receive_time.as_duration().as_secs() } as usize;
        let slot = seconds % PKT_INFO_SLOT_COUNT;
        if self.ack_info[slot].time_sent == ack_receive_time {
            self.ack_info[slot].ack_count += bytes_acknowledged as u64;
        } else {
            self.ack_info[slot].time_sent = ack_receive_time;
            self.ack_info[slot].ack_count = bytes_acknowledged as u64;
        }
        self.update_ack_rate(_newest_acked_time_sent);
        self.bytes_in_flight -= bytes_acknowledged as u32;
    }

    fn on_packet_lost<Pub: Publisher>(
        &mut self,
        lost_bytes: u32,
        _packet_info: Self::PacketInfo,
        _persistent_congestion: bool,
        _new_loss_burst: bool,
        _random_generator: &mut dyn RandomGenerator,
        timestamp: Timestamp,
        _publisher: &mut Pub,
    ) {
        let seconds = unsafe { timestamp.as_duration().as_secs() } as usize;
        let slot = seconds % PKT_INFO_SLOT_COUNT;
        if self.lost_info[slot].time_sent == timestamp {
            self.lost_info[slot].lost_count += lost_bytes as u64;
        } else {
            self.lost_info[slot].time_sent = timestamp;
            self.lost_info[slot].lost_count = lost_bytes as u64;
        }
        self.update_ack_rate(timestamp);
        self.bytes_in_flight -= lost_bytes as u32;
    }

    fn on_explicit_congestion<Pub: Publisher>(
        &mut self,
        _ce_count: u64,
        _event_time: Timestamp,
        _publisher: &mut Pub,
    ) {
        // No-op
    }

    fn on_mtu_update<Pub: Publisher>(&mut self, max_data_size: u16, _publisher: &mut Pub) {
        self.pacer.on_mtu_update(max_data_size as u64);
    }

    fn on_packet_discarded<Pub: Publisher>(&mut self, bytes_sent: usize, _publisher: &mut Pub) {
        self.bytes_in_flight -= bytes_sent as u32;
    }

    fn earliest_departure_time(&self) -> Option<Timestamp> {
        self.pacer.earliest_departure_time()
    }
}

#[derive(Debug, Clone)]
pub (crate) struct HysteriaCongestionEndpoint {
    bps_receiver: tokio::sync::watch::Receiver<u64>,
}

impl congestion_controller::Endpoint for HysteriaCongestionEndpoint {
    type CongestionController = Brutal;

    fn new_congestion_controller(&mut self, path_info: congestion_controller::PathInfo) -> Self::CongestionController {
        todo!()
    }
} 
