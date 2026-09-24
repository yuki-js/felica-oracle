//! Shared test fixture: one emulated card plus matching oracle material.
//!
//! Both sides are built from the same key material via felica-rs public API
//! (precedent: felica-rs's own `secure/test_util.rs`). Nothing mirrored here.

use felica::felica_standard::{
    EmulatedArea, EmulatedService, EmulatedSystem, FelicaStandardEmulator, ServiceCode,
    generate_service_keys_des,
};

use crate::config::AppConfig;

pub const IDM: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
pub const IDM_HEX: &str = "0102030405060708";
pub const PMM: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
pub const IDI: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
pub const PMI: [u8; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
pub const SYSTEM_KEY: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
pub const AREA_KEY: [u8; 8] = [0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB, 0xED, 0x0F];
pub const SERVICE_KEY: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
pub const SYSTEM_CODE: u16 = 0x0003;
pub const AREA: u16 = 0x0040;
pub const SERVICE: u16 = 0x0048;
pub const BLOCK: [u8; 16] = [0xAA; 16];

pub struct Fixture {
    pub card: FelicaStandardEmulator,
    pub gsk: [u8; 8],
    pub usk: [u8; 8],
}

/// Card holding the chain plus the GSK/USK the oracle is provisioned with.
pub fn setup() -> Fixture {
    let (gsk, usk) = generate_service_keys_des(&SYSTEM_KEY, &[AREA_KEY], &[SERVICE_KEY]);
    let mut system = EmulatedSystem::new(SYSTEM_CODE, IDM, PMM).expect("system");
    system.set_system_key(SYSTEM_KEY);
    system.set_idi_pmi(IDI, PMI);
    let mut area = EmulatedArea::new(AREA, 0x00FF).expect("area");
    area.set_key(AREA_KEY);
    let mut service = EmulatedService::with_blocks(ServiceCode::new(SERVICE), 0x0000, vec![BLOCK]);
    service.set_key(SERVICE_KEY);
    area.add_service(service).expect("service fits");
    system.add_area(area).expect("area fits");
    let mut card = FelicaStandardEmulator::new();
    card.add_system(system);
    Fixture { card, gsk, usk }
}

pub fn app_config(f: &Fixture) -> AppConfig {
    AppConfig {
        bind_addr: None,
        k_group: f.gsk,
        k_user: f.usk,
        system_code: SYSTEM_CODE,
        areas: vec![AREA],
        services: vec![SERVICE],
    }
}
