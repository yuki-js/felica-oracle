//! Oracle business logic: the `impl OracleImpl` processing behind the wire
//! handlers in [`super::handler`]. Wire translation stays there; everything
//! that decides, validates, or computes lives here.

use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;

use super::handler::OracleImpl;
use super::types::{
    AttestRequest, AttestResponse, ChallengeRequest, ChallengeResponse, SettleRequest,
    SettleResponse,
};

impl OracleImpl {
    pub async fn challenge_impl(
        &self,
        req: ChallengeRequest,
    ) -> RpcResult<ChallengeResponse> {
        let idm = req.idm_bytes().map_err(crate::error::invalid_params)?;
        let r1 = req.r1_bytes().map_err(crate::error::invalid_params)?;
        let oracle =
            crate::oracle::OracleKeys::new(self.config.k_group, self.config.k_user);
        if self.config.areas.is_empty() && self.config.services.is_empty() {
            return Err(crate::error::internal(
                "oracle node path not configured (set AREAS/SERVICES)",
            ));
        }
        let c1a = oracle.session(&idm).c1a(&r1);
        Ok(ChallengeResponse {
            c1a: hex::encode(c1a),
            system_code: self.config.system_code,
            areas: self.config.areas.clone(),
            services: self.config.services.clone(),
        })
    }

    pub async fn settle_impl(&self, req: SettleRequest) -> RpcResult<SettleResponse> {
        use crate::oracle::schedule;

        let idm = req.idm_bytes().map_err(crate::error::invalid_params)?;
        let r1 = req.r1_bytes().map_err(crate::error::invalid_params)?;
        let c1b = req.c1b_bytes().map_err(crate::error::invalid_params)?;
        let c2a = req.c2a_bytes().map_err(crate::error::invalid_params)?;
        let session =
            crate::oracle::OracleKeys::new(self.config.k_group, self.config.k_user)
                .session(&idm);
        // Genuine C1B authentication (possible only because `r1` is supplied):
        // `3DES(L,β,r1) == c1b`, else `C1B_MISMATCH` (spec §8.4).
        if !session.check_c1b(&r1, &c1b) {
            return Err(crate::error::c1b_mismatch());
        }
        let mut tid = [0u8; 6];
        tid.copy_from_slice(&r1[2..8]);
        let r2 = session.open_r2(&c2a);
        let c2b = session.c2b(&r2);
        let ecmd = match &req.read_spec {
            None => None,
            Some(rs) => {
                let index = self
                    .config
                    .services
                    .iter()
                    .position(|s| *s == rs.service)
                    .filter(|i| *i < 16)
                    .ok_or_else(|| {
                        crate::error::invalid_params(
                            "read service is not in the authenticated service list",
                        )
                    })?;
                Some(hex::encode({
                    let inner = schedule::read_block_payload(index as u8, rs.block);
                    let payload = schedule::build_cmd_payload(&tid, &inner);
                    let enc = schedule::encrypt_command(
                        schedule::READ_COMMAND_CODE,
                        &r2,
                        &payload,
                    );
                    schedule::frame_secure_command(schedule::READ_COMMAND_CODE, &enc)
                }))
            }
        };
        Ok(SettleResponse {
            c2b: hex::encode(c2b),
            ecmd,
        })
    }

    pub async fn attest_impl(&self, _req: AttestRequest) -> RpcResult<AttestResponse> {
        Err(ErrorObjectOwned::from(crate::error::not_implemented()))
    }
}
