use base64::prelude::*;
use serde_bytes::ByteBuf;

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

fn error_exit(msg: &str, code: i32, nsm_fd: i32) {
    eprintln!("{}", msg);
    nsm_exit(nsm_fd);

    std::process::exit(code);
}

pub fn get_attestation_doc(public_key: Option<ByteBuf>, user_data: Option<ByteBuf>, nonce: Option<ByteBuf>) -> Option<String> {
    let nsm_fd = nsm_init();

    if nsm_fd == -1 {
        error_exit("Not running in Nitro Enclave", -1, nsm_fd);
        return None;
    }

    let request = Request::Attestation {
        public_key,
        user_data,
        nonce,
    };

    let response = nsm_process_request(nsm_fd, request);
    
    match response {
        Response::Attestation{document} => {
            nsm_exit(nsm_fd);
            Some(BASE64_STANDARD.encode(document))
        },
        Response::Error(err) => {
            error_exit(format!("{:?}", err).as_str(), -1, nsm_fd);
            None
        },
        _ => {
            error_exit("Something went wrong", -1, nsm_fd);
            None
        }
    }
}
