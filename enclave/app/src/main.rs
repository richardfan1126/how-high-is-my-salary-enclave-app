mod attestation;
mod encryption;
mod salary;

use std::sync::Mutex;
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_json::json;
use rocket::State;
use rocket::serde::{Deserialize, json::Json};

use attestation::get_attestation_doc;
use encryption::Encryption;

use salary::Salary;

#[macro_use] extern crate rocket;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct GetAttestationReq {
    nonce: String,
}

#[derive(Serialize)]
struct GetAttestationResponse {
    attestation_doc: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct AddEntryReq {
    public_key: String,
    encrypted_payload: String,
    encrypted_nonce: String,
}

#[derive(Serialize)]
struct AddEntryResponse {
    attestation_doc: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct GetPositionReq {
    public_key: String,
    encrypted_payload: String,
    encrypted_nonce: String,
}

#[derive(Serialize)]
struct GetPositionResponse {
    attestation_doc: String,
}

#[get("/health-check")]
fn health_check() -> String {
    "".to_string()
}

#[post("/get-attestation", data = "<req>")]
fn get_attestation(req: Json<GetAttestationReq>, encryption: &State<Encryption>) -> Json<GetAttestationResponse> {
    let nonce = Some(ByteBuf::from(req.nonce.to_owned()));
    let public_key = Some(encryption.get_pub_key_byte());
    let user_data = None;
    
    let attestation_doc = get_attestation_doc(public_key, user_data, nonce)
        .expect("Cannot get attestation document");

    Json(GetAttestationResponse {
        attestation_doc
    })
}

#[post("/add", data = "<req>")]
fn add_entry(req: Json<AddEntryReq>, encryption: &State<Encryption>, salary: &State<Mutex<Salary>>) -> Json<AddEntryResponse> {
    let client_pub_key_b64 = req.public_key.to_owned();
    let session_key = encryption.get_session_key(client_pub_key_b64);

    let encrypted_payload = req.encrypted_payload.to_owned();
    let payload = Encryption::decrypt(encrypted_payload, &session_key);

    let input_salary = payload.parse::<u32>()
        .expect("Input is not an integer");

    let uuid = salary
        .lock()
        .expect("Failed to obtain mutex lock")
        .add(input_salary);

    let response = Encryption::encrypt(uuid, &session_key);

    let encrypted_nonce = req.encrypted_nonce.to_owned();
    let nonce = Some(ByteBuf::from(Encryption::decrypt(encrypted_nonce, &session_key)));

    let public_key = None;
    let user_data = Some(ByteBuf::from(response));

    let attestation_doc = get_attestation_doc(public_key, user_data, nonce)
        .expect("Cannot get attestation document");

    Json(AddEntryResponse {
        attestation_doc
    })
}

#[post("/get-position", data = "<req>")]
fn get_position(req: Json<GetPositionReq>, encryption: &State<Encryption>, salary: &State<Mutex<Salary>>) -> Json<GetPositionResponse> {
    let client_pub_key_b64 = req.public_key.to_owned();
    let session_key = encryption.get_session_key(client_pub_key_b64);

    let encrypted_payload = req.encrypted_payload.to_owned();
    let uuid = Encryption::decrypt(encrypted_payload, &session_key);

    let position_and_total = salary
        .lock()
        .expect("Failed to obtain mutex lock")
        .get_position_and_total(uuid);

    let response = match position_and_total {
        Some(position_and_total) => {
            Some(Encryption::encrypt(json!(position_and_total).to_string(), &session_key))
        },
        None => None
    };

    let user_data = match response {
        Some(response) => Some(ByteBuf::from(response)),
        None => None
    };

    let encrypted_nonce = req.encrypted_nonce.to_owned();
    let nonce = Some(ByteBuf::from(Encryption::decrypt(encrypted_nonce, &session_key)));
    
    let public_key = None;

    let attestation_doc = get_attestation_doc(public_key, user_data, nonce)
        .expect("Cannot get attestation document");

    Json(GetPositionResponse {
        attestation_doc
    })
}

#[post("/clear")]
fn clear_record(salary: &State<Mutex<Salary>>) -> String {
    salary
        .lock()
        .expect("Failed to obtain mutex lock")
        .clear();

    "".to_string()
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .manage(Encryption::new())
        .manage(Mutex::new(Salary::new()))
        .mount("/", routes![
            health_check,
            get_attestation,
            add_entry,
            get_position,
            clear_record
        ])
}
