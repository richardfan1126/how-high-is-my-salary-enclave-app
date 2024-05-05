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
    nonce: String,
    encrypted_payload: String,
}

#[derive(Serialize)]
struct AddEntryResponse {
    attestation_doc: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct GetPositionReq {
    nonce: String,
    encrypted_payload: String,
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
        attestation_doc: attestation_doc
    })
}

#[post("/add", data = "<req>")]
fn add_entry(req: Json<AddEntryReq>, encryption: &State<Encryption>, salary: &State<Mutex<Salary>>) -> Json<AddEntryResponse> {
    let encrypted_payload = req.encrypted_payload.to_owned();
    let payload = encryption.decrypt(encrypted_payload);

    let input_salary = payload.parse::<u32>()
        .expect("Input is not an integer");

    let uuid = salary
        .lock()
        .expect("Failed to obtain mutex lock")
        .add(input_salary);

    let nonce = Some(ByteBuf::from(req.nonce.to_owned()));
    let public_key = None;
    let user_data = Some(ByteBuf::from(uuid));

    let attestation_doc = get_attestation_doc(public_key, user_data, nonce)
        .expect("Cannot get attestation document");

    Json(AddEntryResponse {
        attestation_doc: attestation_doc
    })
}

#[post("/get-position", data = "<req>")]
fn get_position(req: Json<GetPositionReq>, encryption: &State<Encryption>, salary: &State<Mutex<Salary>>) -> Json<GetPositionResponse> {
    let encrypted_payload = req.encrypted_payload.to_owned();
    let uuid = encryption.decrypt(encrypted_payload);

    let position_and_total = salary
        .lock()
        .expect("Failed to obtain mutex lock")
        .get_position_and_total(uuid);

    let user_data = match position_and_total {
        Some(position_and_total) => Some(ByteBuf::from(json!(position_and_total).to_string())),
        None => None
    };

    let nonce = Some(ByteBuf::from(req.nonce.to_owned()));
    let public_key = None;

    let attestation_doc = get_attestation_doc(public_key, user_data, nonce)
        .expect("Cannot get attestation document");

    Json(GetPositionResponse {
        attestation_doc: attestation_doc
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
