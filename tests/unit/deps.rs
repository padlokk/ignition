use hub::data_ext::serde_json::json;
use hub::random_ext::rand::Rng;

#[test]
fn hub_reexports() {
    let uuid = hub::data_ext::uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let json = hub::data_ext::serde_json::json!({
        "id": uuid.to_string(),
        "ts": now.to_rfc3339(),
    });

    assert!(json.get("id").is_some());

    // Ensure we can sample randomness via hub::random-ext
    let mut rng = hub::random_ext::rand::thread_rng();
    let value: u32 = rng.gen_range(0..100);
    assert!(value < 100);
}
