use rusqlite::{Connection, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hex;
use chrono::Utc;


pub fn initialize_db() -> Result<Connection> {
  let conn = Connection::open("activity_log.db")?;

  conn.execute(
    "CREATE TABLE IF NOT EXISTS activity_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      event TEXT NOT NULL,
      hmac TEXT NOT NULL
    )",
    [],
  )?;

  Ok(conn)
}


// the reason we make this guy is because rust doesn't support const generics
// also it's a good practice
// hmac is abbreviation for hash-based message authentication code
type HmacSha256 = Hmac<Sha256>;

const SECRET_KEY: &[u8] = b"super secret key";

fn generate_hmac(message: &str) -> String {
  let mut mac = HmacSha256::new_from_slice(SECRET_KEY)
    .expect("Failed to create HmacSha256");

  mac.update(message.as_bytes());
  hex::encode(mac.finalize().into_bytes())
}


pub fn log_activity(conn: &Connection, event: &str) -> Result<()> {
  // rfc3339 is a standard date format
  let timestamp = Utc::now().to_rfc3339();
  let hmac = generate_hmac(&format!("{}:{}", timestamp, event));

  conn.execute(
    "INSERT INTO activity_log (timestamp, event, hmac) VALUES (?1, ?2, ?3)",
    &[&timestamp, event, &hmac],
  )?;

  Ok(())
}


pub fn read_logs(conn: &Connection) -> Result<()> {
  let mut stmt = conn.prepare("SELECT id, timestamp, event, hmac FROM activity_log")?;
  let log_iter = stmt.query_map([], |row| {
    Ok((
      row.get::<_, i32>(0)?,
      row.get::<_, String>(1)?,
      row.get::<_, String>(2)?,
      row.get::<_, String>(3)?,
    ))
  })?;

  for log in log_iter {
    let (id, timestamp, event, hmac) = log?;
    let data = format!("{}:{}", timestamp, event);
    let expected_hmac = generate_hmac(&data);

    if hmac == expected_hmac {
      println!("ID: {}, Timestamp: {}, Event: {}", id, timestamp, event);
    } else {
      println!("ID: {}, Timestamp: {}, Event: {} - HMAC MISMATCH!", id, timestamp, event);
    }
  }

  Ok(())
}