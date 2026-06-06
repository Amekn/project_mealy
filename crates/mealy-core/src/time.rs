pub type Timestamp = time::OffsetDateTime;

pub fn now() -> Timestamp {
    time::OffsetDateTime::now_utc()
}
