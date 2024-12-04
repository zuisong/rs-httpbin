use time::{
    macros::{format_description, offset},
    OffsetDateTime,
};
fn main() {
    let d = OffsetDateTime::now_utc().to_offset(offset!(+8)).replace_offset(offset!(+1));

    println!(
        "{}",
        d.format(format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"))
            .unwrap()
    );
}
