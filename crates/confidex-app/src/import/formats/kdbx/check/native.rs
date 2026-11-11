fn main() {
    let mut args = std::env::args().skip(1);
    let profile = args
        .next()
        .expect("profile")
        .parse()
        .expect("numeric profile");
    let input = std::fs::read(args.next().expect("public input path")).expect("read public input");
    println!(
        "{}",
        serde_json::to_string(&confidex_kdbx_import_probe::perform(input, profile)).unwrap()
    );
}
