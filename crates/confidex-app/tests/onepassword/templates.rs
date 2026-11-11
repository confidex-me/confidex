use super::*;

const INPUT: &[u8] = include_bytes!("../import_fixtures/onepassword_1pux/templates.1pux");

#[test]
fn captured_templates_retain_every_item_field_and_document() {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(INPUT)).unwrap();
    assert_eq!(archive.len(), 4);
    assert!(
        archive
            .file_names()
            .all(|name| !name.unwrap().contains(".DS_Store"))
    );
    let source: Json = serde_json::from_reader(archive.by_name("export.data").unwrap()).unwrap();
    let account = &source["accounts"][0];
    let vault = &account["vaults"][0];
    let items = vault["items"].as_array().unwrap();
    let plan = run(INPUT).unwrap();
    assert_eq!(plan.items.len(), 22);
    assert_eq!(plan.statistics.blocked, 0);
    assert_eq!(plan.statistics.excluded, 0);
    let expected = [
        ("109", 8),
        ("107", 9),
        ("002", 16),
        ("112", 7),
        ("103", 11),
        ("006", 0),
        ("003", 0),
        ("102", 9),
        ("106", 11),
        ("100", 13),
        ("004", 25),
        ("108", 2),
        ("104", 7),
        ("001", 0),
        ("115", 3),
        ("110", 10),
        ("114", 1),
        ("001", 0),
        ("113", 8),
        ("101", 10),
        ("105", 8),
        ("111", 17),
    ];
    for ((item, raw), (category, fields)) in plan.items.iter().zip(items).zip(expected) {
        assert_eq!(raw["categoryUuid"], category);
        assert_eq!(
            raw["details"]["sections"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["fields"].as_array().unwrap().len())
                .sum::<usize>(),
            fields
        );
        assert_eq!(
            item.source.account.as_deref(),
            account["attrs"]["uuid"].as_str()
        );
        assert_eq!(
            item.source.vault.as_deref(),
            vault["attrs"]["uuid"].as_str()
        );
        assert_eq!(item.source.item.as_deref(), raw["uuid"].as_str());
        let attributes = item.source_attributes(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            serde_json::from_str::<Json>(attributes["item"].as_str().unwrap()).unwrap(),
            *raw
        );
        let record = item.record(MAX_OPEN_MEMORY).unwrap();
        assert_eq!(
            record.extra["confidex.title"].as_str(),
            raw["overview"]["title"].as_str()
        );
        assert!(record.entries.len() >= fields);
        for entry in record
            .entries
            .iter()
            .filter(|e| e.extra.contains_key("confidex.import.original"))
        {
            assert_eq!(entry.type_name, "secure-note/v1");
            let preserved: Json =
                serde_json::from_str(entry.value["text"].as_str().unwrap()).unwrap();
            assert_eq!(
                Some(&preserved["data"]),
                raw.pointer(preserved["path"].as_str().unwrap())
            );
        }
    }
    let document = plan.items[5].record(MAX_OPEN_MEMORY).unwrap();
    let file = document
        .entries
        .iter()
        .find(|e| e.type_name == "file/v1")
        .unwrap();
    assert_eq!(
        file.value["filename"].as_str(),
        Some("passport-public-sample.png")
    );
    use std::io::Read;
    let mut expected = Vec::new();
    archive
        .by_name("files/ipgch6ssxb5uzqoqfnnrcqkucu__passport-public-sample.png")
        .unwrap()
        .read_to_end(&mut expected)
        .unwrap();
    assert_eq!(file.value["data"].as_slice(), Some(expected.as_slice()));
    let context = plan.container_attributes(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(context["unmatched_files"].as_array().unwrap().len(), 1);
    assert_eq!(plan.container_status, Status::Review);
}
