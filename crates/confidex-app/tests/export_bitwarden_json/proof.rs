use confidex_app::{
    export::{self, Consent, Limits, Records},
    import::{
        self, Format, Options,
        formats::bitwarden_json::{self, Profile, Writer},
    },
};
use confidex_vault::{
    record::{Entry, Mapping, Record},
    resources::MAX_OPEN_MEMORY,
};
use serde_json::Value as Json;

pub fn run() {
    for profile in [Profile::Personal, Profile::Organization] {
        let mut options = Options::default();
        options.source_instance = Some("public-bitwarden-worker".into());
        let imported = import::prepare(
            Format::BitwardenJson,
            include_bytes!("../export_fixtures/bitwarden_json/card-identity.input.json"),
            &options,
            import::Limits::default(),
            &mut |_| true,
            bitwarden_json::parse,
        )
        .unwrap();
        let mut records = Records::new(Limits::default()).unwrap();
        for item in &imported.items {
            records.push(item.record(MAX_OPEN_MEMORY).unwrap()).unwrap();
        }
        let mut custom = Record::default();
        let uri = "otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45";
        custom.entries.push(import::totp::entry(uri).unwrap());
        custom
            .extra
            .insert("confidex.title".into(), "Public worker".into());
        for (kind, key, value) in [
            ("text/v1", "text", ""),
            ("secret/v1", "secret", "PUBLIC-HIDDEN"),
        ] {
            custom.entries.push(Entry {
                name: String::new(),
                type_name: kind.into(),
                value: Mapping::from([(key.into(), value.into())]),
                extra: Mapping::new(),
            });
        }
        records.push(custom).unwrap();
        let plan = export::prepare(records, Box::new(Writer::new(profile)), &mut |_| true).unwrap();
        assert!(plan.issues().is_empty());
        let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
        assert!(!artifact.file.encrypted);
        let output: Json = serde_json::from_slice(artifact.bytes()).unwrap();
        assert_eq!(output["items"][0]["type"], 3);
        assert_eq!(output["items"][0]["card"]["number"], "4111111111111111");
        assert_eq!(output["items"][1]["type"], 4);
        assert_eq!(
            output["items"][1]["identity"]["passportNumber"],
            "PUBLIC-OLD-ID"
        );
        assert_eq!(output["items"][2]["fields"][0]["name"], "");
        assert_eq!(output["items"][2]["fields"][0]["value"], "");
        assert_eq!(output["items"][2]["fields"][1]["type"], 1);
        assert_eq!(output["items"][2]["fields"][1]["value"], "PUBLIC-HIDDEN");
        assert_eq!(output["items"][2]["login"]["totp"], uri);
        let imported = import::prepare(
            Format::BitwardenJson,
            artifact.bytes(),
            &options,
            import::Limits::default(),
            &mut |_| true,
            bitwarden_json::parse,
        )
        .unwrap();
        assert_eq!(imported.items.len(), 3);
    }
}
