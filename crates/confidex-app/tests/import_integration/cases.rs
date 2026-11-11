use confidex_app::import::{self, CsvColumn, CsvMapping, Format, Limits, Options, Plan, formats};

pub const EXPORT_PASSWORD: &str = " Public test-only 密码 é e\u{301} ";

pub struct Case {
    pub name: &'static str,
    pub origin: &'static str,
    pub format: Format,
    pub input: &'static [u8],
    pub password: Option<&'static str>,
    pub keyfile: Option<&'static [u8]>,
    pub parser: import::Parser,
    pub total: usize,
    pub selected: usize,
}
pub const CASES: &[Case] = &[
    Case {
        name: "bitwarden-personal",
        origin: "bitwarden-json",
        format: Format::BitwardenJson,
        input: include_bytes!("../import_fixtures/bitwarden_json/personal.json"),
        password: None,
        keyfile: None,
        parser: formats::bitwarden_json::parse,
        total: 3,
        selected: 3,
    },
    Case {
        name: "bitwarden-organization",
        origin: "bitwarden-json",
        format: Format::BitwardenJson,
        input: include_bytes!("../import_fixtures/bitwarden_json/organization.json"),
        password: None,
        keyfile: None,
        parser: formats::bitwarden_json::parse,
        total: 1,
        selected: 1,
    },
    Case {
        name: "onepassword",
        origin: "onepassword1pux",
        format: Format::Onepassword1pux,
        input: include_bytes!("../import_fixtures/onepassword_1pux/account.1pux"),
        password: None,
        keyfile: None,
        parser: formats::onepassword_1pux::parse,
        total: 4,
        selected: 3,
    },
    Case {
        name: "keepass",
        origin: "keepass-xml",
        format: Format::KeepassXml,
        input: include_bytes!("../import_fixtures/keepass_xml/database.xml"),
        password: None,
        keyfile: None,
        parser: formats::keepass_xml::parse,
        total: 3,
        selected: 1,
    },
    Case {
        name: "csv",
        origin: "csv",
        format: Format::Csv,
        input: include_bytes!("../import_fixtures/csv/generic.csv"),
        password: None,
        keyfile: None,
        parser: formats::csv::parse,
        total: 2,
        selected: 2,
    },
    Case {
        name: "bitwarden-zip",
        origin: "bitwarden-zip",
        format: Format::BitwardenZip,
        input: include_bytes!("../import_fixtures/bitwarden_zip/personal.zip"),
        password: None,
        keyfile: None,
        parser: formats::bitwarden_zip::parse,
        total: 3,
        selected: 3,
    },
    Case {
        name: "bitwarden-encrypted",
        origin: "bitwarden-encrypted-json",
        format: Format::BitwardenEncryptedJson,
        input: include_bytes!("../import_fixtures/bitwarden_encrypted_json/pbkdf2-legacy.json"),
        password: Some(EXPORT_PASSWORD),
        keyfile: None,
        parser: formats::bitwarden_encrypted_json::parse,
        total: 3,
        selected: 3,
    },
];
const KDBX_PASSWORD: Case = Case {
    name: "kdbx-password",
    origin: "kdbx",
    format: Format::Kdbx,
    input: include_bytes!("../import_fixtures/kdbx/password.kdbx"),
    password: Some("PUBLIC-FIXTURE-DATABASE"),
    keyfile: None,
    parser: formats::kdbx::parse,
    total: 3,
    selected: 1,
};
const KDBX_KEY: &[u8] = include_bytes!("../import_fixtures/kdbx/public.key");
pub const KDBX: &[Case] = &[
    KDBX_PASSWORD,
    Case {
        name: "kdbx-keyfile",
        input: include_bytes!("../import_fixtures/kdbx/keyfile.kdbx"),
        password: None,
        keyfile: Some(KDBX_KEY),
        ..KDBX_PASSWORD
    },
    Case {
        name: "kdbx-both",
        input: include_bytes!("../import_fixtures/kdbx/both.kdbx"),
        keyfile: Some(KDBX_KEY),
        ..KDBX_PASSWORD
    },
    Case {
        name: "kdbx-empty-password",
        input: include_bytes!("../import_fixtures/kdbx/empty-password.kdbx"),
        password: Some(""),
        ..KDBX_PASSWORD
    },
    Case {
        name: "kdbx-empty-password-keyfile",
        input: include_bytes!("../import_fixtures/kdbx/empty-password-keyfile.kdbx"),
        password: Some(""),
        keyfile: Some(KDBX_KEY),
        ..KDBX_PASSWORD
    },
];
impl Case {
    pub fn plan(&self) -> Plan {
        self.plan_from(self.input)
    }
    pub fn plan_from(&self, input: &[u8]) -> Plan {
        let password = self.password.unwrap_or_default();
        let plan = self.try_plan_from(input, password).unwrap();
        assert_eq!(plan.items.len(), self.total, "{}", self.name);
        assert_eq!(
            plan.statistics.ready + plan.statistics.review,
            self.selected,
            "{}",
            self.name
        );
        plan
    }
    pub fn try_plan_from(&self, input: &[u8], password: &str) -> Result<Plan, import::Error> {
        import::prepare(
            self.format,
            input,
            &self.options(password),
            Limits::default(),
            &mut |_| true,
            self.parser,
        )
    }
    pub fn options(&self, password: &str) -> Options {
        let mut options = Options::default();
        options.source_instance = Some("public-integration-source".into());
        options.password = password.into();
        options.password_present = self.password.is_some();
        options.keyfile = self.keyfile.unwrap_or_default().to_vec();
        options.keyfile_present = self.keyfile.is_some();
        if self.format == Format::Csv {
            let mapping: serde_json::Value =
                serde_json::from_str(include_str!("../import_fixtures/csv/mapping.json")).unwrap();
            options.csv = Some(CsvMapping {
                delimiter: b',',
                header: true,
                columns: mapping["columns"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|column| CsvColumn {
                        index: column["index"].as_u64().unwrap() as usize,
                        target: column["target"].as_str().unwrap().into(),
                        name: column["name"].as_str().unwrap_or("").into(),
                    })
                    .collect(),
            });
        }
        options
    }
}
