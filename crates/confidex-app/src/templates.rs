//! Starter sets share the ordinary ordered Record model.
use crate::{Error, Field};

pub struct FieldSpec {
    pub name: &'static str,
    pub type_name: &'static str,
    pub section: &'static str,
}

pub struct Template {
    pub id: &'static str,
    pub name: &'static str,
    pub fields: &'static [FieldSpec],
}

const fn spec(name: &'static str, type_name: &'static str, section: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        type_name,
        section,
    }
}

pub const FEATURED: usize = 6;
pub const CATALOG: &[Template] = &[
    Template {
        id: "login",
        name: "Login",
        fields: &[
            spec("Username", "username/v1", ""),
            spec("Password", "password/v1", ""),
            spec("Website", "url/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "secure-note",
        name: "Secure Note",
        fields: &[spec("Notes", "secure-note/v1", "")],
    },
    Template {
        id: "credit-card",
        name: "Credit Card",
        fields: &[
            spec("Card number", "secret/v1", ""),
            spec("Cardholder", "text/v1", ""),
            spec("Expiry", "text/v1", ""),
            spec("CVV", "secret/v1", ""),
            spec("PIN", "secret/v1", ""),
            spec("Brand", "text/v1", ""),
        ],
    },
    Template {
        id: "identity",
        name: "Identity",
        fields: &[
            spec("Full name", "text/v1", ""),
            spec("Document number", "text/v1", ""),
            spec("Date of birth", "text/v1", ""),
            spec("Country", "text/v1", ""),
            spec("Expires", "text/v1", ""),
            spec("Photo", "photo/v1", ""),
        ],
    },
    Template {
        id: "api-key",
        name: "API Credentials",
        fields: &[
            spec("Username", "username/v1", ""),
            spec("Credential", "secret/v1", ""),
            spec("Type", "text/v1", ""),
            spec("Filename", "text/v1", ""),
            spec("Valid from", "date/v1", ""),
            spec("Expires", "date/v1", ""),
            spec("Hostname", "text/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "document",
        name: "Document",
        fields: &[
            spec("Document", "file/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "ssh-key",
        name: "SSH Key",
        fields: &[spec("SSH key", "ssh/v1", ""), spec("Notes", "note/v1", "")],
    },
    Template {
        id: "bank-account",
        name: "Bank Account",
        fields: &[
            spec("Bank name", "text/v1", ""),
            spec("Name on account", "text/v1", ""),
            spec("Type", "text/v1", ""),
            spec("Routing number", "text/v1", ""),
            spec("Account number", "text/v1", ""),
            spec("SWIFT", "text/v1", ""),
            spec("IBAN", "text/v1", ""),
            spec("PIN", "password/v1", ""),
            spec("Phone", "text/v1", "Branch Information"),
            spec("Address", "text/v1", "Branch Information"),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "crypto-wallet",
        name: "Crypto Wallet",
        fields: &[
            spec("Recovery phrase", "password/v1", ""),
            spec("Password", "password/v1", ""),
            spec("Wallet address", "text/v1", "Wallet"),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "database",
        name: "Database",
        fields: &[
            spec("Type", "text/v1", ""),
            spec("Server", "text/v1", ""),
            spec("Port", "text/v1", ""),
            spec("Database", "text/v1", ""),
            spec("Username", "username/v1", ""),
            spec("Password", "password/v1", ""),
            spec("SID", "text/v1", ""),
            spec("Alias", "text/v1", ""),
            spec("Connection options", "text/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "driver-license",
        name: "Driver License",
        fields: &[
            spec("Full name", "text/v1", ""),
            spec("Address", "text/v1", ""),
            spec("Date of birth", "date/v1", ""),
            spec("Gender", "text/v1", ""),
            spec("Height", "text/v1", ""),
            spec("Number", "text/v1", ""),
            spec("License class", "text/v1", ""),
            spec("Conditions / restrictions", "text/v1", ""),
            spec("State", "text/v1", ""),
            spec("Country", "text/v1", ""),
            spec("Expiry date", "month-year/v1", ""),
            spec("Front side", "photo/v1", ""),
            spec("Back side", "photo/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "email",
        name: "Email",
        fields: &[
            spec("Type", "text/v1", ""),
            spec("Username", "username/v1", ""),
            spec("Server", "text/v1", ""),
            spec("Port number", "text/v1", ""),
            spec("Password", "password/v1", ""),
            spec("Security", "text/v1", ""),
            spec("Auth method", "text/v1", ""),
            spec("SMTP server", "text/v1", "SMTP"),
            spec("Port number", "text/v1", "SMTP"),
            spec("Username", "username/v1", "SMTP"),
            spec("Password", "password/v1", "SMTP"),
            spec("Security", "text/v1", "SMTP"),
            spec("Auth method", "text/v1", "SMTP"),
            spec("Provider", "text/v1", "Contact Information"),
            spec("Provider's website", "text/v1", "Contact Information"),
            spec("Phone (local)", "text/v1", "Contact Information"),
            spec("Phone (toll free)", "text/v1", "Contact Information"),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "medical-record",
        name: "Medical Record",
        fields: &[
            spec("Date", "date/v1", ""),
            spec("Location", "text/v1", ""),
            spec("Healthcare professional", "text/v1", ""),
            spec("Patient", "text/v1", ""),
            spec("Reason for visit", "note/v1", ""),
            spec("Medication", "text/v1", "Medication"),
            spec("Dosage", "text/v1", "Medication"),
            spec("Medication notes", "note/v1", "Medication"),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "membership",
        name: "Membership",
        fields: &[
            spec("Group", "text/v1", ""),
            spec("Website", "text/v1", ""),
            spec("Telephone", "text/v1", ""),
            spec("Member name", "text/v1", ""),
            spec("Member since", "month-year/v1", ""),
            spec("Expiry date", "month-year/v1", ""),
            spec("Member ID", "text/v1", ""),
            spec("PIN", "password/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "outdoor-license",
        name: "Outdoor License",
        fields: &[
            spec("Full name", "text/v1", ""),
            spec("Valid from", "date/v1", ""),
            spec("Expires", "date/v1", ""),
            spec("Approved wildlife", "text/v1", ""),
            spec("Maximum quota", "text/v1", ""),
            spec("State", "text/v1", ""),
            spec("Country", "text/v1", ""),
            spec("Front side", "photo/v1", ""),
            spec("Back side", "photo/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "passport",
        name: "Passport",
        fields: &[
            spec("Type", "text/v1", ""),
            spec("Issuing country", "text/v1", ""),
            spec("Number", "text/v1", ""),
            spec("Full name", "text/v1", ""),
            spec("Gender", "text/v1", ""),
            spec("Nationality", "text/v1", ""),
            spec("Issuing authority", "text/v1", ""),
            spec("Date of birth", "date/v1", ""),
            spec("Place of birth", "text/v1", ""),
            spec("Issued on", "date/v1", ""),
            spec("Expiry date", "date/v1", ""),
            spec("Front side", "photo/v1", ""),
            spec("Back side", "photo/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "password",
        name: "Password",
        fields: &[
            spec("Username", "username/v1", ""),
            spec("Password", "password/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "rewards",
        name: "Rewards",
        fields: &[
            spec("Company name", "text/v1", ""),
            spec("Member name", "text/v1", ""),
            spec("Member ID", "text/v1", ""),
            spec("PIN", "password/v1", ""),
            spec("Member ID (additional)", "text/v1", "More Information"),
            spec("Member since", "month-year/v1", "More Information"),
            spec("Customer service phone", "text/v1", "More Information"),
            spec("Phone for reservations", "text/v1", "More Information"),
            spec("Website", "text/v1", "More Information"),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "server",
        name: "Server",
        fields: &[
            spec("URL", "text/v1", ""),
            spec("Username", "username/v1", ""),
            spec("Password", "password/v1", ""),
            spec("Admin console URL", "text/v1", "Admin Console"),
            spec("Admin console username", "username/v1", "Admin Console"),
            spec("Console password", "password/v1", "Admin Console"),
            spec("Name", "text/v1", "Hosting Provider"),
            spec("Website", "text/v1", "Hosting Provider"),
            spec("Support URL", "text/v1", "Hosting Provider"),
            spec("Support phone", "text/v1", "Hosting Provider"),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "social-security-number",
        name: "Social Security Number",
        fields: &[
            spec("Name", "text/v1", ""),
            spec("Number", "password/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "software-license",
        name: "Software License",
        fields: &[
            spec("Version", "text/v1", ""),
            spec("License key", "secure-note/v1", ""),
            spec("Licensed to", "text/v1", "Customer"),
            spec("Registered email", "text/v1", "Customer"),
            spec("Company", "text/v1", "Customer"),
            spec("Download page", "text/v1", "Publisher"),
            spec("Publisher", "text/v1", "Publisher"),
            spec("Website", "text/v1", "Publisher"),
            spec("Retail price", "text/v1", "Publisher"),
            spec("Support email", "text/v1", "Publisher"),
            spec("Purchase date", "date/v1", "Order"),
            spec("Order number", "text/v1", "Order"),
            spec("Order total", "text/v1", "Order"),
            spec("License file", "file/v1", ""),
            spec("Front side", "photo/v1", ""),
            spec("Back side", "photo/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
    Template {
        id: "wireless-router",
        name: "Wireless Router",
        fields: &[
            spec("Base station name", "text/v1", ""),
            spec("Base station password", "password/v1", ""),
            spec("Server / IP address", "text/v1", ""),
            spec("AirPort ID", "text/v1", ""),
            spec("Network name", "text/v1", ""),
            spec("Wireless security", "wifi-qr/v1", ""),
            spec("Wireless network password", "password/v1", ""),
            spec("Attached storage password", "password/v1", ""),
            spec("Notes", "note/v1", ""),
        ],
    },
];

pub fn get(id: &str) -> Option<&'static Template> {
    CATALOG.iter().find(|template| template.id == id)
}

pub fn ids() -> impl Iterator<Item = &'static str> {
    CATALOG
        .iter()
        .map(|template| template.id)
        .chain(["wifi", "note", "empty"])
}

impl Template {
    pub fn sections(&self) -> Vec<crate::sections::Section> {
        let mut sections: Vec<crate::sections::Section> = Vec::new();
        for (index, field) in self.fields.iter().enumerate() {
            if field.section.is_empty() {
                continue;
            }
            if let Some(section) = sections.last_mut()
                && section.name == field.section
                && section.end() == index
            {
                section.count += 1;
            } else {
                sections.push(crate::sections::Section::new(field.section, index, 1));
            }
        }
        sections
    }

    pub fn fields(&self) -> Result<Vec<Field>, Error> {
        let mut fields = self
            .fields
            .iter()
            .map(|spec| {
                let mut field = crate::field(spec.type_name)?;
                field.name = spec.name.into();
                field.protected |= spec.type_name == "secret/v1";
                Ok(field)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        if self.id == "wireless-router" {
            fields[5].values.insert("ssid".into(), "4".into());
            fields[5].values.insert("password".into(), "6".into());
        }
        Ok(fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_matches_the_independent_field_contract() {
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/starter-catalog.json")).unwrap();
        let actual: Vec<_> = CATALOG
            .iter()
            .map(|template| {
                let fields: Vec<_> = template
                    .fields
                    .iter()
                    .map(|field| [field.name, field.type_name, field.section])
                    .collect();
                serde_json::json!({"id": template.id, "name": template.name, "fields": fields})
            })
            .collect();
        assert_eq!(serde_json::json!(actual), expected);
    }
    #[test]
    fn all_starter_fields_round_trip_through_the_ordinary_record_model() {
        for template in CATALOG {
            let fields = template.fields().unwrap();
            let sections = template.sections();
            let mut record = confidex_vault::record::Record::default();
            crate::sections::apply(&mut record, Some(&sections), fields.len()).unwrap();
            crate::fields::apply(&mut record, &fields).unwrap();
            let encoded = record
                .encode_content(confidex_vault::resources::MAX_OPEN_MEMORY)
                .unwrap();
            let restored = confidex_vault::record::Record::decode_content(
                &encoded.bytes,
                confidex_vault::resources::MAX_OPEN_MEMORY,
            )
            .unwrap()
            .record;
            let restored_fields = crate::fields::read(&restored).unwrap();
            assert_eq!(
                restored_fields.len(),
                template.fields.len(),
                "{}",
                template.id
            );
            for (field, spec) in restored_fields.iter().zip(template.fields) {
                assert_eq!(field.name, spec.name);
                assert_eq!(field.type_name, spec.type_name);
            }
            let restored_sections = crate::sections::read(&restored, &restored_fields).unwrap();
            assert_eq!(restored_sections.len(), sections.len());
            for (before, after) in sections.iter().zip(restored_sections) {
                assert_eq!(
                    (&before.name, before.start, before.count),
                    (&after.name, after.start, after.count)
                );
            }
        }
    }
    #[test]
    fn section_spans_cover_only_their_named_independent_fields() {
        for template in CATALOG {
            let sections = template.sections();
            crate::sections::validate(&sections, template.fields.len()).unwrap();
            for (index, field) in template.fields.iter().enumerate() {
                let section = sections
                    .iter()
                    .find(|section| section.start <= index && index < section.end());
                assert_eq!(
                    section.map_or("", |section| section.name.as_str()),
                    field.section
                );
            }
        }
        let email = get("email").unwrap().sections();
        assert_eq!(
            email
                .iter()
                .map(|section| section.name.as_str())
                .collect::<Vec<_>>(),
            ["SMTP", "Contact Information"]
        );
    }
    #[test]
    fn catalog_has_unique_templates_and_keeps_independent_source_fields() {
        let mut names = std::collections::BTreeSet::new();
        assert_eq!(CATALOG.len(), 22);
        assert_eq!(CATALOG[FEATURED - 1].id, "document");
        for template in CATALOG {
            assert!(names.insert(template.id));
            assert!(!template.fields.is_empty());
            assert!(template.fields.iter().all(|field| !field.name.is_empty()));
            assert!(
                template
                    .fields
                    .iter()
                    .all(|field| !matches!(field.type_name, "login/v1" | "api_key/v1"))
            );
        }
        for id in [
            "driver-license",
            "outdoor-license",
            "passport",
            "software-license",
        ] {
            let photos: Vec<_> = get(id)
                .unwrap()
                .fields
                .iter()
                .filter(|field| field.type_name == "photo/v1")
                .map(|field| field.name)
                .collect();
            assert_eq!(photos, ["Front side", "Back side"]);
        }
    }
    #[test]
    fn repeated_email_fields_and_router_links_keep_their_purpose() {
        let email = get("email").unwrap();
        assert_eq!(
            email
                .fields
                .iter()
                .filter(|field| field.name == "Password")
                .count(),
            2
        );
        assert_eq!(email.fields[10].section, "SMTP");
        let router = get("wireless-router").unwrap().fields().unwrap();
        assert_eq!(router[5].values["ssid"], "4");
        assert_eq!(router[5].values["password"], "6");
        assert_eq!(router[6].name, "Wireless network password");
        assert!(
            router
                .iter()
                .all(|field| field.source.is_none() && field.source_key.is_none())
        );
        assert_eq!(
            get("medical-record").unwrap().fields[1].type_name,
            "text/v1"
        );
    }
}
