//! Value geometry and actions. Clipboard I/O belongs to the host.
use super::{Icon, Metrics as M, fonts, icon_button, layout};
use crate::theme::Palette;
use eframe::egui::{self, Id, Rect, Response, Vec2};

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum CopyState {
    #[default]
    Idle,
    Pending,
    Copied,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Password,
    Multiline,
}
#[derive(Clone, Copy)]
pub struct Labels<'a> {
    pub copy: &'a str,
    pub pending: &'a str,
    pub copied: &'a str,
    pub failed: &'a str,
    pub show: &'a str,
    pub hide: &'a str,
    pub large: &'a str,
    pub empty: &'a str,
}
impl<'a> Labels<'a> {
    pub fn new(text: &'a [String; 8]) -> Self {
        Self {
            copy: &text[0],
            pending: &text[1],
            copied: &text[2],
            failed: &text[3],
            show: &text[4],
            hide: &text[5],
            large: &text[6],
            empty: &text[7],
        }
    }
}
pub struct ValueField<'a> {
    pub id: Id,
    pub value: &'a mut String,
    pub kind: Kind,
    pub protected: bool,
    pub editing: bool,
    pub enabled: bool,
    pub revealed: &'a mut bool,
    pub feedback: CopyState,
    pub labels: Labels<'a>,
}
pub struct Output {
    pub rect: Rect,
    pub input: Response,
    pub viewport: Rect,
    pub copy: Response,
    pub reveal: Option<Response>,
    pub large: Option<Response>,
    pub accessory: Option<Response>,
}
impl ValueField<'_> {
    pub fn show(self, ui: &mut egui::Ui, p: Palette) -> Output {
        self.show_inner(ui, p, None, "")
    }
    pub(super) fn show_password(
        self,
        ui: &mut egui::Ui,
        p: Palette,
        generate: &str,
        active: bool,
    ) -> Output {
        self.show_action(ui, p, generate, Icon::Generate, active, "")
    }
    pub(super) fn show_action(
        self,
        ui: &mut egui::Ui,
        p: Palette,
        label: &str,
        icon: Icon,
        active: bool,
        hint: &str,
    ) -> Output {
        self.show_inner(ui, p, Some((label, icon, active)), hint)
    }
    fn show_inner(
        self,
        ui: &mut egui::Ui,
        p: Palette,
        action_label: Option<(&str, Icon, bool)>,
        hint: &str,
    ) -> Output {
        let d = super::density(ui);
        let password = self.kind == Kind::Password;
        let protected = self.protected || password;
        let concealed = protected && !*self.revealed && !password;
        let side = d.icon;
        let actions = 1 + usize::from(protected) + usize::from(password);
        let actions_width = side * actions as f32 + M::XS * (actions - 1) as f32;
        let action_padding = if action_label.is_some() {
            side + M::XS
        } else {
            0.
        };
        let minimum = 40. + 2. * M::MD + action_padding;
        let stacked = ui.available_width() < minimum + M::SM + actions_width;
        let width = if stacked {
            ui.available_width()
        } else {
            (ui.available_width() - actions_width - M::SM).max(1.)
        };
        let mut input = None;
        let mut viewport = Rect::NOTHING;
        let mut copy = None;
        let mut reveal = None;
        let mut large = None;
        let mut accessory = None;
        let mut draw = |ui: &mut egui::Ui| {
            let font = if password {
                egui::FontId::monospace(d.body)
            } else {
                fonts::regular(d.body)
            };
            let padding = ui.fonts_mut(|f| (d.input - f.row_height(&font)) / 2.);
            let multiline = self.kind == Kind::Multiline;
            let height = if multiline { d.multiline } else { d.input };
            let mut mask = if self.value.is_empty() {
                String::new()
            } else {
                "••••••••••••••••".into()
            };
            let mut add_editor = |ui: &mut egui::Ui| {
                let buffer = if concealed {
                    &mut mask
                } else {
                    &mut *self.value
                };
                let mut editor = if multiline {
                    egui::TextEdit::multiline(buffer).desired_rows(1)
                } else {
                    egui::TextEdit::singleline(buffer).password(password && !*self.revealed)
                };
                let horizontal_padding = if multiline { 0. } else { M::MD };
                let margin = if multiline {
                    egui::Margin::ZERO
                } else {
                    egui::Margin {
                        left: horizontal_padding as i8,
                        right: (horizontal_padding + action_padding) as i8,
                        top: padding.max(0.).ceil() as i8,
                        bottom: padding.max(0.).floor() as i8,
                    }
                };
                if multiline {
                    editor = editor.frame(egui::Frame::NONE);
                }
                let editor = editor
                    .id(self.id.with("input"))
                    .font(font.clone())
                    .text_color(p.text)
                    .hint_text(if self.editing {
                        hint
                    } else {
                        self.labels.empty
                    })
                    .interactive(self.editing && !concealed)
                    .desired_width(ui.available_width().max(1.))
                    .margin(margin);
                input = Some(
                    ui.add_enabled_ui(self.enabled, |ui| {
                        if multiline {
                            ui.add_sized([ui.available_width(), height - 2. * (M::MD + 1.)], editor)
                        } else {
                            ui.add(editor)
                        }
                    })
                    .inner,
                );
            };
            viewport = ui
                .allocate_ui_with_layout(
                    Vec2::new(width, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        if multiline {
                            egui::Frame::NONE
                                .fill(p.background)
                                .stroke(egui::Stroke::new(1., p.border))
                                .corner_radius(M::FIELD_RADIUS)
                                .inner_margin(M::MD)
                                .show(ui, |ui| {
                                    layout::scroll(ui, "value-lines", false, &mut add_editor);
                                });
                        } else {
                            add_editor(ui);
                        }
                    },
                )
                .response
                .rect;
            if self.editing
                && let Some((label, icon, active)) = action_label
            {
                let rect = Rect::from_center_size(
                    egui::pos2(viewport.right() - M::XS - side / 2., viewport.center().y),
                    Vec2::new(side, side.max(ui.spacing().interact_size.y)),
                );
                let mut overlay = ui.new_child(
                    egui::UiBuilder::new()
                        .id_salt(self.id.with("generate"))
                        .max_rect(rect)
                        .layout(egui::Layout::left_to_right(egui::Align::Center)),
                );
                let response = icon_button(
                    &mut overlay,
                    Palette {
                        text_muted: if active { p.accent } else { p.text_muted },
                        ..p
                    },
                    label,
                    icon,
                    self.enabled,
                );
                response.widget_info(|| {
                    egui::WidgetInfo::selected(egui::Role::Button, self.enabled, active, label)
                });
                accessory = Some(response);
            }
            if stacked {
                ui.add_space(M::XS);
            }
            ui.allocate_ui_with_layout(
                Vec2::new(
                    if stacked {
                        ui.available_width()
                    } else {
                        actions_width
                    },
                    d.input,
                ),
                egui::Layout::left_to_right(egui::Align::Center).with_main_wrap(true),
                |ui| {
                    ui.spacing_mut().item_spacing.x = M::XS;
                    let usable = self.enabled && !self.value.is_empty();
                    if protected {
                        let r = icon_button(
                            ui,
                            p,
                            if *self.revealed {
                                self.labels.hide
                            } else {
                                self.labels.show
                            },
                            if *self.revealed {
                                Icon::EyeOff
                            } else {
                                Icon::Eye
                            },
                            self.enabled,
                        );
                        if r.clicked() {
                            *self.revealed = !*self.revealed;
                        }
                        reveal = Some(r);
                    }
                    let (icon, label) = match self.feedback {
                        CopyState::Idle => (Icon::Copy, self.labels.copy),
                        CopyState::Pending => (Icon::Refresh, self.labels.pending),
                        CopyState::Copied => (Icon::Check, self.labels.copied),
                        CopyState::Failed => (Icon::Alert, self.labels.failed),
                    };
                    copy = Some(icon_button(
                        ui,
                        p,
                        label,
                        icon,
                        usable && self.feedback != CopyState::Pending,
                    ));
                    if password {
                        large = Some(icon_button(
                            ui,
                            p,
                            self.labels.large,
                            Icon::LargeType,
                            usable,
                        ));
                    }
                },
            );
        };
        let rect = ui
            .push_id(self.id, |ui| {
                if stacked {
                    ui.vertical(&mut draw).response.rect
                } else {
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = M::SM;
                        draw(ui);
                    })
                    .response
                    .rect
                }
            })
            .inner;
        let input = input.unwrap();
        super::focus_ring(ui, viewport, input.has_focus(), p.accent);
        Output {
            rect,
            input,
            viewport,
            copy: copy.unwrap(),
            reveal,
            large,
            accessory,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn labels() -> Labels<'static> {
        Labels {
            copy: "Copy",
            pending: "Pending",
            copied: "Copied",
            failed: "Failed",
            show: "Show",
            hide: "Hide",
            large: "Large type",
            empty: "Empty",
        }
    }
    #[test]
    fn field_actions_end_at_the_card_padding_in_view_and_edit() {
        for screen in [390., 1320.] {
            for width in [320., 640.] {
                for kind in [Kind::Text, Kind::Password, Kind::Multiline] {
                    let ctx = egui::Context::default();
                    super::super::setup(&ctx);
                    let mut text = "Public spacing fixture".repeat(40);
                    let mut name = "Public field".to_owned();
                    let mut revealed = false;
                    for editing in [false, true] {
                        for _ in 0..3 {
                            let mut output = ctx.run_ui(
                                egui::RawInput {
                                    screen_rect: Some(Rect::from_min_size(
                                        egui::Pos2::ZERO,
                                        Vec2::new(screen, 800.),
                                    )),
                                    ..Default::default()
                                },
                                |ui| {
                                    super::super::apply_density(ui.ctx(), false);
                                    ui.set_width(width);
                                    ui.spacing_mut().item_spacing.y = M::XL;
                                    let p = crate::theme::THEMES[0].colors;
                                    let card = super::super::field::Field {
                                        id: Id::unique("spacing-card"),
                                        list: Id::unique("spacing-list"),
                                        name: &mut name,
                                        kind: "text",
                                        editing,
                                        move_label: "Move",
                                        remove_label: "Remove",
                                    }
                                    .show(ui, p, |ui| {
                                        ValueField {
                                            id: Id::unique("spacing-value"),
                                            value: &mut text,
                                            kind,
                                            protected: false,
                                            editing,
                                            enabled: true,
                                            revealed: &mut revealed,
                                            feedback: CopyState::Idle,
                                            labels: labels(),
                                        }
                                        .show(ui, p)
                                    });
                                    let r = card.inner;
                                    assert!(r.rect.top() - card.name.rect.bottom() <= M::SM);
                                    if kind == Kind::Text {
                                        assert!(
                                            card.rect.height() <= if editing { 120. } else { 100. }
                                        );
                                    }
                                    let last = r.large.as_ref().unwrap_or(&r.copy).rect;
                                    let inset = super::super::density(ui).field_padding + 1.;
                                    assert!(
                                        (card.rect.right() - last.right() - inset).abs() < 1.,
                                        "card={:?}, actions={last:?}",
                                        card.rect
                                    );
                                    assert!((r.rect.right() - last.right()).abs() < 1.);
                                },
                            );
                            output.textures_delta.clear();
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn password_generator_is_inline_and_does_not_move_actions() {
        for screen_width in [390., 1320.] {
            for width in [180., 320., 640.] {
                let ctx = egui::Context::default();
                super::super::setup(&ctx);
                let mut text = "public fixture".repeat(100);
                let mut revealed = false;
                let mut baseline = None;
                for (editing, enabled) in [(true, true), (false, true), (true, false)] {
                    for frame in 0..3 {
                        let mut output = ctx.run_ui(
                            egui::RawInput {
                                screen_rect: Some(Rect::from_min_size(
                                    egui::Pos2::ZERO,
                                    Vec2::new(screen_width, 800.),
                                )),
                                ..Default::default()
                            },
                            |ui| {
                                super::super::apply_density(ui.ctx(), false);
                                ui.set_width(width);
                                let r = ValueField {
                                    id: Id::unique("inline-password"),
                                    value: &mut text,
                                    kind: Kind::Password,
                                    protected: true,
                                    editing,
                                    enabled,
                                    revealed: &mut revealed,
                                    feedback: CopyState::Idle,
                                    labels: labels(),
                                }
                                .show_password(
                                    ui,
                                    crate::theme::THEMES[0].colors,
                                    "Generate",
                                    true,
                                );
                                if frame == 2 {
                                    assert_eq!(r.input.rect.x_range(), r.viewport.x_range());
                                    let geometry = [
                                        r.viewport,
                                        r.copy.rect,
                                        r.reveal.unwrap().rect,
                                        r.large.unwrap().rect,
                                    ];
                                    if let Some(expected) = baseline {
                                        assert_eq!(geometry, expected);
                                    } else {
                                        baseline = Some(geometry);
                                    }
                                    if editing {
                                        let opener = r.accessory.unwrap();
                                        assert!(
                                            r.input.rect.contains_rect(opener.rect),
                                            "generator must be inside the editor: input={:?}, button={:?}", r.input.rect, opener.rect
                                        );
                                        assert_eq!(opener.enabled(), enabled);
                                    } else {
                                        assert!(r.accessory.is_none());
                                    }
                                }
                            },
                        );
                        output.textures_delta.clear();
                    }
                }
            }
        }
    }
    #[test]
    fn note_size_and_actions_stay_fixed_when_content_is_revealed() {
        for screen_width in [390., 1320.] {
            for width in [180., 320., 640.] {
                for original in [
                    String::new(),
                    "Public note".into(),
                    "Public note\n\n".repeat(60),
                ] {
                    let ctx = egui::Context::default();
                    super::super::setup(&ctx);
                    let mut text = original.clone();
                    let mut baseline = None;
                    for (editing, state) in [
                        (false, false),
                        (true, false),
                        (true, true),
                        (false, true),
                        (false, false),
                    ] {
                        let mut revealed = state;
                        for frame in 0..3 {
                            let raw_input = egui::RawInput {
                                screen_rect: Some(Rect::from_min_size(
                                    egui::Pos2::ZERO,
                                    Vec2::new(screen_width, 800.),
                                )),
                                ..Default::default()
                            };
                            ctx.run_ui(raw_input, |ui| {
                                super::super::apply_density(ui.ctx(), false);
                                ui.set_width(width);
                                let r = ValueField {
                                    id: Id::unique("stable-note"),
                                    value: &mut text,
                                    kind: Kind::Multiline,
                                    protected: true,
                                    editing,
                                    enabled: true,
                                    revealed: &mut revealed,
                                    feedback: CopyState::Idle,
                                    labels: labels(),
                                }
                                .show(ui, crate::theme::THEMES[0].colors);
                                if frame == 2 {
                                    assert!((r.viewport.height() - 160.).abs() < 1.);
                                    assert!(
                                        (r.input.rect.top() - r.viewport.top() - M::MD - 1.).abs()
                                            < 1.,
                                        "note content must start at the top"
                                    );
                                    let geometry = [
                                        r.rect.size(),
                                        r.viewport.size(),
                                        r.copy.rect.min - r.rect.min,
                                        r.reveal.unwrap().rect.min - r.rect.min,
                                    ];
                                    if let Some(expected) = baseline {
                                        assert_eq!(
                                            geometry, expected,
                                            "width={width}, editing={editing}, revealed={state}"
                                        );
                                    } else {
                                        baseline = Some(geometry);
                                    }
                                }
                            })
                            .textures_delta
                            .clear();
                        }
                    }
                    assert_eq!(text, original);
                }
            }
        }
    }
    #[test]
    fn long_note_focus_stays_on_the_visible_viewport() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let p = crate::theme::THEMES[0].colors;
        crate::theme::THEMES[0].apply(&ctx);
        let mut text = "Public note\n".repeat(100);
        let mut shown = false;
        for frame in 0..3 {
            let mut viewport = Rect::NOTHING;
            let mut clip = Rect::NOTHING;
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                ui.set_width(320.);
                clip = ui.clip_rect();
                let r = ValueField {
                    id: Id::unique("bounded-note-focus"),
                    value: &mut text,
                    kind: Kind::Multiline,
                    protected: false,
                    editing: true,
                    enabled: true,
                    revealed: &mut shown,
                    feedback: CopyState::Idle,
                    labels: labels(),
                }
                .show(ui, p);
                r.input.request_focus();
                viewport = r.viewport;
            });
            output.textures_delta.clear();
            if frame > 0 {
                assert!(output.shapes.iter().any(|shape| {
                    matches!(&shape.shape, egui::Shape::Rect(r) if r.stroke.color == p.accent && r.rect == viewport.expand(2.).intersect(clip))
                }));
            }
            assert!(viewport.height() <= 161.);
        }
    }
    #[test]
    fn view_and_edit_values_center_text_with_their_actions() {
        for width in [390., 1320.] {
            let mut geometry = None;
            for editing in [false, true] {
                let ctx = egui::Context::default();
                super::super::setup(&ctx);
                crate::theme::THEMES[0].apply(&ctx);
                let mut text = "Public value".to_owned();
                let mut shown = false;
                let mut bounds = None;
                for frame in 0..3 {
                    let mut output = ctx.run_ui(
                        egui::RawInput {
                            screen_rect: Some(Rect::from_min_size(
                                egui::Pos2::ZERO,
                                Vec2::new(width, 800.),
                            )),
                            ..Default::default()
                        },
                        |ui| {
                            super::super::apply_density(ui.ctx(), false);
                            ui.set_width(300.);
                            bounds = Some(
                                ValueField {
                                    id: Id::unique("aligned-value"),
                                    value: &mut text,
                                    kind: Kind::Text,
                                    protected: false,
                                    editing,
                                    enabled: true,
                                    revealed: &mut shown,
                                    feedback: CopyState::Idle,
                                    labels: labels(),
                                }
                                .show(ui, crate::theme::THEMES[0].colors),
                            );
                        },
                    );
                    output.textures_delta.clear();
                    let r = bounds.as_ref().unwrap();
                    let current = [r.viewport, r.copy.rect];
                    if frame == 2 {
                        if let Some(expected) = geometry {
                            assert_eq!(current, expected, "view/edit moved the field actions");
                        } else {
                            geometry = Some(current);
                        }
                    }
                    assert!(
                        output.shapes.iter().any(|shape| {
                            matches!(&shape.shape, egui::Shape::Rect(frame)
                            if frame.stroke.width > 0. && frame.rect.contains_rect(r.viewport))
                        }),
                        "values need a visible boundary in view and edit mode"
                    );
                    let painted = output
                        .shapes
                        .iter()
                        .find_map(|shape| match &shape.shape {
                            egui::Shape::Text(t) if t.galley.job.text == text => {
                                Some(t.galley.rect.translate(t.pos.to_vec2()))
                            }
                            _ => None,
                        })
                        .unwrap();
                    assert!(
                        (painted.center().y - r.copy.rect.center().y).abs() < 1.,
                        "{width}, edit={editing}: {painted:?} vs {:?}",
                        r.copy.rect
                    );
                    assert!((painted.left() - r.rect.left() - M::MD).abs() < 1.);
                    assert_eq!(text, "Public value");
                }
            }
        }
    }
    #[test]
    fn an_empty_protected_note_can_be_revealed_then_edited() {
        fn frame(
            ctx: &egui::Context,
            text: &mut String,
            revealed: &mut bool,
            events: Vec<egui::Event>,
        ) -> Output {
            let mut response = None;
            ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    ui.set_width(320.);
                    response = Some(
                        ValueField {
                            id: Id::unique("empty-note"),
                            value: text,
                            kind: Kind::Multiline,
                            protected: true,
                            editing: true,
                            enabled: true,
                            revealed,
                            feedback: CopyState::Idle,
                            labels: labels(),
                        }
                        .show(ui, crate::theme::THEMES[0].colors),
                    );
                },
            )
            .textures_delta
            .clear();
            response.unwrap()
        }
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let mut text = String::new();
        let mut revealed = false;
        frame(&ctx, &mut text, &mut revealed, vec![]);
        let response = frame(&ctx, &mut text, &mut revealed, vec![]);
        assert!(!response.copy.enabled());
        let reveal = response.reveal.unwrap();
        assert!(reveal.enabled());
        for pressed in [true, false] {
            frame(
                &ctx,
                &mut text,
                &mut revealed,
                vec![
                    egui::Event::PointerMoved(reveal.rect.center()),
                    egui::Event::PointerButton {
                        pos: reveal.rect.center(),
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
        assert!(revealed);
        let response = frame(&ctx, &mut text, &mut revealed, vec![]);
        assert!((response.input.rect.height() - 134.).abs() < 1.);
        let point = response.viewport.center();
        for pressed in [true, false] {
            frame(
                &ctx,
                &mut text,
                &mut revealed,
                vec![
                    egui::Event::PointerMoved(point),
                    egui::Event::PointerButton {
                        pos: point,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
        let response = frame(
            &ctx,
            &mut text,
            &mut revealed,
            vec![egui::Event::Text("Public note".into())],
        );
        assert_eq!(text, "Public note");
        assert!(response.copy.enabled());
    }
    #[test]
    fn protected_notes_do_not_paint_their_content_until_revealed() {
        let secret = "Private-note-sentinel";
        for protected in [false, true] {
            for editing in [false, true] {
                for revealed in [false, true] {
                    let ctx = egui::Context::default();
                    super::super::setup(&ctx);
                    let mut text = secret.to_owned();
                    let mut shown = revealed;
                    let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                        ui.set_width(320.);
                        let r = ValueField {
                            id: Id::unique("protected-note"),
                            value: &mut text,
                            kind: Kind::Multiline,
                            protected,
                            editing,
                            enabled: true,
                            revealed: &mut shown,
                            feedback: CopyState::Idle,
                            labels: labels(),
                        }
                        .show(ui, crate::theme::THEMES[0].colors);
                        assert_eq!(r.reveal.is_some(), protected);
                        assert!(r.large.is_none());
                        assert!(
                            r.input.rect.height() <= r.viewport.height() + 0.5,
                            "short note should fit without scrolling"
                        );
                    });
                    output.textures_delta.clear();
                    let painted = output.shapes.iter().any(|shape| {
                        matches!(&shape.shape,
                        egui::Shape::Text(text) if text.galley.job.text.contains(secret))
                    });
                    assert_eq!(painted, !protected || revealed);
                    assert_eq!(text, secret);
                }
            }
        }
    }

    #[test]
    fn long_values_keep_actions_inside_the_slot_without_overlap() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let fixture = "AЖe\u{301}🔐".repeat(1024);
        for width in [180., 260., 320., 600.] {
            for kind in [Kind::Text, Kind::Password, Kind::Multiline] {
                for enabled in [true, false] {
                    let mut text = if kind == Kind::Multiline {
                        "public\n\n".repeat(60)
                    } else {
                        fixture.clone()
                    };
                    let original = text.clone();
                    let mut revealed = false;
                    ctx.run_ui(
                        egui::RawInput {
                            screen_rect: Some(Rect::from_min_size(
                                egui::Pos2::ZERO,
                                Vec2::new(900., 600.),
                            )),
                            ..Default::default()
                        },
                        |ui| {
                            ui.set_width(width);
                            let left = ui.cursor().left();
                            let r = ValueField {
                                id: Id::unique("stress"),
                                value: &mut text,
                                kind,
                                protected: false,
                                editing: true,
                                enabled,
                                revealed: &mut revealed,
                                feedback: CopyState::Idle,
                                labels: labels(),
                            }
                            .show(ui, crate::theme::THEMES[0].colors);
                            for rect in [r.rect, r.viewport, r.copy.rect] {
                                assert!(
                                    rect.left() >= left && rect.right() <= left + width + 1.,
                                    "{width}: {rect:?}"
                                );
                            }
                            assert!(
                                r.viewport.right() + M::SM <= r.copy.rect.left() + 1.
                                    || r.viewport.bottom() + M::XS <= r.copy.rect.top() + 1.
                            );
                            assert!(
                                r.viewport.height() <= super::super::density(ui).multiline + 1.
                            );
                            if let Some(large) = r.large {
                                assert_eq!(large.enabled(), enabled && !text.is_empty());
                            }
                            assert_eq!(r.copy.enabled(), enabled);
                        },
                    )
                    .textures_delta
                    .clear();
                    assert_eq!(text, original);
                    assert!(!revealed);
                }
            }
        }
    }
}
