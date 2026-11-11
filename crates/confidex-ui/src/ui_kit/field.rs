//! A shared field shell. The caller supplies the type label and value editor.
//! This component owns the header, actions, and field geometry.
use super::{
    Icon, Metrics as M, fonts,
    record::{TagRole, tag},
};
use crate::theme::Palette;
use eframe::egui::{self, Id, Rect, RichText, Sense, Vec2};

#[derive(Clone, Copy)]
struct FieldDrag {
    list: Id,
    field: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Remove,
    Up,
    Down,
}
pub struct Field<'a> {
    /// These IDs identify local UI state, not entries in the vault format.
    pub id: Id,
    pub list: Id,
    pub name: &'a mut String,
    pub kind: &'a str,
    pub editing: bool,
    pub move_label: &'a str,
    pub remove_label: &'a str,
}
pub struct Response<R> {
    pub rect: Rect,
    pub handle: egui::Response,
    pub name: egui::Response,
    pub kind: egui::Response,
    pub remove: Option<egui::Response>,
    pub action: Option<Action>,
    pub inner: R,
}
impl Field<'_> {
    pub fn show<R>(
        self,
        ui: &mut egui::Ui,
        p: Palette,
        body: impl FnOnce(&mut egui::Ui) -> R,
    ) -> Response<R> {
        self.show_frame(ui, p, true, body)
    }
    pub fn show_row<R>(
        self,
        ui: &mut egui::Ui,
        p: Palette,
        body: impl FnOnce(&mut egui::Ui) -> R,
    ) -> Response<R> {
        self.show_frame(ui, p, false, body)
    }
    fn show_frame<R>(
        self,
        ui: &mut egui::Ui,
        p: Palette,
        framed: bool,
        body: impl FnOnce(&mut egui::Ui) -> R,
    ) -> Response<R> {
        let d = super::density(ui);
        let header_height = if self.editing {
            d.control.max(32.)
        } else {
            24.
        };
        let padding = if framed { d.field_padding } else { M::XS };
        let origin = ui.cursor().min;
        let grip = Rect::from_min_size(
            origin + Vec2::splat(padding + 1.),
            Vec2::splat(header_height),
        );
        let handle = ui
            .interact(
                grip,
                self.id.with("handle"),
                if self.editing {
                    Sense::click_and_drag()
                } else {
                    Sense::hover()
                },
            )
            .on_hover_cursor(if self.editing {
                egui::CursorIcon::Grab
            } else {
                egui::CursorIcon::Default
            });
        if self.editing {
            if handle.clicked() {
                handle.request_focus();
            }
            handle.widget_info(|| {
                egui::WidgetInfo::labeled(egui::Role::Button, true, self.move_label)
            });
            handle.dnd_set_drag_payload(FieldDrag {
                list: self.list,
                field: self.id,
            });
        }
        let dragging = self.editing
            && egui::DragAndDrop::payload::<FieldDrag>(ui.ctx())
                .is_some_and(|d| d.list == self.list && d.field == self.id);
        let mut action = None;
        if self.editing && handle.has_focus() {
            action = ui.input_mut(|i| {
                if i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                    Some(Action::Up)
                } else if i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                    Some(Action::Down)
                } else {
                    None
                }
            });
        }
        let layer = egui::LayerId::new(egui::Order::Tooltip, self.id.with("drag"));
        let builder = if dragging {
            egui::UiBuilder::new().id_salt(self.id).layer_id(layer)
        } else {
            egui::UiBuilder::new().id_salt(self.id)
        };
        let result = ui
            .scope_builder(builder, |ui| {
                let base = if framed || dragging {
                    super::card(p)
                } else {
                    super::Card {
                        frame: egui::Frame::NONE,
                    }
                };
                let frame = base
                    .fill(if dragging {
                        p.control
                    } else if framed {
                        p.surface
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .stroke(if framed || dragging || handle.has_focus() {
                        egui::Stroke::new(
                            1.,
                            if dragging || handle.has_focus() {
                                p.accent
                            } else {
                                p.border
                            },
                        )
                    } else {
                        egui::Stroke::NONE
                    })
                    .inner_margin(padding)
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = M::XS;
                        let mut remove = None;
                        let header = ui
                            .allocate_ui_with_layout(
                                Vec2::new(ui.available_width(), header_height),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.spacing_mut().interact_size.y = header_height;
                                    if self.editing {
                                        let (rect, _) = ui.allocate_exact_size(
                                            Vec2::splat(header_height),
                                            Sense::hover(),
                                        );
                                        Icon::Grip.paint(
                                            ui,
                                            rect,
                                            if dragging || handle.hovered() {
                                                p.accent
                                            } else {
                                                p.text_muted
                                            },
                                        );
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if self.editing {
                                                let r = super::icon_button(
                                                    ui,
                                                    p,
                                                    self.remove_label,
                                                    Icon::Trash,
                                                    true,
                                                );
                                                if r.clicked() {
                                                    action = Some(Action::Remove);
                                                }
                                                remove = Some(r);
                                            }
                                            let type_width = ui
                                                .fonts_mut(|f| {
                                                    f.layout_no_wrap(
                                                        self.kind.to_owned(),
                                                        fonts::medium(M::CAPTION),
                                                        p.text_muted,
                                                    )
                                                    .size()
                                                    .x + 12.
                                                })
                                                .min(ui.available_width() * 0.45);
                                            let kind = ui
                                                .allocate_ui_with_layout(
                                                    Vec2::new(type_width, header_height),
                                                    egui::Layout::right_to_left(
                                                        egui::Align::Center,
                                                    ),
                                                    |ui| tag(ui, p, self.kind, TagRole::Type),
                                                )
                                                .inner
                                                .on_hover_text(self.kind);
                                            let width = ui.available_width().max(1.);
                                            let name = ui
                                                .allocate_ui_with_layout(
                                                    Vec2::new(width, header_height),
                                                    egui::Layout::left_to_right(
                                                        egui::Align::Center,
                                                    ),
                                                    |ui| {
                                                        if self.editing {
                                                            ui.add(
                                                                egui::TextEdit::singleline(
                                                                    self.name,
                                                                )
                                                                .id(self
                                                                    .id
                                                                    .with(("header", "name")))
                                                                .font(fonts::medium(d.body))
                                                                .hint_text(self.kind)
                                                                .frame(egui::Frame::NONE)
                                                                .margin(Vec2::ZERO)
                                                                .min_size(Vec2::new(
                                                                    width,
                                                                    header_height,
                                                                ))
                                                                .align(egui::Align2::LEFT_CENTER)
                                                                .desired_width(width),
                                                            )
                                                        } else {
                                                            ui.add(
                                                                egui::Label::new(
                                                                    RichText::new(
                                                                        if self.name.is_empty() {
                                                                            self.kind
                                                                        } else {
                                                                            self.name.as_str()
                                                                        },
                                                                    )
                                                                    .font(fonts::medium(d.body)),
                                                                )
                                                                .truncate(),
                                                            )
                                                        }
                                                    },
                                                )
                                                .inner;
                                            (name, kind)
                                        },
                                    )
                                    .inner
                                },
                            )
                            .inner;
                        let inner = body(ui);
                        (header.0, header.1, remove, inner)
                    });
                (frame.response.rect, frame.inner)
            })
            .inner;
        let (rect, (name, kind, remove, inner)) = result;
        if dragging {
            ui.painter().rect(
                rect,
                M::RADIUS,
                p.background,
                egui::Stroke::new(1., p.border),
                egui::StrokeKind::Inside,
            );
            if let Some(delta) = ui.input(|i| {
                i.pointer
                    .interact_pos()
                    .zip(i.pointer.press_origin())
                    .map(|(now, start)| now - start)
            }) {
                ui.ctx().transform_layer_shapes(
                    layer,
                    egui::emath::TSTransform::from_translation(delta),
                );
            }
            ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
        }
        Response {
            rect,
            handle: handle.on_hover_text(self.move_label),
            name,
            kind,
            remove,
            action,
            inner,
        }
    }
}

/// Returns an insertion slot. Applying the move is the caller's responsibility.
pub fn drop_target(
    ui: &mut egui::Ui,
    p: Palette,
    list: Id,
    cards: &[(Id, Rect)],
) -> Option<(Id, usize)> {
    let drag = egui::DragAndDrop::payload::<FieldDrag>(ui.ctx())?;
    if drag.list != list {
        return None;
    }
    let pos = ui.ctx().pointer_interact_pos()?;
    let first = cards.first()?.1;
    let last = cards.last()?.1;
    let area = first.union(last).expand(M::SM).intersect(ui.clip_rect());
    if !area.contains(pos) {
        return None;
    }
    let slot = cards
        .iter()
        .position(|(_, r)| pos.y < r.center().y)
        .unwrap_or(cards.len());
    let y = if slot == cards.len() {
        last.bottom() + M::XS
    } else {
        cards[slot].1.top() - M::XS
    };
    ui.painter()
        .hline(first.x_range(), y, egui::Stroke::new(2., p.accent));
    let step = ui.input(|i| i.stable_dt.min(0.05)) * 180.;
    if pos.y < ui.clip_rect().top() + M::XL {
        ui.scroll_with_delta(Vec2::new(0., step));
    }
    if pos.y > ui.clip_rect().bottom() - M::XL {
        ui.scroll_with_delta(Vec2::new(0., -step));
    }
    if ui.input(|i| i.pointer.any_released()) {
        egui::DragAndDrop::take_payload::<FieldDrag>(ui.ctx());
        Some((drag.field, slot))
    } else {
        None
    }
}

pub fn move_to_slot<T>(items: &mut [T], from: usize, slot: usize) -> bool {
    if from >= items.len() || slot > items.len() {
        return false;
    }
    let to = if slot > from { slot - 1 } else { slot };
    if to == from {
        return false;
    }
    if from < to {
        items[from..=to].rotate_left(1);
    } else {
        items[to..=from].rotate_right(1);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::super::record::{contents, heading};
    use super::*;
    #[test]
    fn short_records_stay_compact_and_long_records_keep_their_actions_visible() {
        for width in [320., 960., 1920.] {
            for count in [1, 8] {
                let ctx = egui::Context::default();
                super::super::setup(&ctx);
                let p = crate::theme::THEMES[0].colors;
                let mut title = String::new();
                let mut names = vec![String::new(); count];
                let mut values = vec![String::new(); count];
                for frame in 0..3 {
                    let mut column = Rect::NOTHING;
                    let mut cards = Vec::new();
                    let mut geometry = None;
                    let mut output = ctx.run_ui(
                        egui::RawInput {
                            screen_rect: Some(Rect::from_min_size(
                                egui::Pos2::ZERO,
                                Vec2::new(width, 600.),
                            )),
                            ..Default::default()
                        },
                        |ui| {
                            super::super::apply_density(ui.ctx(), false);
                            super::super::layout::content_column(ui, |ui| {
                                column = ui.max_rect();
                                geometry = Some(contents(
                                    ui,
                                    "compact-record",
                                    ui.available_height(),
                                    super::super::density(ui).control,
                                    |ui| {
                                        heading(ui, &mut title, true, "Record title");
                                        for i in 0..count {
                                            let r = Field {
                                                id: Id::unique(i),
                                                list: Id::unique("fields"),
                                                name: &mut names[i],
                                                kind: "Login",
                                                editing: true,
                                                move_label: "Move",
                                                remove_label: "Remove",
                                            }
                                            .show(ui, p, |ui| {
                                                super::super::field(
                                                    ui,
                                                    &mut values[i],
                                                    false,
                                                    false,
                                                    true,
                                                )
                                            });
                                            cards.push(r.rect);
                                        }
                                    },
                                    Some(|ui: &mut egui::Ui| {
                                        super::super::button(
                                            ui,
                                            p,
                                            "Add field",
                                            super::super::ButtonRole::Quiet,
                                            0.,
                                            true,
                                        );
                                    }),
                                ));
                            });
                        },
                    );
                    output.textures_delta.clear();
                    if frame == 2 {
                        let geometry = geometry.unwrap();
                        assert!(column.width() <= M::CONTENT_WIDTH);
                        assert!((column.center().x - ctx.content_rect().center().x).abs() < 1.);
                        assert!(geometry.content.bottom() + M::LG <= geometry.footer.top());
                        assert!(geometry.footer.bottom() <= ctx.content_rect().bottom());
                        if count == 1 {
                            assert!(geometry.content.contains_rect(cards[0]));
                            assert!(geometry.footer.top() - cards[0].bottom() < 40.);
                            for hint in ["Record title", "Login"] {
                                assert!(output.shapes.iter().any(|s| matches!(&s.shape, egui::Shape::Text(t) if t.galley.job.text == hint)));
                            }
                        }
                        assert!(title.is_empty() && names.iter().all(String::is_empty));
                    }
                }
            }
        }
    }
    #[test]
    fn field_frame_contains_header_actions_and_value_at_each_width() {
        for width in [260., 320., 680.] {
            let ctx = egui::Context::default();
            super::super::setup(&ctx);
            let p = crate::theme::THEMES[0].colors;
            crate::theme::THEMES[0].apply(&ctx);
            let mut name = "one-time code with a long name".to_owned();
            let mut value = "Public fixture".to_owned();
            for _ in 0..3 {
                let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                    ui.set_width(width);
                    let card = Field {
                        id: Id::unique("field"),
                        list: Id::unique("list"),
                        name: &mut name,
                        kind: "One-time code",
                        editing: true,
                        move_label: "Move",
                        remove_label: "Remove",
                    }
                    .show(ui, p, |ui| {
                        super::super::field(ui, &mut value, false, false, true)
                    });
                    assert!(
                        (card.rect.width() - width).abs() < 0.1,
                        "{width}: {:?}",
                        card.rect
                    );
                    assert!(card.rect.contains_rect(card.handle.rect));
                    assert!(card.rect.contains_rect(card.remove.as_ref().unwrap().rect));
                    assert!(card.rect.contains_rect(card.inner.rect));
                    assert!(
                        (card.inner.rect.left()
                            - card.rect.left()
                            - super::super::density(ui).field_padding
                            - 1.)
                            .abs()
                            < 0.1
                    );
                    assert!(card.name.rect.left() > card.inner.rect.left());
                    assert!(card.rect.height() < 180.);
                    assert!(card.name.rect.bottom() < card.inner.rect.top());
                    assert!(card.name.rect.right() < card.remove.unwrap().rect.left());
                    assert!(card.kind.rect.left() >= card.name.rect.right());
                });
                output.textures_delta.clear();
            }
        }
    }
    #[test]
    fn type_badges_stay_beside_delete_for_empty_and_matching_names() {
        for width in [260., 390., 680.] {
            for editing in [true, false] {
                for original in ["", "Date", "A longer field name"] {
                    let ctx = egui::Context::default();
                    super::super::setup(&ctx);
                    let mut name = original.to_owned();
                    for _ in 0..3 {
                        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                            ui.set_width(width);
                            let card = Field {
                                id: Id::unique("field"),
                                list: Id::unique("list"),
                                name: &mut name,
                                kind: "Date",
                                editing,
                                move_label: "Move",
                                remove_label: "Remove",
                            }
                            .show(
                                ui,
                                crate::theme::THEMES[0].colors,
                                |_| {},
                            );
                            let right = card.remove.as_ref().map_or(
                                card.rect.right() - super::super::density(ui).field_padding - 1.,
                                |remove| remove.rect.left() - ui.spacing().item_spacing.x,
                            );
                            assert!((card.kind.rect.right() - right).abs() < 1.);
                            assert!(card.name.rect.right() <= card.kind.rect.left());
                            if editing {
                                assert!(card.name.rect.width() > width * 0.35);
                            }
                        });
                        output.textures_delta.clear();
                    }
                    assert_eq!(name, original);
                }
            }
        }
    }
    #[test]
    fn moving_slots_preserves_values_and_handles_ends() {
        let mut items = [(0, "same", "one"), (1, "same", "two"), (2, "", "three")];
        assert!(move_to_slot(&mut items, 0, 3));
        assert_eq!(items.map(|v| v.0), [1, 2, 0]);
        assert!(move_to_slot(&mut items, 2, 0));
        assert_eq!(
            items,
            [(0, "same", "one"), (1, "same", "two"), (2, "", "three")]
        );
        assert!(!move_to_slot(&mut items, 1, 2));
        assert!(!move_to_slot(&mut items, 3, 0));
        assert!(!move_to_slot(&mut items, 0, 4));
    }
}
