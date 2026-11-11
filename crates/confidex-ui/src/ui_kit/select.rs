//! A field-anchored select. Menus stay above or below their control.
use eframe::egui::{
    self, AtomExt as _, Atoms, IdSalt, InnerResponse, IntoAtoms, RectAlign, Ui,
    class::{Classes, HasClasses},
    widget_style::ButtonStyle,
};

pub struct Select<'a> {
    id: IdSalt,
    text: Atoms<'a>,
    width: Option<f32>,
    height: Option<f32>,
}
impl<'a> Select<'a> {
    pub fn from_id_salt(id: impl egui::AsIdSalt) -> Self {
        Self {
            id: IdSalt::new(id),
            text: Atoms::default(),
            width: None,
            height: None,
        }
    }
    pub fn selected_text(mut self, text: impl IntoAtoms<'a>) -> Self {
        self.text = text.into_atoms();
        self
    }
    pub fn width(mut self, width: f32) -> Self {
        self.width = Some(width);
        self
    }
    pub fn height(mut self, height: f32) -> Self {
        self.height = Some(height);
        self
    }
    pub fn show_ui<R>(
        self,
        ui: &mut Ui,
        contents: impl FnOnce(&mut Ui) -> R,
    ) -> InnerResponse<Option<R>> {
        let id = ui.make_persistent_id(self.id);
        let popup_id = id.with("popup");
        let open = egui::Popup::is_id_open(ui.ctx(), popup_id);
        let mut classes = Classes::default().with_class(egui::ComboBox::CLASS);
        classes.add_class_if(egui::ComboBox::CLASS_OPEN, open);
        let ButtonStyle { atom_layout } = ui.widget_style(id, &classes);
        let color = if open {
            ui.visuals().widgets.open.fg_stroke.color
        } else {
            ui.visuals().text_color()
        };
        let arrow = egui::Atom::paint(
            egui::Vec2::splat(ui.spacing().icon_width),
            move |ui, args| {
                let rect = egui::Rect::from_center_size(args.rect.center(), egui::vec2(8., 4.));
                ui.painter().add(egui::Shape::convex_polygon(
                    vec![rect.left_top(), rect.right_top(), rect.center_bottom()],
                    color,
                    egui::Stroke::NONE,
                ));
            },
        )
        .atom_grow(true)
        .atom_align(egui::Align2::RIGHT_CENTER);
        let accessible = self.text.text().map(String::from).unwrap_or_default();
        let width = self
            .width
            .unwrap_or(ui.spacing().combo_width)
            .min(ui.available_width())
            .max(1.);
        let response = atom_layout
            .apply(
                egui::WidgetAtom::new((self.text, arrow))
                    .id(id)
                    .sense(egui::Sense::click())
                    .fallback_font(egui::TextStyle::Button)
                    .wrap_mode(egui::TextWrapMode::Truncate),
            )
            .min_size(egui::vec2(width, ui.spacing().interact_size.y))
            .show(ui)
            .response;
        response.widget_info(|| {
            let mut info = egui::WidgetInfo::new(egui::Role::ComboBox);
            info.enabled = ui.is_enabled();
            info.current_text_value = Some(accessible.clone());
            info
        });
        let inner = anchored_menu(
            ui,
            &response,
            egui::Popup::menu(&response)
                .id(popup_id)
                .style(egui::style::StyleModifier::default()),
            self.height.unwrap_or(ui.spacing().combo_height),
            contents,
        );
        if inner.is_some() {
            ui.ctx().accesskit_node_builder(popup_id, |node| {
                node.set_role(egui::accesskit::Role::ListBox)
            });
        }
        InnerResponse { inner, response }
    }
}

/// Show a bounded menu on the column of its button.
pub fn menu<R>(
    ui: &Ui,
    response: &egui::Response,
    contents: impl FnOnce(&mut Ui) -> R,
) -> Option<R> {
    anchored_menu(
        ui,
        response,
        egui::Popup::menu(response),
        ui.spacing().combo_height,
        contents,
    )
}

fn anchored_menu<R>(
    ui: &Ui,
    response: &egui::Response,
    popup: egui::Popup<'_>,
    maximum: f32,
    contents: impl FnOnce(&mut Ui) -> R,
) -> Option<R> {
    if !response
        .interact_rect
        .intersect(ui.ctx().content_rect())
        .is_positive()
    {
        egui::Popup::close_id(ui.ctx(), popup.get_id());
        return None;
    }
    let frame = egui::Frame::popup(ui.style());
    let chrome = frame.total_margin().sum();
    let popup = popup.frame(frame);
    let anchor = popup.get_anchor_rect().unwrap_or(response.rect);
    // shortcut: Use a native host when menus must leave the OS window.
    let viewport = ui.ctx().content_rect();
    let maximum = maximum.max(0.);
    let expected = popup
        .get_expected_size()
        .map_or(maximum + chrome.y, |s| s.y);
    let below = (viewport.bottom() - anchor.bottom()).max(0.);
    let above = (anchor.top() - viewport.top()).max(0.);
    let down = below >= expected || below >= above;
    let height = maximum.min((if down { below } else { above } - chrome.y).max(0.));
    let align = match (down, anchor.left() + anchor.width() <= viewport.right()) {
        (true, true) => RectAlign::BOTTOM_START,
        (true, false) => RectAlign::BOTTOM_END,
        (false, true) => RectAlign::TOP_START,
        (false, false) => RectAlign::TOP_END,
    };
    let menu_width = anchor.width().min(viewport.width());
    popup
        .width(menu_width)
        .align(align)
        .align_alternatives(&[])
        .show(|ui| {
            ui.set_width((menu_width - chrome.x).max(1.));
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
            super::layout::scroll_area(
                ui,
                "select-options",
                egui::ScrollArea::vertical()
                    .max_height(height)
                    .min_scrolled_height(0.)
                    .min_scrolled_width(0.)
                    .auto_shrink([false, true]),
                1,
                contents,
            )
            .inner
        })
        .map(|r| r.inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::{Pos2, Rect, Vec2};
    fn draw(
        ctx: &egui::Context,
        viewport: egui::ViewportId,
        size: Vec2,
        pos: Pos2,
        events: Vec<egui::Event>,
        selected: &mut usize,
        long: bool,
    ) -> (egui::Response, Option<Rect>, Vec<Rect>) {
        let mut input = egui::RawInput {
            viewport_id: viewport,
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
            events,
            ..Default::default()
        };
        input.viewports.entry(viewport).or_default();
        let mut control = None;
        let mut popup = None;
        let mut items = Vec::new();
        let mut output = ctx.run_ui(input, |ui| {
            let mut field = ui.new_child(
                egui::UiBuilder::new()
                    .id_salt("form")
                    .max_rect(Rect::from_min_size(pos, egui::vec2(160., 36.)))
                    .layout(egui::Layout::top_down(egui::Align::Min)),
            );
            field.set_clip_rect(Rect::from_min_size(pos, egui::vec2(160., 36.)));
            let response = Select::from_id_salt("choice")
                .selected_text("Selected")
                .width(160.)
                .height(280.)
                .show_ui(&mut field, |ui| {
                    for i in 0..if long { 40 } else { 2 } {
                        let text = if i == 0 && long {
                            "Long option ".repeat(60)
                        } else {
                            format!("Option {i}")
                        };
                        items.push(ui.selectable_value(selected, i, text).rect);
                    }
                });
            popup = ui
                .ctx()
                .read_response(response.response.id.with("popup"))
                .map(|r| r.rect);
            control = Some(response.response);
        });
        output.textures_delta.clear();
        let response = control.unwrap();
        (response, popup, items)
    }
    fn click(
        ctx: &egui::Context,
        viewport: egui::ViewportId,
        size: Vec2,
        anchor: Pos2,
        point: Pos2,
        selected: &mut usize,
        long: bool,
    ) {
        for pressed in [true, false] {
            draw(
                ctx,
                viewport,
                size,
                anchor,
                vec![
                    egui::Event::PointerMoved(point),
                    egui::Event::PointerButton {
                        pos: point,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                selected,
                long,
            );
        }
    }
    #[test]
    fn menus_stay_on_the_field_column_and_use_the_viewport_instead_of_the_form_clip() {
        for viewport in [
            egui::ViewportId::ROOT,
            egui::ViewportId::from_hash_of("native-settings"),
        ] {
            for (size, pos) in [
                (egui::vec2(500., 300.), egui::pos2(320., 220.)),
                (egui::vec2(500., 300.), egui::pos2(320., 20.)),
                (egui::vec2(390., 200.), egui::pos2(200., 80.)),
                (egui::vec2(500., 100.), egui::pos2(320., 50.)),
            ] {
                for long in [false, true] {
                    let ctx = egui::Context::default();
                    super::super::setup(&ctx);
                    ctx.all_styles_mut(|s| s.animation_time = 0.);
                    let mut selected = 0;
                    let (control, _, _) =
                        draw(&ctx, viewport, size, pos, vec![], &mut selected, long);
                    click(
                        &ctx,
                        viewport,
                        size,
                        pos,
                        control.rect.center(),
                        &mut selected,
                        long,
                    );
                    let mut last = None;
                    for _ in 0..4 {
                        last = Some(draw(&ctx, viewport, size, pos, vec![], &mut selected, long));
                    }
                    let (control, popup, _) = last.unwrap();
                    let popup = popup.unwrap_or_else(|| {
                        panic!("missing popup: {viewport:?} {size:?} {pos:?} long={long}")
                    });
                    assert!(
                        (popup.left() - control.rect.left()).abs() < 1.,
                        "{viewport:?}, {size:?}: {popup:?} / {:?}",
                        control.rect
                    );
                    assert!(
                        (popup.width() - control.rect.width()).abs() < 1.,
                        "{popup:?} / {:?}",
                        control.rect
                    );
                    assert!(
                        popup.bottom() <= control.rect.top() + 1.
                            || popup.top() >= control.rect.bottom() - 1.,
                        "{popup:?} / {:?}",
                        control.rect
                    );
                    assert!(
                        Rect::from_min_size(Pos2::ZERO, size)
                            .expand(1.)
                            .contains_rect(popup),
                        "{viewport:?}: {popup:?}"
                    );
                    assert!(
                        popup.height() > 36.,
                        "menu was clipped to the form: {popup:?}"
                    );
                }
            }
        }
    }
    #[test]
    fn a_menu_closes_when_its_button_leaves_the_visible_form() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let viewport = egui::ViewportId::ROOT;
        let size = egui::vec2(500., 400.);
        let pos = egui::pos2(20., 80.);
        let mut selected = 0;
        let (control, _, _) = draw(&ctx, viewport, size, pos, vec![], &mut selected, true);
        click(
            &ctx,
            viewport,
            size,
            pos,
            control.rect.center(),
            &mut selected,
            true,
        );
        assert!(egui::Popup::is_id_open(&ctx, control.id.with("popup")));
        draw(
            &ctx,
            viewport,
            size,
            egui::pos2(20., 500.),
            vec![],
            &mut selected,
            true,
        );
        assert!(!egui::Popup::is_id_open(&ctx, control.id.with("popup")));
        assert_eq!(selected, 0);
    }

    #[test]
    fn an_open_menu_follows_its_field_after_resize_and_its_list_scrolls() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        ctx.all_styles_mut(|s| s.animation_time = 0.);
        let viewport = egui::ViewportId::ROOT;
        let mut selected = 3;
        let size = egui::vec2(500., 300.);
        let pos = egui::pos2(320., 220.);
        let (control, _, _) = draw(&ctx, viewport, size, pos, vec![], &mut selected, true);
        click(
            &ctx,
            viewport,
            size,
            pos,
            control.rect.center(),
            &mut selected,
            true,
        );
        for _ in 0..3 {
            draw(&ctx, viewport, size, pos, vec![], &mut selected, true);
        }
        let size = egui::vec2(600., 500.);
        let pos = egui::pos2(400., 40.);
        let mut last = None;
        for _ in 0..4 {
            last = Some(draw(&ctx, viewport, size, pos, vec![], &mut selected, true));
        }
        let (control, popup, items) = last.unwrap();
        let popup = popup.unwrap();
        assert!((popup.left() - control.rect.left()).abs() < 1.);
        assert!(popup.top() >= control.rect.bottom() - 1.);
        let first = items[0].top();
        draw(
            &ctx,
            viewport,
            size,
            pos,
            vec![
                egui::Event::PointerMoved(popup.center()),
                egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    source: egui::MouseWheelSource::Unknown,
                    phase: egui::TouchPhase::Move,
                    delta: egui::vec2(0., -180.),
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            &mut selected,
            true,
        );
        let mut last = None;
        for _ in 0..5 {
            last = Some(draw(&ctx, viewport, size, pos, vec![], &mut selected, true));
        }
        assert!(last.unwrap().2[0].top() < first - 1.);
        assert_eq!(selected, 3);
    }
    #[test]
    fn selection_closes_the_menu_and_escape_keeps_the_value() {
        let ctx = egui::Context::default();
        super::super::setup(&ctx);
        let viewport = egui::ViewportId::ROOT;
        let size = egui::vec2(500., 400.);
        let pos = egui::pos2(280., 60.);
        let mut selected = 0;
        let (control, _, _) = draw(&ctx, viewport, size, pos, vec![], &mut selected, false);
        click(
            &ctx,
            viewport,
            size,
            pos,
            control.rect.center(),
            &mut selected,
            false,
        );
        let mut items = vec![];
        for _ in 0..3 {
            items = draw(&ctx, viewport, size, pos, vec![], &mut selected, false).2;
        }
        click(
            &ctx,
            viewport,
            size,
            pos,
            items[1].center(),
            &mut selected,
            false,
        );
        assert_eq!(selected, 1);
        assert!(!egui::Popup::is_id_open(&ctx, control.id.with("popup")));
        ctx.memory_mut(|m| m.request_focus(control.id));
        for pressed in [true, false] {
            draw(
                &ctx,
                viewport,
                size,
                pos,
                vec![egui::Event::Key {
                    key: egui::Key::Space,
                    physical_key: None,
                    pressed,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                &mut selected,
                false,
            );
        }
        assert!(egui::Popup::is_id_open(&ctx, control.id.with("popup")));
        draw(
            &ctx,
            viewport,
            size,
            pos,
            vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            &mut selected,
            false,
        );
        assert_eq!(selected, 1);
        assert!(!egui::Popup::is_id_open(&ctx, control.id.with("popup")));
    }
}
