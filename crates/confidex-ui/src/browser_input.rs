fn pasted_fragment(before: &str, start: u32, end: u32, after: &str) -> Option<String> {
    if start > end {
        return None;
    }
    let before = zeroize::Zeroizing::new(before.encode_utf16().collect::<Vec<_>>());
    let prefix = zeroize::Zeroizing::new(String::from_utf16(before.get(..start as usize)?).ok()?);
    let suffix = zeroize::Zeroizing::new(String::from_utf16(before.get(end as usize..)?).ok()?);
    after
        .strip_prefix(prefix.as_str())?
        .strip_suffix(suffix.as_str())
        .map(str::to_owned)
}

#[cfg(target_arch = "wasm32")]
pub use web::{TextInput, install};

#[cfg(target_arch = "wasm32")]
mod web {
    use super::pasted_fragment;
    use eframe::egui;
    use std::{cell::RefCell, rc::Rc};
    use wasm_bindgen::{JsCast, JsValue};
    use web_sys::{
        ClipboardEvent, HtmlCanvasElement, HtmlInputElement, InputEvent, PointerEvent, TouchEvent,
    };
    use zeroize::Zeroizing;

    #[derive(Default)]
    pub struct TextInput {
        input_id: String,
        focus: Option<(egui::Id, egui::IMEPurpose)>,
        pending: Vec<egui::Event>,
        clear_buffer: bool,
        native_gesture: bool,
    }

    impl TextInput {
        pub fn new(input_id: String) -> Self {
            Self {
                input_id,
                ..Self::default()
            }
        }

        fn paste(&mut self, text: String) {
            self.native_gesture = false;
            self.pending
                .push(egui::Event::Paste(text.replace("\r\n", "\n")));
            self.clear_buffer = true;
        }
    }

    impl egui::plugin::Plugin for TextInput {
        fn debug_name(&self) -> &'static str {
            "Browser text input"
        }

        fn input_hook(&mut self, _: &egui::Context, input: &mut egui::RawInput) {
            input.events.append(&mut self.pending);
        }

        fn on_end_pass(&mut self, ui: &mut egui::Ui) {
            if ui.will_discard() {
                return;
            }
            let mut ime = ui.output(|output| output.ime);
            let purpose = ime.map(|ime| ime.purpose);
            let focus = ui.memory(|memory| memory.focused()).zip(purpose);
            if focus != self.focus || self.clear_buffer {
                self.native_gesture = false;
            }
            if self.native_gesture {
                return;
            }
            if self.clear_buffer || focus.is_some() && focus != self.focus {
                // Reset the shared buffer after paste or a change of text field.
                ui.memory_mut(|memory| memory.interrupt_ime());
            }
            self.clear_buffer = false;
            self.focus = focus;
            if let Some(response) = focus.and_then(|(id, _)| ui.ctx().read_response(id)) {
                let transform = ui
                    .ctx()
                    .layer_transform_to_global(response.layer_id)
                    .unwrap_or_default();
                let rect = transform * response.interact_rect;
                ime =
                    ime.filter(|_| ui.ctx().layer_id_at(rect.center()) == Some(response.layer_id));
                if let Some(ime) = &mut ime {
                    ime.rect = rect;
                }
            }
            let _ = update_input(&self.input_id, ime, ui.ctx().zoom_factor());
        }
    }

    fn update_input(
        id: &str,
        ime: Option<egui::output::IMEOutput>,
        zoom: f32,
    ) -> Result<(), JsValue> {
        let window = web_sys::window().ok_or_else(|| JsValue::from_str("Missing window"))?;
        let Some(element) = window
            .document()
            .and_then(|document| document.get_element_by_id(id))
        else {
            return Ok(());
        };
        let input = element.dyn_into::<HtmlInputElement>()?;
        let coarse = window
            .match_media("(any-pointer: coarse)")?
            .is_some_and(|media| media.matches());
        let style = input.style();
        if let Some(ime) =
            ime.filter(|ime| coarse && ime.rect.is_positive() && ime.rect.is_finite())
        {
            let canvas = input
                .previous_element_sibling()
                .ok_or_else(|| JsValue::from_str("Missing canvas"))?
                .dyn_into::<HtmlCanvasElement>()?;
            let width = canvas.width() as f32 / window.device_pixel_ratio() as f32;
            let height = canvas.height() as f32 / window.device_pixel_ratio() as f32;
            let cursor = ime.cursor_rect.center() * zoom;
            let offset = ime.rect.min * zoom
                - egui::vec2(cursor.x.clamp(0., width), cursor.y.clamp(0., height));
            // eframe positions the input at the cursor after this pass.
            style.set_property(
                "transform",
                &format!("translate({}px, {}px)", offset.x, offset.y),
            )?;
            style.set_property("width", &format!("{}px", ime.rect.width() * zoom))?;
            style.set_property("height", &format!("{}px", ime.rect.height() * zoom))?;
            style.set_property("padding", "0")?;
            style.set_property("pointer-events", "auto")?;
            // WebKit excludes zero-opacity inputs from the native paste callout.
            style.set_property("opacity", "1")?;
            style.set_property("-webkit-text-fill-color", "transparent")?;
            style.set_property("appearance", "none")?;
            style.set_property("box-shadow", "none")?;
            style.set_property("z-index", "1")?;
            style.set_property("user-select", "text")?;
            style.set_property("-webkit-user-select", "text")?;
            style.set_property("-webkit-touch-callout", "default")?;
            let input_type = if ime.purpose == egui::IMEPurpose::Password {
                "password"
            } else {
                "text"
            };
            if input.type_() != input_type {
                input.set_type(input_type);
            }
            input.set_autocomplete("off");
        } else {
            style.set_property("pointer-events", "none")?;
            style.set_property("opacity", "0")?;
            style.set_property("transform", "none")?;
            style.set_property("width", "1px")?;
            style.set_property("height", "1px")?;
        }
        Ok(())
    }

    struct Paste {
        before: Zeroizing<String>,
        start: u32,
        end: u32,
        text: Option<Zeroizing<String>>,
    }

    #[derive(Clone, Copy)]
    struct TouchStart {
        id: i32,
        x: i32,
        y: i32,
        started_at: f64,
        native: bool,
    }

    #[derive(Clone, Copy)]
    struct NativePointer {
        pos: egui::Pos2,
        started_at: f64,
        modifiers: egui::Modifiers,
        dragging: bool,
    }

    impl TouchStart {
        fn contains(&self, point: web_sys::Touch) -> bool {
            point.identifier() == self.id
                && (point.client_x() - self.x).abs() <= 10
                && (point.client_y() - self.y).abs() <= 10
        }
    }

    pub fn install(
        runner: &eframe::WebRunner,
        canvas: &HtmlCanvasElement,
        input_id: &str,
    ) -> Result<(), JsValue> {
        let input = canvas
            .next_element_sibling()
            .ok_or_else(|| JsValue::from_str("Browser text input is missing"))?
            .dyn_into::<HtmlInputElement>()?;
        input.set_id(input_id);
        let document = canvas
            .owner_document()
            .ok_or_else(|| JsValue::from_str("Missing document"))?;
        let capture = web_sys::AddEventListenerOptions::new();
        capture.set_capture(true);
        runner.add_event_listener_ex(
            &input,
            "paste",
            &capture,
            |event: ClipboardEvent, runner, _| {
                // Allow the keyboard fallback when the clipboard event has no text.
                event.stop_propagation();
                if let Some(text) = event
                    .clipboard_data()
                    .and_then(|data| data.get_data("text/plain").ok())
                    .filter(|text| !text.is_empty())
                {
                    event.prevent_default();
                    runner.egui_ctx().plugin::<TextInput>().lock().paste(text);
                    runner.logic();
                    runner.egui_ctx().request_repaint();
                }
            },
        )?;
        let paste: Rc<RefCell<Option<Paste>>> = Rc::default();
        runner.add_event_listener_ex(&input, "beforeinput", &capture, {
            let paste = paste.clone();
            let input = input.clone();
            move |event: InputEvent, runner, _| {
                runner
                    .egui_ctx()
                    .plugin::<TextInput>()
                    .lock()
                    .native_gesture = false;
                *paste.borrow_mut() = if event.input_type() == "insertFromPaste" {
                    let text = event
                        .data()
                        .or_else(|| event.data_transfer()?.get_data("text/plain").ok());
                    input
                        .selection_start()
                        .ok()
                        .flatten()
                        .zip(input.selection_end().ok().flatten())
                        .map(|(start, end)| Paste {
                            before: Zeroizing::new(input.value()),
                            start,
                            end,
                            text: text.map(Zeroizing::new),
                        })
                } else {
                    None
                };
            }
        })?;
        runner.add_event_listener_ex(&input, "input", &capture, {
            let input = input.clone();
            move |event: InputEvent, runner, _| {
                if event.input_type() != "insertFromPaste" || event.is_composing() {
                    paste.borrow_mut().take();
                    return;
                }
                let previous = paste.borrow_mut().take();
                let text = event.data().or_else(|| {
                    let previous = previous?;
                    previous.text.map(|text| text.to_string()).or_else(|| {
                        pasted_fragment(
                            &previous.before,
                            previous.start,
                            previous.end,
                            &input.value(),
                        )
                    })
                });
                let Some(text) = text else { return };
                // Some mobile keyboards send input without a clipboard paste event.
                event.stop_immediate_propagation();
                runner.egui_ctx().plugin::<TextInput>().lock().paste(text);
                runner.logic();
                runner.egui_ctx().request_repaint();
            }
        })?;

        let native_pointer: Rc<RefCell<Option<NativePointer>>> = Rc::default();
        for (name, pressed) in [
            ("pointerdown", true),
            ("pointerup", false),
            ("pointercancel", false),
        ] {
            let native_pointer = native_pointer.clone();
            runner.add_event_listener(&input, name, move |event: PointerEvent, runner| {
                if event.button() > 0 {
                    return;
                }
                event.stop_propagation();
                if pressed
                    && event.pointer_type() != "touch"
                    && let Some(input) = event
                        .current_target()
                        .and_then(|target| target.dyn_into::<HtmlInputElement>().ok())
                {
                    let options = web_sys::FocusOptions::new();
                    options.set_prevent_scroll(true);
                    let _ = input.focus_with_options(&options);
                }
                let canvas = runner.canvas().get_bounding_client_rect();
                let zoom = runner.egui_ctx().zoom_factor();
                let pos = egui::pos2(
                    (event.client_x() as f32 - canvas.left() as f32) / zoom,
                    (event.client_y() as f32 - canvas.top() as f32) / zoom,
                );
                let pos = if name == "pointercancel" {
                    runner
                        .egui_ctx()
                        .input(|input| input.pointer.latest_pos())
                        .unwrap_or(pos)
                } else {
                    pos
                };
                let modifiers = runner.egui_ctx().input(|input| input.modifiers);
                if event.pointer_type() == "touch" {
                    if pressed {
                        *native_pointer.borrow_mut() = Some(NativePointer {
                            pos,
                            started_at: event.time_stamp(),
                            modifiers,
                            dragging: false,
                        });
                        // Let WebKit own the hold before changing the DOM or egui selection.
                        runner
                            .egui_ctx()
                            .plugin::<TextInput>()
                            .lock()
                            .native_gesture = true;
                        return;
                    }
                    let Some(initial) = native_pointer.borrow_mut().take() else {
                        return;
                    };
                    if !initial.dragging
                        && (name == "pointercancel"
                            || event.time_stamp() - initial.started_at >= 500.)
                    {
                        return;
                    }
                    let plugin = runner.egui_ctx().plugin::<TextInput>();
                    let mut plugin = plugin.lock();
                    plugin.native_gesture = false;
                    if !initial.dragging {
                        plugin.pending.push(egui::Event::PointerMoved(initial.pos));
                        plugin.pending.push(egui::Event::PointerButton {
                            pos: initial.pos,
                            button: egui::PointerButton::Primary,
                            pressed: true,
                            modifiers: initial.modifiers,
                        });
                    }
                }
                {
                    let plugin = runner.egui_ctx().plugin::<TextInput>();
                    let mut plugin = plugin.lock();
                    plugin.pending.push(egui::Event::PointerMoved(pos));
                    plugin.pending.push(egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers,
                    });
                    if !pressed {
                        plugin.pending.push(egui::Event::PointerGone);
                    }
                }
                // Keep the native input as the touch target for the iOS paste menu.
                runner.logic();
                runner.egui_ctx().request_repaint();
            })?;
        }
        runner.add_event_listener(&input, "pointermove", move |event: PointerEvent, runner| {
            if event.buttons() == 0 {
                return;
            }
            event.stop_propagation();
            let canvas = runner.canvas().get_bounding_client_rect();
            let zoom = runner.egui_ctx().zoom_factor();
            let pos = egui::pos2(
                (event.client_x() as f32 - canvas.left() as f32) / zoom,
                (event.client_y() as f32 - canvas.top() as f32) / zoom,
            );
            if event.pointer_type() == "touch" {
                let mut state = native_pointer.borrow_mut();
                let Some(initial) = state.as_mut() else {
                    return;
                };
                if !initial.dragging {
                    if event.time_stamp() - initial.started_at >= 500.
                        || initial.pos.distance(pos) * zoom <= 10.
                    {
                        return;
                    }
                    initial.dragging = true;
                    let plugin = runner.egui_ctx().plugin::<TextInput>();
                    let mut plugin = plugin.lock();
                    plugin.native_gesture = false;
                    plugin.pending.push(egui::Event::PointerMoved(initial.pos));
                    plugin.pending.push(egui::Event::PointerButton {
                        pos: initial.pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: initial.modifiers,
                    });
                }
            }
            runner
                .egui_ctx()
                .plugin::<TextInput>()
                .lock()
                .pending
                .push(egui::Event::PointerMoved(pos));
            runner.egui_ctx().request_repaint();
        })?;

        runner.add_event_listener(&input, "touchmove", |event: TouchEvent, _| {
            event.stop_propagation();
        })?;
        let touch: Rc<RefCell<Option<TouchStart>>> = Rc::default();
        runner.add_event_listener_ex(&document, "touchstart", &capture, {
            let touch = touch.clone();
            let ids = [canvas.id(), input.id()];
            move |event: TouchEvent, _, _| {
                let target_id = event
                    .target()
                    .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
                    .map(|target| target.id());
                let own_target = target_id.as_ref().is_some_and(|id| ids.contains(id));
                let native = target_id.as_ref() == Some(&ids[1]);
                *touch.borrow_mut() = (own_target && event.touches().length() == 1)
                    .then(|| event.touches().get(0))
                    .flatten()
                    .map(|point| TouchStart {
                        id: point.identifier(),
                        x: point.client_x(),
                        y: point.client_y(),
                        started_at: event.time_stamp(),
                        native,
                    });
            }
        })?;
        runner.add_event_listener_ex(&document, "touchmove", &capture, {
            let touch = touch.clone();
            move |event: TouchEvent, _, _| {
                let mut start = touch.borrow_mut();
                if let Some(initial) = *start {
                    let point = event.touches().get(0);
                    if event.touches().length() != 1
                        || !point.is_some_and(|point| initial.contains(point))
                    {
                        *start = None;
                    }
                }
            }
        })?;
        runner.add_event_listener(&document, "touchcancel", {
            let touch = touch.clone();
            move |_: TouchEvent, _| {
                touch.borrow_mut().take();
            }
        })?;
        runner.add_event_listener(&document, "touchend", {
            let input = input.clone();
            move |event: TouchEvent, runner| {
                let Some(initial) = touch.borrow_mut().take() else {
                    return;
                };
                if event.touches().length() != 0
                    || !event
                        .changed_touches()
                        .get(0)
                        .is_some_and(|point| initial.contains(point))
                {
                    return;
                }
                runner.logic();
                let editing = runner
                    .egui_ctx()
                    .plugin::<TextInput>()
                    .lock()
                    .focus
                    .is_some();
                if editing && !initial.native && event.time_stamp() - initial.started_at < 500. {
                    // Focus the editable element in this gesture even if the canvas cannot take focus.
                    let options = web_sys::FocusOptions::new();
                    options.set_prevent_scroll(true);
                    let _ = input.blur();
                    let _ = input.focus_with_options(&options);
                    runner.logic();
                }
                runner.egui_ctx().request_repaint();
            }
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::pasted_fragment;

    #[test]
    fn paste_uses_utf16_selection_and_preserves_the_surrounding_text() {
        assert_eq!(pasted_fragment("ab", 2, 2, "ab🌴"), Some("🌴".into()));
        assert_eq!(
            pasted_fragment("a🌴b", 1, 3, "aПриветb"),
            Some("Привет".into())
        );
        assert_eq!(
            pasted_fragment("🌴x", 0, 3, "replacement"),
            Some("replacement".into())
        );
        assert_eq!(pasted_fragment("abc", 2, 1, "ac"), None);
        assert_eq!(pasted_fragment("abc", 0, 4, "value"), None);
        assert_eq!(pasted_fragment("🌴x", 1, 2, "value"), None);
        assert_eq!(pasted_fragment("prefix", 6, 6, "changed"), None);
    }
}
